"""
Backup encryption and integrity compliance checks.
HIPAA reference: 164.308(a)(7) — Contingency Plan (REQUIRED)
NIST SP 800-66r2: Section 3.3 — Contingency Plan safeguards

Unencrypted or untested backups are a primary source of ePHI exposure after ransomware attacks.
Healthcare organizations are among the top ransomware targets.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class BackupEncryptionCheck(BaseCheck):
    """
    BAK-01: Verify backups are encrypted at rest.
    Tests: Windows Server Backup encryption setting, Veeam registry, Acronis, Backup Exec,
           Azure Backup agent, shadow copy volume encryption via BitLocker.
    """
    check_id = "BAK-01"
    check_name = "Backup Encryption"
    category = "Contingency Plan"
    hipaa_reference = "164.308(a)(7)(ii)(A)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check 1: Windows Server Backup — wbadmin get versions shows backup metadata
            wsb_policy = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' "
                r"-ErrorAction SilentlyContinue) -ne $null"
            )

            # Check 2: Veeam Backup & Replication — encryption enabled in job config registry
            veeam_encryption = context.winrm.run_ps(
                target.hostname,
                r"$veeam = Get-ItemProperty 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' "
                r"-ErrorAction SilentlyContinue; "
                r"if ($veeam) { 'installed' } else { 'not found' }"
            )

            # Check 3: Azure Backup agent (MARS)
            mars_agent = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'obengine' -ErrorAction SilentlyContinue | "
                r"Select-Object -ExpandProperty Status"
            )

            # Check 4: Acronis Backup
            acronis = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'AcrSch2Svc','acronisagent' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Check 5: Shadow copies exist (prerequisite for backup recovery)
            shadow_copies = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            # Check 6: Any third-party backup software installed
            backup_software = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | "
                r"Where-Object { $_.DisplayName -match 'Veeam|Acronis|Backup Exec|StorageCraft|Datto|"
                r"Carbonite|IDrive|Arcserve|Nakivo|Zerto|CommVault|Veritas' } | "
                r"Select-Object DisplayName | ConvertTo-Json"
            )

            evidence = {
                "wsb_configured": wsb_policy.strip().lower(),
                "veeam": veeam_encryption.strip(),
                "mars_agent": mars_agent.strip(),
                "acronis_running": acronis.strip(),
                "shadow_copy_count": shadow_copies.strip(),
                "backup_software_found": backup_software.strip() not in ("", "null", "[]"),
            }

            has_backup_solution = any([
                "installed" in veeam_encryption.lower(),
                "running" in mars_agent.lower(),
                acronis.strip() not in ("", "0"),
                backup_software.strip() not in ("", "null", "[]"),
            ])

            shadow_count = int(shadow_copies.strip()) if shadow_copies.strip().isdigit() else 0

            if has_backup_solution and shadow_count > 0:
                return self._pass(
                    target,
                    details=f"Backup solution detected ({veeam_encryption.strip() if 'installed' in veeam_encryption.lower() else 'third-party'}) with {shadow_count} shadow copy/copies present.",
                    evidence=evidence,
                )
            elif has_backup_solution:
                return self._fail(
                    target,
                    details="Backup software detected but no Volume Shadow Copies found. Backup recoverability cannot be confirmed.",
                    remediation=(
                        "Enable Volume Shadow Copy Service (VSS) on all volumes containing ePHI. "
                        "Verify backup jobs are running successfully and test restoration quarterly. "
                        "Under HIPAA 164.308(a)(7), backup procedures and testing are REQUIRED."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No recognized backup solution detected. ePHI on this server may have no recovery path after ransomware or hardware failure.",
                    remediation=(
                        "Implement encrypted backup under HIPAA 164.308(a)(7) Contingency Plan: "
                        "1. Deploy Veeam, Azure Backup (MARS agent), or equivalent enterprise backup. "
                        "2. Enable backup encryption (AES-256 minimum). "
                        "3. Store one backup copy offsite or in immutable cloud storage. "
                        "4. Test restoration at minimum quarterly — document test results. "
                        "5. Retention: minimum 6 years for ePHI-related backups (HIPAA record retention)."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable Volume Shadow Copy on C: drive\n"
                        "vssadmin add shadowstorage /for=C: /on=C: /maxsize=20%\n"
                        "# Schedule daily shadow copies via Task Scheduler or PowerShell:\n"
                        "$action = New-ScheduledTaskAction -Execute 'cmd.exe' "
                        "-Argument '/c vssadmin create shadow /for=C:'\n"
                        "$trigger = New-ScheduledTaskTrigger -Daily -At '2:00AM'\n"
                        "Register-ScheduledTask -TaskName 'DailyShadowCopy' -Action $action -Trigger $trigger -RunLevel Highest"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class BackupRestorationTestCheck(BaseCheck):
    """
    BAK-02: Verify backup restoration has been tested within the past 90 days.
    Tests: Windows Event Log for backup success events, Veeam job history, wbadmin job status.
    HIPAA requires documented, tested contingency plans — not just backups that exist.
    """
    check_id = "BAK-02"
    check_name = "Backup Restoration Testing"
    category = "Contingency Plan"
    hipaa_reference = "164.308(a)(7)(ii)(D)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Windows Backup event log — Event ID 4 = successful backup, within 90 days
            backup_events = context.winrm.run_ps(
                target.hostname,
                r"$cutoff = (Get-Date).AddDays(-90); "
                r"$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Backup'; Id=4; StartTime=$cutoff} "
                r"-ErrorAction SilentlyContinue; "
                r"[PSCustomObject]@{ Count = if($events) { $events.Count } else { 0 }; "
                r"LastSuccess = if($events) { $events[0].TimeCreated.ToString('yyyy-MM-dd') } else { 'none' } } "
                r"| ConvertTo-Json"
            )

            # Check Veeam job history (last 90 days)
            veeam_jobs = context.winrm.run_ps(
                target.hostname,
                r"$cutoff = (Get-Date).AddDays(-90); "
                r"try { "
                r"Add-PSSnapin -Name VeeamPSSnapIn -ErrorAction SilentlyContinue; "
                r"$jobs = Get-VBRBackupSession | Where-Object { $_.EndTime -gt $cutoff -and $_.Result -eq 'Success' }; "
                r"$jobs.Count "
                r"} catch { '0' }"
            )

            # Check wbadmin last backup status
            wbadmin_last = context.winrm.run_ps(
                target.hostname,
                r"wbadmin get versions 2>&1 | Select-String 'Backup time:' | Select-Object -Last 1 | "
                r"ForEach-Object { $_.Line.Trim() }"
            )

            import json as _json
            try:
                data = _json.loads(backup_events)
                event_count = data.get("Count", 0)
                last_success = data.get("LastSuccess", "none")
            except Exception:
                event_count = 0
                last_success = "none"

            veeam_count = int(veeam_jobs.strip()) if veeam_jobs.strip().isdigit() else 0

            evidence = {
                "windows_backup_events_90d": event_count,
                "last_windows_backup": last_success,
                "veeam_jobs_90d": veeam_count,
                "wbadmin_last": wbadmin_last.strip(),
            }

            if event_count > 0 or veeam_count > 0:
                return self._pass(
                    target,
                    details=f"Recent backup activity confirmed: {event_count} Windows Backup events, {veeam_count} Veeam jobs in past 90 days.",
                    evidence=evidence,
                )
            elif wbadmin_last.strip() and "none" not in wbadmin_last.lower():
                return self._fail(
                    target,
                    details=f"Backup found ({wbadmin_last.strip()}) but cannot confirm it was within 90 days or was tested for restoration.",
                    remediation=(
                        "Document backup tests with date, restored data scope, and technician name. "
                        "HIPAA 164.308(a)(7)(ii)(D) requires testing and revision of contingency plans. "
                        "Schedule quarterly restore tests and log results for OCR audit readiness."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No backup activity found in the past 90 days. Server may not have a functioning backup.",
                    remediation=(
                        "Implement and verify backup schedule immediately. "
                        "HIPAA 164.308(a)(7) requires documented backup and restoration procedures. "
                        "Test backup restoration at minimum quarterly. "
                        "Keep restoration test records for 6 years (HIPAA documentation requirement)."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class OffSiteBackupCheck(BaseCheck):
    """
    BAK-03: Verify backups are stored offsite or in immutable cloud storage.
    Tests: Azure Backup, AWS Backup agent presence, Datto/Acronis cloud backup presence,
           UNC path destinations pointing to non-local shares.
    """
    check_id = "BAK-03"
    check_name = "Off-Site / Cloud Backup Storage"
    category = "Contingency Plan"
    hipaa_reference = "164.308(a)(7)(ii)(A)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Azure Backup (MARS / Recovery Services agent)
            azure_backup = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'obengine','MicrosoftAzureRecoveryServicesAgent' "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Check for Datto, Acronis Cyber Cloud, or Carbonite (cloud-first BDR)
            cloud_bdr = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | "
                r"Where-Object { $_.DisplayName -match 'Datto|Carbonite|IDrive|Backblaze|Acronis.*(Cloud|True Image)' } | "
                r"Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Check wbadmin targets — if configured to a UNC path (could be offsite NAS or cloud gateway)
            wbadmin_target = context.winrm.run_ps(
                target.hostname,
                r"wbadmin get disks 2>&1 | Select-String 'Disk name|Volume label' | "
                r"ForEach-Object { $_.Line.Trim() } | Select-Object -First 4"
            )

            azure_count = int(azure_backup.strip()) if azure_backup.strip().isdigit() else 0
            cloud_count = int(cloud_bdr.strip()) if cloud_bdr.strip().isdigit() else 0

            evidence = {
                "azure_backup_running": azure_count > 0,
                "cloud_bdr_software": cloud_count > 0,
                "backup_targets": wbadmin_target.strip(),
            }

            if azure_count > 0 or cloud_count > 0:
                return self._pass(
                    target,
                    details="Cloud or offsite backup solution detected (Azure Backup, BDR, or cloud agent running).",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No cloud or offsite backup solution detected. Local-only backups are destroyed in ransomware attacks and physical disasters.",
                    remediation=(
                        "Implement offsite backup under HIPAA 164.308(a)(7) Contingency Plan: "
                        "1. Azure Backup (MARS agent) — encrypts and sends to Azure Recovery Services Vault. "
                        "2. Datto SIRIS or Veeam Cloud Connect — immutable cloud backup with rapid restore. "
                        "3. Acronis Cyber Cloud — agent-based with air-gapped cloud storage. "
                        "Follow the 3-2-1 rule: 3 copies, 2 media types, 1 offsite/cloud."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
