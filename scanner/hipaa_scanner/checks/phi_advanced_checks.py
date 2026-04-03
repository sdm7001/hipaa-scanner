"""
Advanced PHI protection and healthcare-specific compliance checks.
HIPAA reference: 164.312(a)(1), 164.308(a)(1) — Access Control, Risk Analysis

These checks go beyond basic PHI detection to verify controls that specifically
protect electronic Protected Health Information (ePHI) in clinical environments.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class EhrApplicationSecurityCheck(BaseCheck):
    """
    PHI-03: Detect common EHR/EMR applications and verify they are running
    on supported, patched versions. Outdated EHR software is a top HIPAA
    violation source — vendors stop patching legacy versions.
    """
    check_id = "PHI-03"
    check_name = "EHR/EMR Application Inventory and Version Check"
    category = "PHI Discovery"
    hipaa_reference = "164.308(a)(1)(ii)(A)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    # Known EHR/EMR/practice management software
    EHR_SIGNATURES = [
        "Epic", "Cerner", "Meditech", "Allscripts", "eClinicalWorks",
        "athenahealth", "NextGen", "Greenway", "Practice Fusion", "Kareo",
        "DrChrono", "AdvancedMD", "Netsmart", "Veradigm", "Amazing Charts",
        "ChartLogic", "Modernizing Medicine", "WebPT", "Centricity", "McKesson",
    ]

    def run(self, target: Target, context) -> Finding:
        try:
            # Search installed software for EHR applications
            installed_ehr = context.winrm.run_ps(
                target.hostname,
                r"$ehr = @(" + ",".join(f"'{s}'" for s in self.EHR_SIGNATURES) + r"); "
                r"Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.DisplayName; $ehr | Where-Object { $n -like \"*$_*\" } } | "
                r"Select-Object DisplayName, DisplayVersion, InstallDate | ConvertTo-Json"
            )

            # Check for EHR-related processes running
            ehr_processes = context.winrm.run_ps(
                target.hostname,
                r"$ehr = @(" + ",".join(f"'{s.lower()}'" for s in self.EHR_SIGNATURES) + r"); "
                r"Get-Process -ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.Name.ToLower(); $ehr | Where-Object { $n -like \"*$_*\" } } | "
                r"Select-Object -Unique Name | ConvertTo-Json"
            )

            # Check for EHR data directories
            ehr_dirs = context.winrm.run_ps(
                target.hostname,
                r"$paths = @('C:\Epic', 'C:\Cerner', 'C:\eCW', 'C:\AdvPM', "
                r"  'C:\Meditech', 'C:\NextGen', 'C:\Allscripts'); "
                r"$found = $paths | Where-Object { Test-Path $_ }; "
                r"if ($found) { $found -join ',' } else { '' }"
            )

            import json as _json
            ehr_software = []
            if installed_ehr.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(installed_ehr)
                    ehr_software = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            ehr_proc_list = []
            if ehr_processes.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(ehr_processes)
                    ehr_proc_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            ehr_dir_list = [d.strip() for d in ehr_dirs.strip().split(",") if d.strip()]

            evidence = {
                "ehr_software_installed": [f"{s.get('DisplayName')} v{s.get('DisplayVersion','?')}" for s in ehr_software[:5]],
                "ehr_processes_running": [p.get("Name") for p in ehr_proc_list[:5]],
                "ehr_data_directories": ehr_dir_list,
                "ehr_applications_count": len(ehr_software),
            }

            if not ehr_software and not ehr_proc_list and not ehr_dir_list:
                return self._na(target, "No EHR/EMR applications detected on this system.")

            if ehr_software:
                return self._pass(
                    target,
                    details=f"EHR/EMR applications inventoried: {', '.join([s.get('DisplayName','?') for s in ehr_software[:3]])}. Verify these applications are on vendor-supported versions.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"EHR processes/directories detected but not in software inventory: {', '.join([p.get('Name','?') for p in ehr_proc_list[:3]])}. EHR software may be unregistered or portable.",
                    remediation=(
                        "Ensure all EHR/EMR software is: "
                        "1. Properly installed (registered in Add/Remove Programs). "
                        "2. On a vendor-supported version — check vendor EOL calendar. "
                        "3. Included in your asset inventory and patch management process. "
                        "4. Covered by a Business Associate Agreement with the vendor. "
                        "Log EHR software versions in asset inventory for annual HIPAA risk assessment."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class EncryptedEmailCheck(BaseCheck):
    """
    PHI-04: Verify email client is configured to use S/MIME or equivalent
    encrypted email when sending PHI. Unencrypted email transmission of PHI
    is a top HIPAA violation — fines routinely exceed $100K per incident.
    """
    check_id = "PHI-04"
    check_name = "Encrypted Email (S/MIME) Configuration"
    category = "Transmission Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check for S/MIME certificates in user certificate store
            smime_certs = context.winrm.run_ps(
                target.hostname,
                r"$certs = Get-ChildItem Cert:\CurrentUser\My "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.EnhancedKeyUsageList -match 'Secure Email' }; "
                r"if ($certs) { $certs.Count } else { 0 }"
            )

            # Check Outlook S/MIME settings
            outlook_smime = context.winrm.run_ps(
                target.hostname,
                r"$path = 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Security'; "
                r"@{ "
                r"  DefaultEncryption = (Get-ItemProperty $path -ErrorAction SilentlyContinue).DefaultEncryption; "
                r"  DefaultSigning = (Get-ItemProperty $path -ErrorAction SilentlyContinue).DefaultSigning "
                r"} | ConvertTo-Json"
            )

            # Check for secure messaging apps used for PHI (alternative to S/MIME)
            secure_msg_apps = context.winrm.run_ps(
                target.hostname,
                r"$apps = @('TigerConnect', 'Imprivata', 'Klara', 'Spruce', "
                r"  'OhMD', 'Spok', 'PerfectServe', 'Vocera', 'Microsoft Teams Health'); "
                r"$installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.DisplayName; $apps | Where-Object { $n -like \"*$_*\" } }; "
                r"if ($installed) { ($installed.DisplayName) -join ',' } else { '' }"
            )

            import json as _json
            try:
                smime_count = int(smime_certs.strip())
            except (ValueError, AttributeError):
                smime_count = 0

            outlook_cfg = {}
            if outlook_smime.strip() not in ("", "null"):
                try:
                    outlook_cfg = _json.loads(outlook_smime)
                except Exception:
                    pass

            secure_apps = [a.strip() for a in secure_msg_apps.strip().split(",") if a.strip()]

            default_encrypt = outlook_cfg.get("DefaultEncryption", 0)
            default_sign = outlook_cfg.get("DefaultSigning", 0)

            evidence = {
                "smime_certificates": smime_count,
                "outlook_default_encryption": default_encrypt,
                "outlook_default_signing": default_sign,
                "secure_messaging_apps": secure_apps,
            }

            if smime_count > 0 or secure_apps:
                return self._pass(
                    target,
                    details=(
                        f"Encrypted communication available: "
                        f"{smime_count} S/MIME certificate(s)" +
                        (f", secure messaging: {', '.join(secure_apps)}" if secure_apps else "") + "."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No S/MIME certificates or HIPAA-compliant secure messaging apps detected. PHI may be transmitted via unencrypted email.",
                    remediation=(
                        "Implement encrypted email for PHI: "
                        "Option 1 - S/MIME: "
                        "  1. Obtain S/MIME certificates from a CA (DigiCert, Comodo, GlobalSign). "
                        "  2. Install in Outlook: File → Options → Trust Center → Email Security → Import. "
                        "  3. Enable default encryption: Trust Center → Email Security → check 'Encrypt contents and attachments'. "
                        "Option 2 - Secure messaging platform (preferred for clinical use): "
                        "  TigerConnect, Imprivata Cortext, Klara, or Microsoft Teams (HIPAA BAA available). "
                        "Option 3 - Microsoft 365 Message Encryption: "
                        "  Purview Information Protection — encrypt automatically based on sensitive content rules. "
                        "Unencrypted email with PHI = HIPAA violation. Average fine: $100K-$1.9M."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class PrinterSecurityCheck(BaseCheck):
    """
    PHI-05: Verify network printers are secured and print jobs containing
    PHI are not left in accessible print queues or stored on printer HDDs.
    Physical PHI left on printers is a common HIPAA violation source.
    """
    check_id = "PHI-05"
    check_name = "Network Printer Security"
    category = "Physical Safeguards"
    hipaa_reference = "164.310(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 4.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Get network printers
            printers = context.winrm.run_ps(
                target.hostname,
                r"Get-Printer -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Type -eq 'Connection' -or $_.PortName -like '*.*.*.*' } | "
                r"Select-Object Name, PortName, PrinterStatus | ConvertTo-Json"
            )

            # Check if print spooler is running (needed for print jobs)
            spooler = context.winrm.run_ps(
                target.hostname,
                r"(Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status"
            )

            # Check for print jobs stuck in queue
            pending_jobs = context.winrm.run_ps(
                target.hostname,
                r"(Get-PrintJob -ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            # Check if print spooler spool directory has retained files
            spool_files = context.winrm.run_ps(
                target.hostname,
                r"(Get-ChildItem 'C:\Windows\System32\spool\PRINTERS' "
                r"-ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            import json as _json
            printer_list = []
            if printers.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(printers)
                    printer_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            if not printer_list:
                return self._na(target, "No network printers detected on this system.")

            try:
                pending = int(pending_jobs.strip())
            except (ValueError, AttributeError):
                pending = 0

            try:
                spool_count = int(spool_files.strip())
            except (ValueError, AttributeError):
                spool_count = 0

            evidence = {
                "network_printers": [p.get("Name", "?") for p in printer_list[:5]],
                "printer_count": len(printer_list),
                "pending_print_jobs": pending,
                "spool_directory_files": spool_count,
                "spooler_running": spooler.strip().lower() == "running",
            }

            issues = []
            if pending > 0:
                issues.append(f"{pending} print job(s) stuck in queue — may contain PHI")
            if spool_count > 0:
                issues.append(f"{spool_count} file(s) in print spool directory — retained print data")

            if not issues:
                return self._pass(
                    target,
                    details=f"{len(printer_list)} network printer(s) detected. Print queue is clear, no retained spool files.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Printer security concerns: {'; '.join(issues)}",
                    remediation=(
                        "Address printer PHI risks: "
                        "1. Clear print queue: Get-PrintJob | Remove-PrintJob. "
                        "2. Clear spool: Stop-Service Spooler; Remove-Item C:\\Windows\\System32\\spool\\PRINTERS\\* -Force; Start-Service Spooler. "
                        "3. Configure printers to not store print data on device HDD (check printer admin console). "
                        "4. Enable print auditing: auditpol /set /subcategory:'Other Object Access Events' /success:enable. "
                        "5. For high-sensitivity areas: implement secure pull printing (PIN at printer). "
                        "Physical PHI left on printers or in queues is a reportable HIPAA breach."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class CloudStorageControlCheck(BaseCheck):
    """
    PHI-06: Verify cloud storage sync clients (OneDrive, Dropbox, Google Drive)
    are either blocked or configured with appropriate BAA/HIPAA compliance controls.
    Unauthorized cloud sync of PHI is a major breach vector.
    """
    check_id = "PHI-06"
    check_name = "Cloud Storage PHI Control"
    category = "Device and Media Controls"
    hipaa_reference = "164.310(d)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check for cloud storage clients installed
            cloud_clients = context.winrm.run_ps(
                target.hostname,
                r"$apps = @('Dropbox', 'Box', 'Google Drive', 'Google Backup', "
                r"  'pCloud', 'Mega', 'SugarSync', 'SpiderOak'); "
                r"$found = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.DisplayName; $apps | Where-Object { $n -like \"*$_*\" } }; "
                r"if ($found) { ($found | Select-Object DisplayName | ConvertTo-Json) } else { '[]' }"
            )

            # Check OneDrive status and configuration (comes with Windows)
            onedrive_status = context.winrm.run_ps(
                target.hostname,
                r"$od = Get-Process -Name OneDrive -ErrorAction SilentlyContinue; "
                r"if ($od) { 'Running' } else { 'Not running' }"
            )

            # Check OneDrive Known Folder Move (KFM) - syncs Desktop/Documents
            onedrive_kfm = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' "
                r"-Name KFMSilentOptIn -ErrorAction SilentlyContinue).KFMSilentOptIn"
            )

            # Check if OneDrive is blocked by policy
            onedrive_blocked = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' "
                r"-Name DisableFileSyncNGSC -ErrorAction SilentlyContinue).DisableFileSyncNGSC"
            )

            # Check SharePoint sync (OneDrive for Business - potentially compliant)
            sharepoint_tenant = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' "
                r"-Name AllowTenantList -ErrorAction SilentlyContinue).AllowTenantList"
            )

            import json as _json
            cloud_list = []
            if cloud_clients.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(cloud_clients)
                    cloud_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            onedrive_running = "running" in onedrive_status.strip().lower()
            onedrive_policy_blocked = onedrive_blocked.strip() == "1"
            kfm_active = bool(onedrive_kfm.strip())
            tenant_restricted = bool(sharepoint_tenant.strip())

            evidence = {
                "unauthorized_cloud_clients": [c.get("DisplayName", "?") for c in cloud_list[:5]],
                "onedrive_running": onedrive_running,
                "onedrive_blocked_by_policy": onedrive_policy_blocked,
                "onedrive_kfm_configured": kfm_active,
                "onedrive_tenant_restricted": tenant_restricted,
            }

            issues = []
            if cloud_list:
                issues.append(f"Non-Microsoft cloud storage clients installed: {', '.join([c.get('DisplayName','?') for c in cloud_list[:3]])}")
            if onedrive_running and not (tenant_restricted or onedrive_policy_blocked):
                issues.append("OneDrive running without tenant restriction — personal OneDrive accounts may sync PHI to non-HIPAA cloud")

            if not issues:
                return self._pass(
                    target,
                    details=f"Cloud storage controlled: no unauthorized clients, OneDrive policy configured. " +
                            ("OneDrive blocked by policy." if onedrive_policy_blocked else "OneDrive tenant-restricted."),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Cloud storage PHI risk: {'; '.join(issues)}",
                    remediation=(
                        "Control cloud storage access: "
                        "1. Block unauthorized cloud clients via AppLocker or GPO software restriction. "
                        "2. If using OneDrive for Business (M365): "
                        "   Restrict to company tenant: HKLM\\SOFTWARE\\Policies\\Microsoft\\OneDrive\\AllowTenantList → your tenant ID. "
                        "   Block personal OneDrive: HKLM\\SOFTWARE\\Policies\\Microsoft\\OneDrive\\DisablePersonalSync = 1. "
                        "3. Block OneDrive entirely if not needed: "
                        "   HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive\\DisableFileSyncNGSC = 1. "
                        "4. Ensure M365 subscription includes HIPAA BAA coverage (Business/Enterprise plans). "
                        "Dropbox, Google Drive personal, and pCloud do NOT have HIPAA BAAs by default."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class RansomwareProtectionCheck(BaseCheck):
    """
    PHI-07: Verify Controlled Folder Access (ransomware protection) and
    backup integrity controls are active. Healthcare is the #1 ransomware
    target — average ransom demand in healthcare is $1.3M.
    """
    check_id = "PHI-07"
    check_name = "Ransomware Protection Controls"
    category = "Antivirus/EDR"
    hipaa_reference = "164.308(a)(7)(i)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Windows Defender Controlled Folder Access
            cfa_enabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).EnableControlledFolderAccess"
            )

            # Check protected folders
            cfa_folders = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).ControlledFolderAccessProtectedFolders"
            )

            # Check Volume Shadow Copy service (critical for ransomware recovery)
            vss_service = context.winrm.run_ps(
                target.hostname,
                r"(Get-Service -Name VSS -ErrorAction SilentlyContinue).Status"
            )

            # Check if any VSS snapshots exist
            vss_snapshots = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            # Check Windows Backup (wbadmin) recent backup
            wbadmin_backup = context.winrm.run_ps(
                target.hostname,
                r"wbadmin get versions 2>$null | Select-String 'Backup time' | Select-Object -Last 1"
            )

            # Check for file recovery configuration
            recuva_or_similar = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\VSS' "
                r"-Name Start -ErrorAction SilentlyContinue).Start"
            )

            try:
                cfa_val = int(cfa_enabled.strip())
            except (ValueError, AttributeError):
                cfa_val = 0
            # 1=Enabled, 2=Audit, 3=BlockDiskModification, 4=AuditDiskModification
            cfa_active = cfa_val >= 1

            vss_running = vss_service.strip().lower() == "running"

            try:
                snapshot_count = int(vss_snapshots.strip())
            except (ValueError, AttributeError):
                snapshot_count = 0

            has_snapshots = snapshot_count > 0
            recent_backup = bool(wbadmin_backup.strip())

            evidence = {
                "controlled_folder_access": cfa_val,
                "cfa_active": cfa_active,
                "vss_service_running": vss_running,
                "vss_snapshot_count": snapshot_count,
                "recent_backup_exists": recent_backup,
                "last_backup": wbadmin_backup.strip()[:100] if wbadmin_backup.strip() else "none found",
            }

            score = sum([cfa_active, vss_running, has_snapshots, recent_backup])

            if score >= 3:
                return self._pass(
                    target,
                    details=f"Ransomware protections in place ({score}/4 controls): CFA={cfa_active}, VSS={vss_running}, {snapshot_count} snapshot(s), recent backup={recent_backup}.",
                    evidence=evidence,
                )
            else:
                issues = []
                if not cfa_active:
                    issues.append("Controlled Folder Access disabled (allows ransomware to encrypt files freely)")
                if not vss_running:
                    issues.append("Volume Shadow Copy service not running (no shadow copy recovery)")
                if not has_snapshots:
                    issues.append("No VSS snapshots exist (cannot recover to previous version)")
                if not recent_backup:
                    issues.append("No recent Windows Backup detected")

                return self._fail(
                    target,
                    details=f"Ransomware protection gaps ({score}/4 controls active): {'; '.join(issues)}. Healthcare is #1 ransomware target — average demand $1.3M.",
                    remediation=(
                        "Enable ransomware protections: "
                        "1. Controlled Folder Access: Set-MpPreference -EnableControlledFolderAccess 1. "
                        "   Add PHI directories: Add-MpPreference -ControlledFolderAccessProtectedFolders 'C:\\PHI'. "
                        "2. Enable VSS: Start-Service VSS; Set-Service VSS -StartupType Automatic. "
                        "3. Enable shadow copies: "
                        "   vssadmin create shadow /for=C: "
                        "   Schedule: schtasks /create /tn 'ShadowCopy' /sc daily /st 23:00 /tr 'vssadmin create shadow /for=C:'. "
                        "4. Offline backup: ensure backups are disconnected from network (3-2-1 rule). "
                        "CRITICAL: Ransomware routinely deletes shadow copies — air-gapped backup is essential."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable Controlled Folder Access:\\n"
                        "Set-MpPreference -EnableControlledFolderAccess 1\\n"
                        "# Ensure VSS is running:\\n"
                        "Set-Service VSS -StartupType Automatic\\n"
                        "Start-Service VSS\\n"
                        "# Create shadow copy now:\\n"
                        "vssadmin create shadow /for=C:\\n"
                        "# Schedule daily shadow copies (PowerShell as Admin):\\n"
                        "$action = New-ScheduledTaskAction -Execute 'vssadmin' -Argument 'create shadow /for=C:'\\n"
                        "$trigger = New-ScheduledTaskTrigger -Daily -At '11:00PM'\\n"
                        "Register-ScheduledTask -TaskName 'DailyShadowCopy' -Action $action -Trigger $trigger -RunLevel Highest"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class PasswordManagerCheck(BaseCheck):
    """
    PHI-08: Verify an enterprise password manager is deployed.
    Password reuse and weak passwords are the #1 credential compromise vector.
    Enterprise password managers with breach monitoring address this root cause.
    """
    check_id = "PHI-08"
    check_name = "Enterprise Password Manager"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 5.0

    PM_SIGNATURES = [
        "1Password", "LastPass", "Bitwarden", "Dashlane", "Keeper",
        "CyberArk", "Delinea", "BeyondTrust", "ManageEngine PAM",
        "KeePass", "NordPass", "Passbolt",
    ]

    def run(self, target: Target, context) -> Finding:
        try:
            pm_check = context.winrm.run_ps(
                target.hostname,
                r"$pms = @(" + ",".join(f"'{p}'" for p in self.PM_SIGNATURES) + r"); "
                r"$found = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.DisplayName; $pms | Where-Object { $n -like \"*$_*\" } }; "
                r"if ($found) { ($found.DisplayName | Select-Object -Unique) -join ',' } else { '' }"
            )

            # Also check browser extensions via registry (rough indicator)
            pm_processes = context.winrm.run_ps(
                target.hostname,
                r"$names = @('1password', 'lastpass', 'bitwarden', 'dashlane', 'keeper'); "
                r"$found = Get-Process -ErrorAction SilentlyContinue | "
                r"Where-Object { $n = $_.Name.ToLower(); $names | Where-Object { $n -like \"*$_*\" } }; "
                r"if ($found) { ($found.Name | Select-Object -Unique) -join ',' } else { '' }"
            )

            found_apps = [a.strip() for a in pm_check.strip().split(",") if a.strip()]
            found_procs = [a.strip() for a in pm_processes.strip().split(",") if a.strip()]
            all_found = list(set(found_apps + found_procs))

            evidence = {
                "password_managers_found": all_found,
                "installed_apps": found_apps,
                "running_processes": found_procs,
            }

            if all_found:
                return self._pass(
                    target,
                    details=f"Enterprise password manager detected: {', '.join(all_found[:3])}. Credential management in place.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No enterprise password manager detected. Staff likely reusing passwords or using insecure storage (sticky notes, browsers).",
                    remediation=(
                        "Deploy an enterprise password manager: "
                        "Healthcare-recommended options: "
                        "1. 1Password Teams/Business — HIPAA-ready, BAA available, browser extensions + desktop app. "
                        "2. Keeper Business — healthcare focus, HIPAA BAA, dark web monitoring. "
                        "3. Bitwarden Business — open source, self-hostable, HIPAA compliant. "
                        "4. CyberArk/Delinea — PAM platforms for privileged accounts. "
                        "Deployment: purchase org license, install client via GPO/Intune, "
                        "train staff on vault usage, enable breach monitoring alerts."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class ScreenPrivacyFilterCheck(BaseCheck):
    """
    PHI-09: Check for visual privacy controls — screen privacy filters and
    clean desk policy compliance indicators. Visual hacking (shoulder surfing)
    accounts for significant PHI exposure at workstations facing waiting rooms.
    HIPAA 164.310(b) — Workstation Use physical safeguard.
    """
    check_id = "PHI-09"
    check_name = "Screen Privacy and Visual Security"
    category = "Physical Safeguards"
    hipaa_reference = "164.310(b)"
    severity = Severity.LOW
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 3.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check screen lock timeout (already covered by ScreenLockTimeout but with different angle)
            lock_timeout = context.winrm.run_ps(
                target.hostname,
                r"(powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 2>$null | "
                r"Select-String 'Current AC Power Setting Index').ToString()"
            )

            # Check if screen orientation/privacy settings exist
            display_count = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_DesktopMonitor -ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            # Check screensaver with password
            screensaver_pwd = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' "
                r"-Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure"
            )

            # Screensaver timeout
            screensaver_timeout = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKCU:\Control Panel\Desktop' "
                r"-Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut"
            )

            screensaver_secured = screensaver_pwd.strip() == "1"

            try:
                ss_timeout = int(screensaver_timeout.strip())
            except (ValueError, AttributeError):
                ss_timeout = 0
            # 10 minutes = 600 seconds for clinical workstations
            ss_timeout_ok = 0 < ss_timeout <= 600

            try:
                monitors = int(display_count.strip())
            except (ValueError, AttributeError):
                monitors = 1

            evidence = {
                "screensaver_password_required": screensaver_secured,
                "screensaver_timeout_seconds": ss_timeout,
                "monitor_count": monitors,
                "timeout_within_10min": ss_timeout_ok,
            }

            if screensaver_secured and ss_timeout_ok:
                return self._pass(
                    target,
                    details=f"Screen security configured: password-protected screensaver activates in {ss_timeout}s ({ss_timeout//60}min).",
                    evidence=evidence,
                )
            else:
                issues = []
                if not screensaver_secured:
                    issues.append("Screensaver does not require password (screen unlocked after activation)")
                if not ss_timeout_ok:
                    issues.append(f"Screensaver timeout {ss_timeout}s ({ss_timeout//60}min) — should be ≤600s (10min) for clinical workstations")

                return self._fail(
                    target,
                    details=f"Screen privacy gaps: {'; '.join(issues)}. Clinical workstations facing patient areas are at visual hacking risk.",
                    remediation=(
                        "Configure screen privacy controls: "
                        "1. Password-protected screensaver: "
                        "   User Config > Admin Templates > Control Panel > Personalization > "
                        "   'Password protect the screen saver' → Enabled. "
                        "2. Screensaver timeout (10 min for clinical): "
                        "   'Screen saver timeout' → 600 seconds. "
                        "3. Physical controls (cannot be automated-checked): "
                        "   - Privacy screen filters on monitors facing waiting areas. "
                        "   - Monitor positioning away from public view. "
                        "   - Clean desk policy training. "
                        "   - Windows + L shortcut for manual lock when stepping away."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
