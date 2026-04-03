"""
Advanced endpoint security checks — EDR, Defender configuration, credential guard.
HIPAA reference:
  164.308(a)(5)(ii)(B) — Protection from Malicious Software (REQUIRED)
  164.312(a)(1) — Access Control (REQUIRED)
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class WindowsDefenderAtpCheck(BaseCheck):
    """
    EDR-01: Verify Windows Defender for Endpoint (MDE/ATP) or equivalent EDR is enrolled.
    Standard AV is insufficient against modern healthcare ransomware — behavioral EDR is required.
    """
    check_id = "EDR-01"
    check_name = "Endpoint Detection and Response (EDR) Enrollment"
    category = "Endpoint Security"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check MDE/ATP onboarding status
            mde_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' "
                r"-ErrorAction SilentlyContinue).OnboardingState"
            )

            # Check Defender for Endpoint service
            sense_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'Sense' -ErrorAction SilentlyContinue | "
                r"Select-Object Status, StartType | ConvertTo-Json"
            )

            # Check for third-party EDR agents
            third_party_edr = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'CSFalconService','cbdefense','SentinelAgent','CrowdStrike Falcon*',"
                r"'Cybereason Active Probe','cb','cylancesvc','TaniumClient' "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Select-Object Name | ConvertTo-Json"
            )

            # Check third-party EDR software installed
            edr_software = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.DisplayName -match 'CrowdStrike|SentinelOne|Carbon Black|Cybereason|"
                r"Cylance|Sophos Intercept|Malwarebytes|Cortex XDR|Trend Micro Apex' } | "
                r"Select-Object DisplayName | ConvertTo-Json"
            )

            mde_enrolled = mde_status.strip() == "1"
            import json as _json
            sense_svc = {}
            if sense_service.strip() not in ("", "null", "[]"):
                try:
                    sense_svc = _json.loads(sense_service)
                except Exception:
                    pass
            mde_running = sense_svc.get("Status", "").lower() == "running"

            has_third_party = (
                third_party_edr.strip() not in ("", "null", "[]") or
                edr_software.strip() not in ("", "null", "[]")
            )

            edr_names = []
            if edr_software.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(edr_software)
                    items = raw if isinstance(raw, list) else [raw]
                    edr_names = [i.get("DisplayName", "") for i in items][:3]
                except Exception:
                    pass

            evidence = {
                "mde_onboarding_state": mde_status.strip(),
                "sense_service": sense_svc.get("Status", "not found"),
                "third_party_edr": has_third_party,
                "edr_products": edr_names,
            }

            if mde_enrolled or mde_running or has_third_party:
                solution = ", ".join(edr_names) if edr_names else ("MDE" if mde_enrolled or mde_running else "Third-party EDR")
                return self._pass(
                    target,
                    details=f"EDR solution detected: {solution}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No EDR (Endpoint Detection and Response) solution detected. Standard antivirus cannot detect fileless malware, living-off-the-land attacks, or modern ransomware techniques used in healthcare breaches.",
                    remediation=(
                        "Deploy EDR on all clinical endpoints as a priority: "
                        "1. Microsoft Defender for Endpoint (MDE) — included with Microsoft 365 Business Premium. "
                        "   Onboard via Intune, SCCM, or local script from security.microsoft.com. "
                        "2. CrowdStrike Falcon, SentinelOne, or Sophos Intercept X for third-party options. "
                        "3. Malwarebytes Endpoint Detection for smaller practices (affordable). "
                        "EDR provides behavioral detection, memory analysis, and ransomware rollback. "
                        "Healthcare is the #1 ransomware target — EDR is not optional."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class CredentialGuardCheck(BaseCheck):
    """
    EDR-02: Verify Windows Credential Guard is enabled.
    Credential Guard isolates LSASS secrets in a virtualization-based security container,
    preventing credential theft attacks (Mimikatz, Pass-the-Hash, Pass-the-Ticket).
    """
    check_id = "EDR-02"
    check_name = "Windows Credential Guard"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check VBS (Virtualization-Based Security) status
            vbs_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' "
                r"-Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity"
            )

            # Check Credential Guard policy
            cg_policy = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "
                r"-Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags"
            )

            # Check if running (via DeviceGuard WMI)
            cg_running = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard "
                r"-ErrorAction SilentlyContinue).SecurityServicesRunning"
            )

            # Check TPM (required for Credential Guard)
            tpm_present = context.winrm.run_ps(
                target.hostname,
                r"(Get-Tpm -ErrorAction SilentlyContinue).TpmPresent"
            )

            vbs_enabled = vbs_status.strip() == "1"
            # LsaCfgFlags: 1=enabled without UEFI lock, 2=enabled with UEFI lock, 0=disabled
            cg_flags = int(cg_policy.strip()) if cg_policy.strip().isdigit() else 0
            cg_policy_enabled = cg_flags in (1, 2)
            # SecurityServicesRunning bit 1 = Credential Guard
            cg_active = "1" in cg_running.strip() if cg_running.strip() else False
            has_tpm = tpm_present.strip().lower() == "true"

            evidence = {
                "vbs_enabled": vbs_enabled,
                "credential_guard_policy": cg_flags,
                "credential_guard_running": cg_active,
                "tpm_present": has_tpm,
            }

            if cg_policy_enabled and vbs_enabled:
                return self._pass(
                    target,
                    details=f"Credential Guard enabled (LsaCfgFlags={cg_flags}, VBS={vbs_enabled}). LSASS credentials protected from Mimikatz-style extraction.",
                    evidence=evidence,
                )
            elif not has_tpm:
                return self._fail(
                    target,
                    details="No TPM detected — Credential Guard requires TPM 2.0. This system may not support Credential Guard.",
                    remediation=(
                        "Enable TPM 2.0 in BIOS/UEFI settings and then configure Credential Guard: "
                        "Computer Configuration > Administrative Templates > System > Device Guard > "
                        "Turn On Virtualization Based Security: Enabled, "
                        "Credential Guard Configuration: Enabled with UEFI lock."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Credential Guard is not enabled. LSASS memory is accessible — Mimikatz and similar tools can extract password hashes and Kerberos tickets.",
                    remediation=(
                        "Enable Credential Guard via Group Policy: "
                        "Computer Configuration > Administrative Templates > System > Device Guard > "
                        "Turn On Virtualization Based Security = Enabled. "
                        "Credential Guard Configuration = Enabled with UEFI lock. "
                        "Requires Windows 10/11 Enterprise or Education, TPM 2.0, and Secure Boot. "
                        "Alternative: Enable Protected Users security group for Domain Admins (prevents NTLM caching)."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class SharedAccountDetectionCheck(BaseCheck):
    """
    EDR-03 (Access Control): Detect shared/generic accounts with recent login activity.
    Shared accounts violate HIPAA 164.312(a)(2)(i) unique user identification requirement.
    Every ePHI access must be traceable to an individual.
    """
    check_id = "EDR-03"
    check_name = "Shared / Generic Account Detection"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 12.0

    SHARED_ACCOUNT_PATTERNS = [
        "admin", "administrator", "shared", "generic", "reception", "frontdesk",
        "front.desk", "nurse", "doctor", "physician", "staff", "user", "workstation",
        "kiosk", "tablet", "demo", "test", "temp", "guest", "public",
    ]

    def run(self, target: Target, context) -> Finding:
        try:
            # Check for generic/shared local accounts that have logged in recently
            shared_local = context.winrm.run_ps(
                target.hostname,
                r"$cutoff = (Get-Date).AddDays(-30); "
                r"Get-LocalUser -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Enabled -eq $true -and $_.LastLogon -gt $cutoff } | "
                r"Select-Object Name, LastLogon | ConvertTo-Json"
            )

            # Also check domain accounts with generic names (if DC is available)
            shared_domain = context.winrm.run_ps(
                target.hostname,
                r"$cutoff = (Get-Date).AddDays(-30); "
                r"$patterns = @('shared','generic','reception','frontdesk','staff','kiosk','nurse','doctor','physician'); "
                r"Get-ADUser -Filter * -Properties LastLogonDate,Enabled -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -gt $cutoff -and "
                r"  ($patterns | Where-Object { $_.SAMAccountName -match $_ }) } | "
                r"Select-Object SamAccountName, LastLogonDate | ConvertTo-Json"
            )

            import json as _json
            local_accounts = []
            if shared_local.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(shared_local)
                    all_local = raw if isinstance(raw, list) else [raw]
                    # Filter by generic name patterns
                    for acct in all_local:
                        name = acct.get("Name", "").lower()
                        if any(pat in name for pat in self.SHARED_ACCOUNT_PATTERNS):
                            local_accounts.append(acct.get("Name", name))
                except Exception:
                    pass

            domain_accounts = []
            if shared_domain.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(shared_domain)
                    items = raw if isinstance(raw, list) else [raw]
                    domain_accounts = [a.get("SamAccountName", "") for a in items][:10]
                except Exception:
                    pass

            all_shared = local_accounts + domain_accounts

            evidence = {
                "shared_local_accounts_found": local_accounts[:10],
                "shared_domain_accounts_found": domain_accounts[:10],
                "total_shared_detected": len(all_shared),
            }

            if not all_shared:
                return self._pass(
                    target,
                    details="No recently-active shared or generic accounts detected.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"{len(all_shared)} shared/generic account(s) with recent login activity: {', '.join(all_shared[:5])}. ePHI access cannot be attributed to individuals with shared accounts.",
                    remediation=(
                        "Replace shared accounts with individual accounts per HIPAA 164.312(a)(2)(i): "
                        "1. Create individual accounts for each employee (firstname.lastname). "
                        "2. Disable shared accounts after individual accounts are configured. "
                        "3. For kiosks/tablets: use Assigned Access (kiosk mode) with no ePHI access, "
                        "   then require individual login for ePHI-accessing applications. "
                        "Shared accounts make HIPAA audit logging useless — you can't know who accessed what."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class PowershellLoggingCheck(BaseCheck):
    """
    AUDIT-01 (Advanced): Verify PowerShell script block logging and module logging are enabled.
    PowerShell is the top tool for living-off-the-land attacks and ransomware deployment.
    Without logging, PowerShell-based attacks leave minimal forensic evidence.
    """
    check_id = "AUDIT-01"
    check_name = "PowerShell Script Block and Module Logging"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check script block logging
            sbl = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' "
                r"-Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging"
            )

            # Check module logging
            module_logging = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' "
                r"-Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging"
            )

            # Check transcription logging
            transcription = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' "
                r"-Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting"
            )

            # Check PowerShell version (v2 can bypass logging - downgrade attack)
            ps_v2 = context.winrm.run_ps(
                target.hostname,
                r"(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root "
                r"-ErrorAction SilentlyContinue).State"
            )

            sbl_enabled = sbl.strip() == "1"
            mod_enabled = module_logging.strip() == "1"
            trans_enabled = transcription.strip() == "1"
            ps2_present = "enabled" in ps_v2.strip().lower()

            evidence = {
                "script_block_logging": sbl_enabled,
                "module_logging": mod_enabled,
                "transcription_logging": trans_enabled,
                "powershell_v2_enabled": ps2_present,
            }

            issues = []
            if not sbl_enabled:
                issues.append("Script Block Logging disabled")
            if not mod_enabled:
                issues.append("Module Logging disabled")
            if ps2_present:
                issues.append("PowerShell v2 present (logging bypass risk)")

            if not issues:
                return self._pass(
                    target,
                    details="PowerShell Script Block Logging and Module Logging are enabled.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"PowerShell logging gaps: {'; '.join(issues)}. Attackers can execute malicious PowerShell without leaving logs.",
                    remediation=(
                        "Enable PowerShell logging via Group Policy: "
                        "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell: "
                        "1. Turn on PowerShell Script Block Logging: Enabled. "
                        "2. Turn on Module Logging: Enabled, Module Name: *. "
                        "3. Turn on PowerShell Transcription: Enabled. "
                        "4. Remove PowerShell v2: Disable-WindowsOptionalFeature -Online "
                        "   -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable PowerShell logging via registry:\n"
                        "# Script Block Logging:\n"
                        "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
                        "-Force | Out-Null\n"
                        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
                        "-Name EnableScriptBlockLogging -Value 1 -Type DWord\n"
                        "# Module Logging:\n"
                        "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' "
                        "-Force | Out-Null\n"
                        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' "
                        "-Name EnableModuleLogging -Value 1 -Type DWord\n"
                        "# Disable PS v2:\n"
                        "Disable-WindowsOptionalFeature -Online "
                        "-FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
