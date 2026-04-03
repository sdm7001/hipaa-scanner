"""
Group Policy and Windows security baseline checks.
HIPAA reference: 164.312(a)(1) — Access Control (REQUIRED)
NIST SP 800-66r2: Section 3.5 — Security Controls

Group Policy is the foundation of Windows security configuration.
Missing or misconfigured GPOs leave workstations and servers in
insecure default states even when policies exist on paper.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class NtlmRelayProtectionCheck(BaseCheck):
    """
    SEC-01: Verify NTLM relay attack protections are enabled.
    NTLM relay is one of the most common Active Directory attack vectors.
    Extended Protection for Authentication (EPA) and SMB signing mitigate this.
    """
    check_id = "SEC-01"
    check_name = "NTLM Relay Attack Protection"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.DOMAIN_CONTROLLER, TargetRole.SERVER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check NTLM restrictions
            ntlm_level = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "
                r"-Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel"
            )

            # Check SMB signing (required for relay protection)
            smb_signing = context.winrm.run_ps(
                target.hostname,
                r"(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature"
            )

            # Check LDAP signing requirement
            ldap_signing = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' "
                r"-Name 'ldapserverintegrity' -ErrorAction SilentlyContinue).ldapserverintegrity"
            )

            # Check LDAP channel binding (Windows Server 2019+)
            ldap_channel = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' "
                r"-Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding"
            )

            # NTLMv1 disabled = level 5 (NTLMv2 only) or level 3+ (preferred)
            try:
                level = int(ntlm_level.strip())
            except (ValueError, AttributeError):
                level = 0

            ntlmv2_only = level >= 3
            smb_sign_req = smb_signing.strip().lower() == "true"

            try:
                ldap_sign_val = int(ldap_signing.strip())
            except (ValueError, AttributeError):
                ldap_sign_val = 0
            ldap_sign_req = ldap_sign_val >= 2  # 2 = Require signing

            try:
                ldap_chan_val = int(ldap_channel.strip())
            except (ValueError, AttributeError):
                ldap_chan_val = 0
            ldap_chan_bind = ldap_chan_val >= 1

            evidence = {
                "lm_compatibility_level": level,
                "ntlmv2_only": ntlmv2_only,
                "smb_signing_required": smb_sign_req,
                "ldap_signing_level": ldap_sign_val,
                "ldap_channel_binding": ldap_chan_val,
            }

            score = sum([ntlmv2_only, smb_sign_req, ldap_sign_req, ldap_chan_bind])

            if score >= 3:
                return self._pass(
                    target,
                    details=f"NTLM relay protections in place: NTLMv2-only={ntlmv2_only}, SMB signing={smb_sign_req}, LDAP signing={ldap_sign_req}, Channel binding={ldap_chan_bind}.",
                    evidence=evidence,
                )
            else:
                issues = []
                if not ntlmv2_only:
                    issues.append(f"LmCompatibilityLevel={level} (should be ≥3 for NTLMv2 only, 5 recommended)")
                if not smb_sign_req:
                    issues.append("SMB signing not required (enables NTLM relay via SMB)")
                if not ldap_sign_req:
                    issues.append("LDAP signing not required (enables LDAP relay attacks)")
                if not ldap_chan_bind:
                    issues.append("LDAP channel binding not configured")

                return self._fail(
                    target,
                    details=f"NTLM relay protections incomplete ({score}/4 controls active): {'; '.join(issues)}",
                    remediation=(
                        "Enable NTLM relay protections via GPO: "
                        "1. LmCompatibilityLevel=5: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > "
                        "   'Network security: LAN Manager authentication level' → 'Send NTLMv2 response only/refuse LM & NTLM'. "
                        "2. SMB Signing: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > "
                        "   'Microsoft network server: Digitally sign communications (always)' → Enabled. "
                        "3. LDAP Signing: 'Domain controller: LDAP server signing requirements' → 'Require signing'. "
                        "4. LDAP Channel Binding: KB4520412 patch + registry LdapEnforceChannelBinding=2."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class DefenderConfigurationCheck(BaseCheck):
    """
    SEC-02: Verify Windows Defender is fully configured with attack surface reduction rules.
    Default Defender install lacks many hardening options that block common attack chains.
    """
    check_id = "SEC-02"
    check_name = "Windows Defender Advanced Configuration"
    category = "Antivirus/EDR"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check if Defender is the active AV
            defender_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled"
            )

            if defender_status.strip().lower() != "true":
                return self._na(target, "Windows Defender is not the active antivirus — third-party AV controls this domain.")

            # Check real-time protection
            realtime = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"
            )

            # Check cloud protection level
            cloud_block = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).CloudBlockLevel"
            )

            # Check behavior monitoring
            behavior_mon = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).DisableBehaviorMonitoring"
            )

            # Check PUA protection
            pua = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).PUAProtection"
            )

            # Check Attack Surface Reduction rules enabled count
            asr_rules = context.winrm.run_ps(
                target.hostname,
                r"$rules = (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids; "
                r"if ($rules) { $rules.Count } else { 0 }"
            )

            # Check network protection
            network_prot = context.winrm.run_ps(
                target.hostname,
                r"(Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection"
            )

            realtime_ok = realtime.strip().lower() == "true"
            behavior_ok = behavior_mon.strip().lower() == "false"  # DisableBehaviorMonitoring=False means enabled
            pua_ok = pua.strip() in ("1", "2")  # 1=Audit, 2=Block

            try:
                cloud_level = int(cloud_block.strip())
            except (ValueError, AttributeError):
                cloud_level = 0
            cloud_ok = cloud_level >= 2  # High or higher

            try:
                asr_count = int(asr_rules.strip())
            except (ValueError, AttributeError):
                asr_count = 0
            asr_ok = asr_count >= 5  # At least 5 ASR rules enabled

            try:
                netprot_val = int(network_prot.strip())
            except (ValueError, AttributeError):
                netprot_val = 0
            netprot_ok = netprot_val >= 1  # 1=Audit, 2=Block

            score = sum([realtime_ok, behavior_ok, pua_ok, cloud_ok, asr_ok, netprot_ok])

            evidence = {
                "realtime_protection": realtime_ok,
                "behavior_monitoring": behavior_ok,
                "pua_protection": pua.strip(),
                "cloud_block_level": cloud_level,
                "asr_rules_count": asr_count,
                "network_protection_level": netprot_val,
            }

            if score >= 5:
                return self._pass(
                    target,
                    details=f"Defender well-configured ({score}/6 controls active): {asr_count} ASR rules, cloud level {cloud_level}, network protection enabled.",
                    evidence=evidence,
                )
            else:
                issues = []
                if not realtime_ok:
                    issues.append("Real-time protection disabled")
                if not behavior_ok:
                    issues.append("Behavior monitoring disabled")
                if not pua_ok:
                    issues.append("PUA/PUP protection not configured")
                if not cloud_ok:
                    issues.append(f"Cloud protection level {cloud_level} (recommend ≥2)")
                if not asr_ok:
                    issues.append(f"Only {asr_count} ASR rules active (recommend ≥5)")
                if not netprot_ok:
                    issues.append("Network protection disabled")

                return self._fail(
                    target,
                    details=f"Defender under-configured ({score}/6 controls active): {'; '.join(issues)}",
                    remediation=(
                        "Harden Windows Defender via PowerShell or Intune/GPO: "
                        "Set-MpPreference -PUAProtection 2 -EnableNetworkProtection 2 -CloudBlockLevel 4 "
                        "-DisableBehaviorMonitoring $false. "
                        "Enable ASR rules: "
                        "Add-MpPreference -AttackSurfaceReductionRules_Ids <rule-guid> -AttackSurfaceReductionRules_Actions Enabled. "
                        "Key ASR rules: Block Office macros, credential theft from LSASS, "
                        "untrusted executables from email, obfuscated scripts. "
                        "Full list: docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Configure Windows Defender hardening:\\n"
                        "Set-MpPreference -PUAProtection 2\\n"
                        "Set-MpPreference -EnableNetworkProtection 2\\n"
                        "Set-MpPreference -CloudBlockLevel 4\\n"
                        "Set-MpPreference -DisableBehaviorMonitoring $false\\n"
                        "# Enable key ASR rules (Audit mode first: use '2' instead of '1'):\\n"
                        "$asrRules = @(\\n"
                        "  'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Block Office child processes\\n"
                        "  '3B576869-A4EC-4529-8536-B80A7769E899',  # Block Office from creating executables\\n"
                        "  '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',  # Block Office from injecting into processes\\n"
                        "  '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',  # Block credential stealing from LSASS\\n"
                        "  'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'   # Block executable content from email\\n"
                        ")\\n"
                        "$asrRules | ForEach-Object { Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions Enabled }"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class SecureBootCheck(BaseCheck):
    """
    SEC-03: Verify Secure Boot and TPM are enabled.
    Secure Boot prevents bootkit/rootkit persistence. TPM enables hardware-backed
    encryption (BitLocker) and credential isolation (Credential Guard).
    """
    check_id = "SEC-03"
    check_name = "Secure Boot and TPM Configuration"
    category = "Endpoint Security"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Secure Boot state
            secure_boot = context.winrm.run_ps(
                target.hostname,
                r"Confirm-SecureBootUEFI -ErrorAction SilentlyContinue"
            )

            # Check TPM presence and status
            tpm_present = context.winrm.run_ps(
                target.hostname,
                r"$tpm = Get-Tpm -ErrorAction SilentlyContinue; "
                r"if ($tpm) { \"$($tpm.TpmPresent),$($tpm.TpmReady),$($tpm.TpmEnabled)\" } else { 'False,False,False' }"
            )

            # Check TPM version
            tpm_version = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject -Namespace root\cimv2\security\microsofttpm "
                r"-Class Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion"
            )

            # Check UEFI vs Legacy BIOS
            bios_mode = context.winrm.run_ps(
                target.hostname,
                r"(Get-ComputerInfo -ErrorAction SilentlyContinue).BiosFirmwareType"
            )

            secure_boot_enabled = secure_boot.strip().lower() == "true"

            tpm_parts = tpm_present.strip().split(",")
            tpm_present_ok = len(tpm_parts) >= 1 and tpm_parts[0].lower() == "true"
            tpm_ready = len(tpm_parts) >= 2 and tpm_parts[1].lower() == "true"

            # TPM 2.0 is required for modern Windows security features
            tpm_ver = tpm_version.strip()
            tpm_20 = "2.0" in tpm_ver if tpm_ver else False

            uefi_mode = "uefi" in bios_mode.strip().lower() if bios_mode.strip() else False

            evidence = {
                "secure_boot_enabled": secure_boot_enabled,
                "tpm_present": tpm_present_ok,
                "tpm_ready": tpm_ready,
                "tpm_version": tpm_ver or "not detected",
                "tpm_20": tpm_20,
                "firmware_type": bios_mode.strip() or "unknown",
            }

            if secure_boot_enabled and tpm_present_ok and tpm_ready:
                return self._pass(
                    target,
                    details=f"Secure Boot enabled, TPM {tpm_ver or 'present'} ready. Hardware security baseline met.",
                    evidence=evidence,
                )
            else:
                issues = []
                if not uefi_mode:
                    issues.append("Legacy BIOS detected — Secure Boot requires UEFI firmware")
                if not secure_boot_enabled:
                    issues.append("Secure Boot is disabled or not supported")
                if not tpm_present_ok:
                    issues.append("No TPM detected — BitLocker without TPM is less secure")
                elif not tpm_ready:
                    issues.append("TPM present but not initialized/ready")
                if tpm_present_ok and not tpm_20:
                    issues.append(f"TPM version {tpm_ver} — TPM 2.0 required for Credential Guard and Device Health Attestation")

                return self._fail(
                    target,
                    details=f"Hardware security baseline incomplete: {'; '.join(issues)}",
                    remediation=(
                        "Enable Secure Boot and TPM via firmware (BIOS/UEFI) settings: "
                        "1. Secure Boot: Enter UEFI firmware → Security → Secure Boot → Enable. "
                        "   Convert from Legacy/CSM to UEFI boot mode first if needed. "
                        "2. TPM: Enable via UEFI firmware → Security → PTT (Intel) or fTPM (AMD) → Enable. "
                        "3. Initialize TPM in Windows: tpm.msc → Initialize TPM. "
                        "4. TPM 2.0 required for: Credential Guard, BitLocker Network Unlock, "
                        "   Device Health Attestation, Windows Hello for Business, Autopilot."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class UserRightsAssignmentCheck(BaseCheck):
    """
    SEC-04: Verify critical user rights assignments are locked down.
    'Log on locally', 'Act as part of OS', and 'Debug programs' rights on
    non-admin accounts represent serious privilege escalation paths.
    """
    check_id = "SEC-04"
    check_name = "User Rights Assignment Hardening"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.DOMAIN_CONTROLLER, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Export security policy and check user rights
            secedit_output = context.winrm.run_ps(
                target.hostname,
                r"$tmpFile = [System.IO.Path]::GetTempFileName(); "
                r"secedit /export /areas USER_RIGHTS /cfg $tmpFile | Out-Null; "
                r"$content = Get-Content $tmpFile -ErrorAction SilentlyContinue; "
                r"Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue; "
                r"$content -match 'SeDebugPrivilege|SeTcbPrivilege|SeNetworkLogonRight|SeRemoteInteractiveLogonRight' | "
                r"Out-String"
            )

            # Check specifically for 'Debug programs' right (SeDebugPrivilege)
            # Should only be Administrators
            debug_right = context.winrm.run_ps(
                target.hostname,
                r"$tmp = [System.IO.Path]::GetTempFileName(); "
                r"secedit /export /areas USER_RIGHTS /cfg $tmp 2>$null | Out-Null; "
                r"$line = (Get-Content $tmp | Where-Object { $_ -match 'SeDebugPrivilege' }); "
                r"Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
                r"$line"
            )

            # Check 'Act as part of operating system' (SeTcbPrivilege) - should be empty
            tcb_right = context.winrm.run_ps(
                target.hostname,
                r"$tmp = [System.IO.Path]::GetTempFileName(); "
                r"secedit /export /areas USER_RIGHTS /cfg $tmp 2>$null | Out-Null; "
                r"$line = (Get-Content $tmp | Where-Object { $_ -match 'SeTcbPrivilege' }); "
                r"Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
                r"$line"
            )

            # Check remote desktop users restricted
            rdp_users = context.winrm.run_ps(
                target.hostname,
                r"$tmp = [System.IO.Path]::GetTempFileName(); "
                r"secedit /export /areas USER_RIGHTS /cfg $tmp 2>$null | Out-Null; "
                r"$line = (Get-Content $tmp | Where-Object { $_ -match 'SeRemoteInteractiveLogonRight' }); "
                r"Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
                r"$line"
            )

            issues = []

            # SeDebugPrivilege should only be *S-1-5-32-544 (Administrators)
            if debug_right.strip():
                debug_val = debug_right.strip()
                if debug_val and "SeDebugPrivilege" in debug_val:
                    # Check if non-admin SIDs are present
                    if not (debug_val.count(",") == 0 or "544" in debug_val):
                        issues.append("SeDebugPrivilege (Debug programs) granted to non-Administrators groups")

            # SeTcbPrivilege should be empty/not assigned
            if tcb_right.strip() and "SeTcbPrivilege" in tcb_right:
                tcb_val = tcb_right.strip().split("=")[-1].strip() if "=" in tcb_right else ""
                if tcb_val and tcb_val not in ("", '""'):
                    issues.append(f"SeTcbPrivilege (Act as OS) is assigned to: {tcb_val[:100]}")

            evidence = {
                "debug_privilege_line": debug_right.strip()[:200] if debug_right.strip() else "not found",
                "tcb_privilege_line": tcb_right.strip()[:200] if tcb_right.strip() else "not found",
                "rdp_logon_line": rdp_users.strip()[:200] if rdp_users.strip() else "not found",
                "issues_found": len(issues),
            }

            if not issues:
                return self._pass(
                    target,
                    details="User rights assignments appear appropriately restricted. No dangerous privilege grants detected.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Dangerous user rights assignments found: {'; '.join(issues)}",
                    remediation=(
                        "Review and restrict user rights via GPO: "
                        "Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment. "
                        "Key restrictions: "
                        "1. SeDebugPrivilege (Debug programs): Administrators only. "
                        "2. SeTcbPrivilege (Act as OS): Empty (no one). "
                        "3. SeTakeOwnershipPrivilege: Administrators only. "
                        "4. SeNetworkLogonRight: Remove 'Everyone' if present. "
                        "Use Microsoft Security Compliance Toolkit baseline for reference values."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class WindowsHelloForBusinessCheck(BaseCheck):
    """
    SEC-05: Verify Windows Hello for Business (WHfB) is deployed for passwordless MFA.
    WHfB replaces passwords with TPM-backed asymmetric keys — phishing-resistant MFA
    that meets 2025 HIPAA NPRM requirements for strong authentication.
    """
    check_id = "SEC-05"
    check_name = "Windows Hello for Business"
    category = "Multi-Factor Authentication"
    hipaa_reference = "164.312(d)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check WHfB GPO/policy configured on workstation
            whfb_gpo = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' "
                r"-Name Enabled -ErrorAction SilentlyContinue).Enabled"
            )

            # Check WHfB enrollment status for current machine
            whfb_enrolled = context.winrm.run_ps(
                target.hostname,
                r"$ngc = Get-ChildItem 'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc' "
                r"-ErrorAction SilentlyContinue; "
                r"if ($ngc) { $ngc.Count } else { 0 }"
            )

            # Check Intune WHfB policy
            intune_whfb = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork' "
                r"-Name Enabled -ErrorAction SilentlyContinue).Enabled"
            )

            # Check if PIN is complex requirement is set
            pin_complex = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' "
                r"-Name RequireDigits -ErrorAction SilentlyContinue).RequireDigits"
            )

            # Check Azure AD joined (required for cloud WHfB)
            aad_joined = context.winrm.run_ps(
                target.hostname,
                r"(dsregcmd /status 2>$null | Select-String 'AzureAdJoined').ToString()"
            )

            whfb_policy = (
                whfb_gpo.strip() == "1" or
                intune_whfb.strip() == "1" or
                "YES" in aad_joined.upper()
            )

            try:
                enrolled_count = int(whfb_enrolled.strip())
            except (ValueError, AttributeError):
                enrolled_count = 0

            evidence = {
                "whfb_gpo_enabled": whfb_gpo.strip(),
                "whfb_intune_policy": intune_whfb.strip(),
                "ngc_enrollment_count": enrolled_count,
                "aad_joined": "YES" in aad_joined.upper() if aad_joined.strip() else False,
                "pin_complexity_configured": pin_complex.strip() == "1",
            }

            if whfb_policy and enrolled_count > 0:
                return self._pass(
                    target,
                    details=f"Windows Hello for Business configured and enrolled ({enrolled_count} credential(s)). Phishing-resistant MFA active.",
                    evidence=evidence,
                )
            elif whfb_policy:
                return self._fail(
                    target,
                    details="WHfB policy is configured but no enrollment detected. Policy may be newly deployed or user hasn't completed enrollment.",
                    remediation=(
                        "Verify WHfB enrollment: "
                        "1. User must complete WHfB setup during next login (Start → Settings → Accounts → Sign-in options). "
                        "2. Check enrollment status: Get-WinEvent -LogName 'Microsoft-Windows-HelloForBusiness/Operational'. "
                        "3. For domain join: ensure DC has ADFS or Azure AD Connect for hybrid join. "
                        "4. For Intune: verify WHfB policy is deployed and enrolled devices show compliance."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Windows Hello for Business not configured. This workstation uses password-only authentication.",
                    remediation=(
                        "Deploy Windows Hello for Business: "
                        "Cloud-only (Azure AD): Intune → Device Configuration → Endpoint Protection → Windows Hello for Business → Enable. "
                        "Hybrid domain-joined: "
                        "1. Configure Key Trust or Certificate Trust deployment. "
                        "2. GPO: Computer Config > Admin Templates > Windows Components > Windows Hello for Business → Enable. "
                        "3. Requires TPM 2.0, Windows 10 1703+, and Azure AD Connect for hybrid. "
                        "WHfB provides phishing-resistant MFA that meets 2025 HIPAA NPRM authentication requirements."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LocalFirewallRulesAuditCheck(BaseCheck):
    """
    SEC-06: Verify Windows Firewall has no overly permissive inbound rules
    that could expose services. A common misconfiguration is an 'Allow All'
    rule added by software installers.
    """
    check_id = "SEC-06"
    check_name = "Windows Firewall Inbound Rules Audit"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Find overly permissive enabled inbound rules (allow all from any to any)
            broad_rules = context.winrm.run_ps(
                target.hostname,
                r"Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Profile -eq 'Any' -or $_.Profile -eq 'Domain,Private,Public' } | "
                r"Get-NetFirewallAddressFilter | "
                r"Where-Object { $_.RemoteAddress -eq 'Any' } | "
                r"Select-Object -First 5 @{N='Rule';E={$_.CreationClassName}} | "
                r"Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Count total inbound allow rules
            total_allow = context.winrm.run_ps(
                target.hostname,
                r"(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
                r"-ErrorAction SilentlyContinue | Measure-Object).Count"
            )

            # Check for rules that allow everything on all ports (risky)
            any_port_rules = context.winrm.run_ps(
                target.hostname,
                r"$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
                r"-ErrorAction SilentlyContinue; "
                r"$risky = $rules | Where-Object { "
                r"  $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
                r"  $pf -and ($pf.LocalPort -eq 'Any' -or $pf.LocalPort -eq '') "
                r"} | Measure-Object; "
                r"$risky.Count"
            )

            try:
                broad_count = int(broad_rules.strip())
            except (ValueError, AttributeError):
                broad_count = 0

            try:
                total_count = int(total_allow.strip())
            except (ValueError, AttributeError):
                total_count = 0

            try:
                any_port_count = int(any_port_rules.strip())
            except (ValueError, AttributeError):
                any_port_count = 0

            evidence = {
                "total_inbound_allow_rules": total_count,
                "broad_any_to_any_rules": broad_count,
                "any_port_allow_rules": any_port_count,
            }

            if broad_count == 0 and any_port_count < 5:
                return self._pass(
                    target,
                    details=f"{total_count} inbound allow rules, none are overly permissive (allow-any-to-any). Firewall rules appear appropriately scoped.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"{broad_count} broad inbound allow rules (any-to-any) and {any_port_count} rules allowing any port detected out of {total_count} total. These may expose services unnecessarily.",
                    remediation=(
                        "Audit and tighten firewall rules: "
                        "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | "
                        "Get-NetFirewallAddressFilter | Where-Object { $_.RemoteAddress -eq 'Any' }. "
                        "For each broad rule: "
                        "1. Identify the creating application. "
                        "2. Restrict RemoteAddress to specific IPs/subnets. "
                        "3. Restrict LocalPort to required ports only. "
                        "4. Remove rules that are no longer needed. "
                        "Consider Microsoft Security Compliance Toolkit firewall baselines."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
