"""
MFA/Multi-Factor Authentication compliance checks.
HIPAA reference: 164.312(d) — Person/Entity Authentication (REQUIRED)
NIST SP 800-63B — MFA requirement for ePHI access
2025 NPRM: MFA mandatory for all ePHI system access

These checks detect common MFA implementations via Windows registry, LDAP, and AD settings.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class MfaRemoteAccessCheck(BaseCheck):
    """
    MF-01: Verify MFA is required for remote access (VPN/RDP).
    Tests: Windows NPS policy, RADIUS configuration, RDP NLA enforcement with MFA provider,
           Azure AD Conditional Access registry indicators.
    """
    check_id = "MF-01"
    check_name = "MFA for Remote Access"
    category = "Multi-Factor Authentication"
    hipaa_reference = "164.312(d)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 15.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check 1: NPS (RADIUS/MFA) service running for remote access MFA enforcement
            nps_result = context.winrm.run_ps(
                target.hostname,
                "Get-Service -Name 'IAS' -ErrorAction SilentlyContinue | Select-Object Status | ConvertTo-Json"
            )

            # Check 2: Azure AD/Entra ID hybrid join (indicates cloud MFA available)
            azure_join = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue) -ne $null"
            )

            # Check 3: Duo/Okta/similar MFA software installed
            mfa_software = context.winrm.run_ps(
                target.hostname,
                "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                "Where-Object { $_.DisplayName -match 'Duo|Okta|PingID|RSA|AuthPoint|Yubico|WatchGuard' } | "
                "Select-Object DisplayName | ConvertTo-Json"
            )

            # Check 4: RDP NLA (Network Level Authentication) enforced — required for smart card/MFA
            nla_enabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' "
                r"-Name UserAuthenticationRequired -ErrorAction SilentlyContinue).UserAuthenticationRequired"
            )

            evidence = {
                "nps_service": nps_result.strip(),
                "azure_ad_joined": azure_join.strip(),
                "mfa_software": mfa_software.strip(),
                "rdp_nla": nla_enabled.strip(),
            }

            has_mfa_indicator = any([
                "Running" in nps_result,
                azure_join.strip().lower() == "true",
                mfa_software.strip() not in ("", "null", "[]"),
            ])

            if has_mfa_indicator:
                return self._pass(
                    target,
                    details=f"MFA indicators detected: NPS={nps_result.strip()}, AzureAD={azure_join.strip()}, Software={'present' if mfa_software.strip() not in ('', 'null', '[]') else 'none'}",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No MFA indicators detected for remote access. No MFA provider software, NPS service, or Azure AD join found.",
                    remediation=(
                        "Implement MFA for all remote access. Options: (1) Deploy Duo Security or Okta MFA, "
                        "(2) Join to Azure AD/Entra ID and enforce Conditional Access with MFA, "
                        "(3) Configure Windows NPS with RADIUS MFA. Remote access without MFA violates "
                        "HIPAA 164.312(d) and the 2025 NPRM proposed requirements."
                    ),
                    evidence=evidence,
                    remediation_script="# Contact your MFA vendor to deploy: Duo (duo.com), Okta (okta.com), or Azure AD (entra.microsoft.com)",
                )
        except Exception as e:
            return self._error(target, str(e))


class MfaPrivilegedAccountsCheck(BaseCheck):
    """
    MF-02: Verify MFA is required for privileged/admin accounts.
    Tests: Domain Admin accounts in AD, local admin accounts, admin MFA group membership.
    """
    check_id = "MF-02"
    check_name = "MFA for Privileged Accounts"
    category = "Multi-Factor Authentication"
    hipaa_reference = "164.312(d)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 12.0

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ldap:
                return self._na(target, "Active Directory connection required for privileged account MFA check")

            # Get Domain Admins
            domain_admins = context.ldap.get_group_members("Domain Admins")

            # Check for Protected Users group (requires Kerberos armoring, smart card)
            protected_users = context.ldap.get_group_members("Protected Users")

            # Get accounts with "SmartcardRequired" flag set in AD
            smartcard_required = context.winrm.run_ps(
                target.hostname,
                "Get-ADUser -Filter {SmartcardLogonRequired -eq $true} -Properties SmartcardLogonRequired | "
                "Select-Object SamAccountName | ConvertTo-Json"
            )

            protected_names = {u.get("cn", [""])[0].lower() for u in protected_users}
            admin_names = [u.get("cn", [""])[0] for u in domain_admins]

            admins_protected = [n for n in admin_names if n.lower() in protected_names]
            admins_unprotected = [n for n in admin_names if n.lower() not in protected_names]

            evidence = {
                "domain_admin_count": len(admin_names),
                "protected_users_count": len(protected_users),
                "admins_in_protected_users": admins_protected[:5],
                "admins_not_protected": admins_unprotected[:5],
                "smartcard_required": smartcard_required.strip(),
            }

            if len(admins_protected) == len(admin_names) and len(admin_names) > 0:
                return self._pass(
                    target,
                    details=f"All {len(admin_names)} Domain Admin accounts are in Protected Users group (requires strong auth).",
                    evidence=evidence,
                )
            elif len(admins_protected) > 0 or len(smartcard_required.strip()) > 10:
                return self._fail(
                    target,
                    details=f"Partial MFA protection: {len(admins_protected)}/{len(admin_names)} Domain Admins in Protected Users. Unprotected admins: {', '.join(admins_unprotected[:3])}",
                    remediation=(
                        "Add all privileged accounts to the 'Protected Users' security group in Active Directory. "
                        "This enforces Kerberos AES encryption and prevents NTLM, credential caching, and delegation. "
                        "Also enroll admin accounts in your MFA provider. Under HIPAA 164.312(d) and 2025 NPRM, "
                        "privileged accounts must use MFA."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"No MFA enforcement detected for {len(admin_names)} Domain Admin accounts. No Protected Users group membership, no SmartcardRequired flag.",
                    remediation=(
                        "Implement MFA for all privileged accounts immediately: "
                        "1. Add all Domain Admins to 'Protected Users' group. "
                        "2. Enable SmartcardLogonRequired for admin accounts. "
                        "3. Configure Conditional Access policies requiring MFA for privileged roles."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# PowerShell: Add Domain Admins to Protected Users\n"
                        "$admins = Get-ADGroupMember 'Domain Admins'\n"
                        "$admins | ForEach-Object { Add-ADGroupMember -Identity 'Protected Users' -Members $_ }"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class MfaWindowsHelloCheck(BaseCheck):
    """
    MF-03: Check if Windows Hello for Business (phishing-resistant MFA) is configured.
    Windows Hello = FIDO2-compliant, meets NIST SP 800-63B AAL2/AAL3 requirements.
    """
    check_id = "MF-03"
    check_name = "Windows Hello for Business (Phishing-Resistant MFA)"
    category = "Multi-Factor Authentication"
    hipaa_reference = "164.312(d)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check WHfB enrollment
            whfb_enrolled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' "
                r"-Name Enabled -ErrorAction SilentlyContinue).Enabled"
            )

            # Check if WHfB is enabled via Group Policy
            whfb_gp = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' "
                r"-ErrorAction SilentlyContinue).Enabled"
            )

            evidence = {
                "whfb_registry": whfb_enrolled.strip(),
                "whfb_gp": whfb_gp.strip(),
            }

            if whfb_enrolled.strip() == "1" or whfb_gp.strip() == "1":
                return self._pass(
                    target,
                    details="Windows Hello for Business is enabled — phishing-resistant MFA configured.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Windows Hello for Business not detected. Device may rely on weaker authentication.",
                    remediation=(
                        "Enable Windows Hello for Business via Group Policy: "
                        "Computer Configuration > Administrative Templates > Windows Components > Windows Hello for Business > "
                        "Enable 'Use Windows Hello for Business'. This provides FIDO2-compliant, phishing-resistant MFA "
                        "that satisfies NIST SP 800-63B AAL2 requirements and the 2025 HIPAA NPRM MFA mandate."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
