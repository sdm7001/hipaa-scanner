"""
Privileged access management compliance checks.
HIPAA reference: 164.312(a)(1) — Access Control (REQUIRED)
NIST SP 800-66r2: Section 3.2 — Access Controls, least privilege enforcement

Privileged accounts are the primary target in healthcare breaches.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class LapsCheck(BaseCheck):
    """
    PAM-01: Verify Local Administrator Password Solution (LAPS) or equivalent is deployed.
    Without LAPS, all machines share the same local admin password — one compromised machine
    compromises every machine.
    """
    check_id = "PAM-01"
    check_name = "Local Administrator Password Solution (LAPS)"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Windows LAPS (modern — built into Windows 11 22H2+ / Server 2019+)
            laps_modern = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' "
                r"-ErrorAction SilentlyContinue) -ne $null"
            )

            # Check legacy LAPS (CSE/GPO extension)
            laps_legacy = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' "
                r"-Name AdmPwdEnabled -ErrorAction SilentlyContinue).AdmPwdEnabled"
            )

            # Check LAPS AD schema extension (DC check)
            laps_schema = context.winrm.run_ps(
                target.hostname,
                r"try { "
                r"  Import-Module AdmPwd.PS -ErrorAction SilentlyContinue; "
                r"  (Get-AdmPwdPassword -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue) -ne $null "
                r"} catch { $false }"
            )

            # Check if the built-in Administrator account has a unique password (LAPS indicator)
            # If no LAPS: check if local admin account is disabled (compensating control)
            admin_disabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue).Enabled -eq $false"
            )

            has_laps = (
                laps_modern.strip().lower() == "true" or
                laps_legacy.strip() == "1" or
                laps_schema.strip().lower() == "true"
            )
            admin_is_disabled = admin_disabled.strip().lower() == "true"

            evidence = {
                "windows_laps_modern": laps_modern.strip(),
                "laps_legacy_gpo": laps_legacy.strip(),
                "laps_ad_schema": laps_schema.strip(),
                "builtin_admin_disabled": admin_is_disabled,
            }

            if has_laps:
                return self._pass(
                    target,
                    details="LAPS is configured — local Administrator account has a unique, rotated password.",
                    evidence=evidence,
                )
            elif admin_is_disabled:
                return self._fail(
                    target,
                    details="Built-in Administrator account is disabled (partial control) but LAPS is not deployed. If local admin is needed, all machines use the same password.",
                    remediation=(
                        "Deploy Windows LAPS (available in Windows 11 22H2+ and Server 2019+ via Windows Update): "
                        "Enable-LapsADPasswordEncryption or use the legacy LAPS GPO CSE. "
                        "LAPS rotates the local administrator password on each machine uniquely. "
                        "PowerShell: Install-Module -Name LAPS; Set-LapsADComputerSelfPermission"
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No LAPS deployment detected AND built-in Administrator account is enabled. Credential reuse attack can compromise entire domain from one endpoint breach.",
                    remediation=(
                        "Deploy LAPS immediately — this is a critical control: "
                        "1. Modern Windows LAPS: enable via Intune or GPO (Windows Server 2019+ DC required). "
                        "2. Legacy LAPS: download from Microsoft, extend AD schema, deploy via GPO. "
                        "3. Immediate compensating control: disable built-in Administrator and create a unique "
                        "   named local admin account per machine using RMM/Ansible/GPO startup script. "
                        "Without LAPS: a Pass-the-Hash attack from one PC compromises every PC."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable Windows LAPS via PowerShell (requires Domain Admin):\n"
                        "# 1. Update AD schema:\n"
                        "# Update-LapsADSchema\n"
                        "# 2. Grant computer objects permission to update their own password:\n"
                        "# Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=domain,DC=com'\n"
                        "# 3. Enable via GPO:\n"
                        "# Computer Config > Admin Templates > System > LAPS > Enable LAPS\n"
                        "# 4. Read a password (verification):\n"
                        "# Get-LapsADPassword -Identity COMPUTERNAME -AsPlainText"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class PrivilegedAccountSeparationCheck(BaseCheck):
    """
    PAM-02: Verify privileged accounts are separate from daily-use accounts.
    Domain Admins should not use their admin accounts for email, browsing, or daily work.
    Privileged Access Workstations (PAWs) best practice.
    """
    check_id = "PAM-02"
    check_name = "Privileged Account Separation"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ldap:
                return self._na(target, "LDAP connection required for privileged account check.")

            # Get Domain Admins and check if they have separate admin accounts
            domain_admins = context.ldap.get_group_members("Domain Admins")

            # Check for naming convention that suggests separate accounts (e.g., admin_jsmith vs jsmith)
            admin_names = [u.get("cn", [""])[0] for u in domain_admins if u.get("cn")]

            # Check if any DA accounts have mailboxes (admin accounts shouldn't have email)
            admin_with_email = context.winrm.run_ps(
                target.hostname,
                r"Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | "
                r"Get-ADUser -Properties mail,EmailAddress -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.mail -ne $null -or $_.EmailAddress -ne $null } | "
                r"Select-Object SamAccountName | ConvertTo-Json"
            )

            import json as _json
            email_admins = []
            if admin_with_email.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(admin_with_email)
                    email_admins = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            # Check for tiered naming convention (admin_ prefix = good practice)
            tiered_naming = any(
                name.lower().startswith("adm_") or name.lower().startswith("a-")
                or name.lower().startswith("admin-") or name.lower().startswith("da-")
                for name in admin_names
            )

            evidence = {
                "domain_admin_count": len(admin_names),
                "admins_with_mailboxes": len(email_admins),
                "admin_names_sample": admin_names[:5],
                "tiered_naming_detected": tiered_naming,
            }

            if not email_admins and (tiered_naming or len(admin_names) <= 2):
                return self._pass(
                    target,
                    details=f"{len(admin_names)} Domain Admin accounts. No admin accounts with email detected — good account separation.",
                    evidence=evidence,
                )
            elif email_admins:
                return self._fail(
                    target,
                    details=f"{len(email_admins)} Domain Admin accounts have email addresses configured: {', '.join([a.get('SamAccountName','?') for a in email_admins[:3]])}. Admins should not use admin accounts for email.",
                    remediation=(
                        "Implement Tier 0/Tier 1/Tier 2 account model: "
                        "1. Domain Admins should have a separate 'adm_' prefixed account with NO mailbox. "
                        "2. Daily work (email, browsing) uses regular user account. "
                        "3. Admin tasks use the admin account only from a Privileged Access Workstation (PAW). "
                        "Admins with email on DA accounts are phishing targets — one phishing click = domain compromise."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"{len(admin_names)} Domain Admin accounts without clear naming separation. Consider tiered admin account naming (adm_, a-) to distinguish privileged from daily accounts.",
                    remediation=(
                        "Create separate admin accounts with naming convention (adm_username): "
                        "1. Create new DA accounts: New-ADUser -Name 'adm_jsmith' -SamAccountName 'adm_jsmith'. "
                        "2. Remove daily accounts from Domain Admins group. "
                        "3. Never add admin accounts to any email-capable group. "
                        "This separation limits blast radius when a daily account is phished."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class StalePrivilegedAccountsCheck(BaseCheck):
    """
    PAM-03: Verify no stale (inactive 30+ days) accounts exist in privileged groups.
    Stale admin accounts are a primary attack vector — terminated employees or unused service accounts
    with Domain Admin rights that were never revoked.
    """
    check_id = "PAM-03"
    check_name = "Stale Privileged Accounts"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 10.0

    STALE_DAYS = 30

    def run(self, target: Target, context) -> Finding:
        try:
            # Find enabled DA accounts that haven't logged in within 30 days
            stale_admins = context.winrm.run_ps(
                target.hostname,
                rf"$cutoff = (Get-Date).AddDays(-{self.STALE_DAYS}); "
                r"Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | "
                r"Get-ADUser -Properties LastLogonDate,Enabled -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Enabled -eq $true -and "
                r"  ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff) } | "
                r"Select-Object SamAccountName, LastLogonDate, Enabled | ConvertTo-Json"
            )

            # Also check Enterprise Admins
            stale_enterprise = context.winrm.run_ps(
                target.hostname,
                rf"$cutoff = (Get-Date).AddDays(-{self.STALE_DAYS}); "
                r"Get-ADGroupMember 'Enterprise Admins' -ErrorAction SilentlyContinue | "
                r"Get-ADUser -Properties LastLogonDate,Enabled -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Enabled -eq $true -and "
                r"  ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff) } | "
                r"Select-Object SamAccountName, LastLogonDate | ConvertTo-Json"
            )

            import json as _json
            stale_da = []
            if stale_admins.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(stale_admins)
                    stale_da = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            stale_ea = []
            if stale_enterprise.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(stale_enterprise)
                    stale_ea = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            evidence = {
                "stale_domain_admins": [a.get("SamAccountName") for a in stale_da][:10],
                "stale_enterprise_admins": [a.get("SamAccountName") for a in stale_ea][:5],
                "stale_da_count": len(stale_da),
                "stale_ea_count": len(stale_ea),
                "stale_threshold_days": self.STALE_DAYS,
            }

            if not stale_da and not stale_ea:
                return self._pass(
                    target,
                    details=f"No stale privileged accounts (all Domain/Enterprise Admins logged in within {self.STALE_DAYS} days).",
                    evidence=evidence,
                )
            else:
                total = len(stale_da) + len(stale_ea)
                names = [a.get("SamAccountName", "?") for a in (stale_da + stale_ea)[:5]]
                return self._fail(
                    target,
                    details=f"{total} stale privileged account(s) found (no login in {self.STALE_DAYS}+ days): {', '.join(names)}. These accounts may belong to terminated employees.",
                    remediation=(
                        "Review and remediate stale privileged accounts immediately: "
                        "1. Verify each account with HR — disable accounts for terminated employees. "
                        "2. Remove from Domain Admins group if not actively needed. "
                        "3. Implement automated stale account detection (run weekly). "
                        "4. Set 30-day automated disable for accounts not in DA with no recent logon. "
                        "PowerShell to disable: Disable-ADAccount -Identity <samaccountname>"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable all stale Domain Admin accounts (review before running!):\n"
                        f"$cutoff = (Get-Date).AddDays(-{self.STALE_DAYS})\n"
                        "Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties LastLogonDate,Enabled | \n"
                        "Where-Object { $_.Enabled -eq $true -and ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff) } | \n"
                        "ForEach-Object { \n"
                        "  Write-Host \"Disabling: $($_.SamAccountName) (Last login: $($_.LastLogonDate))\"\n"
                        "  # Disable-ADAccount -Identity $_.SamAccountName  # Uncomment to execute\n"
                        "}"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
