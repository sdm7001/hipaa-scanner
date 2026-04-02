"""
Module 1: Access Controls (HIPAA 45 CFR 164.312(a))
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Severity, Target, TargetRole, Finding


class PasswordMinLengthCheck(BaseCheck):
    check_id = "AC-01"
    check_name = "Password Policy — Minimum Length"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 10.0

    MINIMUM_LENGTH = 12

    def run(self, target: Target, context) -> Finding:
        try:
            if context.environment_type == "active_directory":
                result = context.ldap.get_password_policy()
                min_len = result.get("minPwdLength", 0)
            else:
                result = context.winrm.run_ps(
                    target.hostname,
                    "(net accounts | Select-String 'Minimum password length').ToString().Trim()"
                )
                # Parse "Minimum password length:   7"
                min_len = int(result.strip().split()[-1]) if result.strip() else 0

            if min_len >= self.MINIMUM_LENGTH:
                return self._pass(target,
                    f"Minimum password length is {min_len} characters (required: {self.MINIMUM_LENGTH}+).",
                    evidence={"min_password_length": min_len})
            else:
                return self._fail(target,
                    f"Minimum password length is {min_len} characters (required: {self.MINIMUM_LENGTH}+).",
                    remediation=f"Increase minimum password length to {self.MINIMUM_LENGTH} or more.",
                    remediation_script=f"Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDOMAIN -MinPasswordLength {self.MINIMUM_LENGTH}",
                    evidence={"min_password_length": min_len, "required": self.MINIMUM_LENGTH})
        except Exception as e:
            return self._error(target, str(e))


class PasswordComplexityCheck(BaseCheck):
    check_id = "AC-02"
    check_name = "Password Policy — Complexity Requirements"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            if context.environment_type == "active_directory":
                result = context.ldap.get_password_policy()
                complexity = result.get("pwdProperties", 0)
                enabled = bool(complexity & 1)  # bit 0 = complexity enabled
            else:
                result = context.winrm.run_ps(
                    target.hostname,
                    "(net accounts | Select-String 'Password requirements').ToString().Trim()"
                )
                enabled = "yes" in result.lower() if result else False

            if enabled:
                return self._pass(target, "Password complexity requirements are enabled.")
            else:
                return self._fail(target,
                    "Password complexity requirements are not enabled.",
                    remediation="Enable 'Password must meet complexity requirements' in Group Policy or local security policy.",
                    remediation_script="secedit /export /cfg C:\\temp\\sec.cfg && (Edit file) && secedit /configure /db secedit.sdb /cfg C:\\temp\\sec.cfg",
                    evidence={"complexity_enabled": False})
        except Exception as e:
            return self._error(target, str(e))


class PasswordMaxAgeCheck(BaseCheck):
    check_id = "AC-03"
    check_name = "Password Policy — Maximum Age"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    points = 4.0

    MAX_AGE_DAYS = 90

    def run(self, target: Target, context) -> Finding:
        try:
            if context.environment_type == "active_directory":
                result = context.ldap.get_password_policy()
                # AD stores maxPwdAge as negative 100-nanosecond intervals
                max_age_raw = abs(int(result.get("maxPwdAge", 0)))
                max_age_days = max_age_raw // (10_000_000 * 86400) if max_age_raw > 0 else 0
            else:
                result = context.winrm.run_ps(
                    target.hostname,
                    "(net accounts | Select-String 'Maximum password age').ToString().Trim()"
                )
                max_age_days = int(result.strip().split()[-1]) if result.strip() else 999

            if 0 < max_age_days <= self.MAX_AGE_DAYS:
                return self._pass(target, f"Password maximum age is {max_age_days} days.",
                    evidence={"max_password_age_days": max_age_days})
            elif max_age_days == 0:
                return self._fail(target,
                    "Passwords are set to never expire.",
                    remediation=f"Set maximum password age to {self.MAX_AGE_DAYS} days or fewer.",
                    remediation_script=f"Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDOMAIN -MaxPasswordAge {self.MAX_AGE_DAYS}.00:00:00",
                    evidence={"max_password_age_days": "never"})
            else:
                return self._fail(target,
                    f"Password maximum age is {max_age_days} days (required: <= {self.MAX_AGE_DAYS}).",
                    remediation=f"Reduce maximum password age to {self.MAX_AGE_DAYS} days or fewer.",
                    evidence={"max_password_age_days": max_age_days, "required_max": self.MAX_AGE_DAYS})
        except Exception as e:
            return self._error(target, str(e))


class AccountLockoutCheck(BaseCheck):
    check_id = "AC-04"
    check_name = "Account Lockout Policy"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 7.0

    MAX_ATTEMPTS = 5

    def run(self, target: Target, context) -> Finding:
        try:
            if context.environment_type == "active_directory":
                result = context.ldap.get_password_policy()
                lockout_threshold = int(result.get("lockoutThreshold", 0))
            else:
                result = context.winrm.run_ps(
                    target.hostname,
                    "(net accounts | Select-String 'Lockout threshold').ToString().Trim()"
                )
                val = result.strip().split()[-1] if result.strip() else "Never"
                lockout_threshold = 0 if val.lower() == "never" else int(val)

            if 0 < lockout_threshold <= self.MAX_ATTEMPTS:
                return self._pass(target,
                    f"Account lockout threshold is {lockout_threshold} attempts.",
                    evidence={"lockout_threshold": lockout_threshold})
            elif lockout_threshold == 0:
                return self._fail(target,
                    "Account lockout is not configured (accounts will never lock).",
                    remediation=f"Set account lockout threshold to {self.MAX_ATTEMPTS} or fewer invalid attempts.",
                    remediation_script=f"Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDOMAIN -LockoutThreshold {self.MAX_ATTEMPTS}",
                    evidence={"lockout_threshold": "disabled"})
            else:
                return self._fail(target,
                    f"Account lockout threshold is {lockout_threshold} (should be <= {self.MAX_ATTEMPTS}).",
                    remediation=f"Reduce lockout threshold to {self.MAX_ATTEMPTS} or fewer.",
                    evidence={"lockout_threshold": lockout_threshold})
        except Exception as e:
            return self._error(target, str(e))


class ScreenLockTimeoutCheck(BaseCheck):
    check_id = "AC-07"
    check_name = "Automatic Screen Lock Timeout"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(iii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 6.0

    MAX_TIMEOUT_SECONDS = 900  # 15 minutes

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $timeout = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveTimeOut' -ErrorAction SilentlyContinue)?.ScreenSaveTimeOut
                $secured = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue)?.ScreenSaverIsSecure
                "$timeout|$secured"
                """.strip()
            )
            parts = (result or "").strip().split("|")
            timeout = int(parts[0]) if parts[0].isdigit() else 0
            secured = parts[1].strip() == "1" if len(parts) > 1 else False

            if 0 < timeout <= self.MAX_TIMEOUT_SECONDS and secured:
                return self._pass(target,
                    f"Screen lock timeout is {timeout // 60} minutes and is secured.",
                    evidence={"timeout_seconds": timeout, "secured": secured})
            else:
                details = []
                if timeout == 0:
                    details.append("Screen saver is not configured")
                elif timeout > self.MAX_TIMEOUT_SECONDS:
                    details.append(f"Screen lock timeout is {timeout // 60} minutes (max: {self.MAX_TIMEOUT_SECONDS // 60})")
                if not secured:
                    details.append("Screen saver does not require password on resume")

                return self._fail(target,
                    ". ".join(details) + ".",
                    remediation="Set screen saver timeout to 15 minutes or less with password-on-resume via Group Policy: Computer Configuration > Policies > Administrative Templates > Control Panel > Personalization.",
                    evidence={"timeout_seconds": timeout, "secured": secured})
        except Exception as e:
            return self._error(target, str(e))


class InactiveAccountsCheck(BaseCheck):
    check_id = "AC-09"
    check_name = "Inactive User Accounts"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    points = 5.0

    INACTIVE_DAYS = 90

    def run(self, target: Target, context) -> Finding:
        try:
            if context.environment_type != "active_directory":
                return self._na(target, "Inactive account check requires Active Directory.")

            inactive = context.ldap.get_inactive_users(days=self.INACTIVE_DAYS)
            count = len(inactive)

            if count == 0:
                return self._pass(target,
                    f"No enabled accounts inactive for more than {self.INACTIVE_DAYS} days.",
                    evidence={"inactive_account_count": 0})
            else:
                sample = inactive[:5]  # Show up to 5 examples
                return self._fail(target,
                    f"{count} enabled user account(s) have not logged in for {self.INACTIVE_DAYS}+ days.",
                    remediation="Review and disable inactive accounts. Consider implementing an automated 90-day inactivity policy.",
                    remediation_script=f"Search-ADAccount -AccountInactive -TimeSpan {self.INACTIVE_DAYS} -UsersOnly | Where-Object {{$_.Enabled -eq $true}} | Disable-ADAccount",
                    evidence={"inactive_account_count": count, "sample_accounts": sample})
        except Exception as e:
            return self._error(target, str(e))


class LocalAdminAuditCheck(BaseCheck):
    check_id = "AC-10"
    check_name = "Local Administrator Account Audit"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-LocalGroupMember -Group 'Administrators' | Where-Object {$_.ObjectClass -eq 'User'}).Name -join ','"
            )
            admins = [a.strip() for a in (result or "").strip().split(",") if a.strip()]
            # Filter out domain admins group (expected) and built-in Administrator
            local_admins = [a for a in admins if "\\" not in a or a.split("\\")[0] == target.hostname]

            evidence = {"local_administrators": admins, "count": len(admins)}

            if len(local_admins) <= 2:  # Built-in + 1 management account is acceptable
                return self._pass(target,
                    f"Local administrators group has {len(admins)} member(s): {', '.join(admins[:5])}.",
                    evidence=evidence)
            else:
                return self._fail(target,
                    f"Local administrators group has {len(admins)} members — review for least-privilege violations.",
                    remediation="Remove unnecessary local admin accounts. Only break-glass accounts and designated management accounts should have local admin rights.",
                    evidence=evidence)
        except Exception as e:
            return self._error(target, str(e))


class RdpSessionTimeoutCheck(BaseCheck):
    check_id = "AC-12"
    check_name = "RDP Session Idle Timeout"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(iii)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 3.0

    MAX_IDLE_MS = 900_000  # 15 minutes in milliseconds

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'MaxIdleTime' -ErrorAction SilentlyContinue)?.MaxIdleTime"
            )
            idle_ms = int(result.strip()) if result.strip().isdigit() else 0

            if 0 < idle_ms <= self.MAX_IDLE_MS:
                return self._pass(target,
                    f"RDP idle timeout is {idle_ms // 60000} minutes.",
                    evidence={"rdp_max_idle_ms": idle_ms})
            else:
                details = "RDP idle timeout is not configured." if idle_ms == 0 else f"RDP idle timeout is {idle_ms // 60000} minutes (max: 15)."
                return self._fail(target, details,
                    remediation="Set RDP idle session timeout to 15 minutes via Group Policy: Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Session Time Limits.",
                    evidence={"rdp_max_idle_ms": idle_ms})
        except Exception as e:
            return self._error(target, str(e))
