"""Module 4: Patch Management (HIPAA 164.308(a)(5)(ii)(B))"""

from .base import BaseCheck
from ..models import Severity, Target, TargetRole


class WindowsUpdateCheck(BaseCheck):
    check_id = "PM-01"
    check_name = "Windows Update — Critical Patches Installed"
    category = "Patch Management"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 10.0

    MAX_DAYS_SINCE_UPDATE = 30

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $missing = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                $critical = ($missing.Updates | Where-Object {$_.MsrcSeverity -eq 'Critical'}).Count
                $important = ($missing.Updates | Where-Object {$_.MsrcSeverity -eq 'Important'}).Count
                "$critical|$important"
                """.strip()
            )
            parts = (result or "0|0").strip().split("|")
            critical_missing = int(parts[0]) if parts[0].isdigit() else 0
            important_missing = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            if critical_missing == 0 and important_missing == 0:
                return self._pass(target, "No critical or important Windows updates are missing.")
            else:
                return self._fail(target,
                    f"{critical_missing} critical and {important_missing} important updates are missing.",
                    remediation="Install all pending critical and important Windows updates immediately. Enable automatic updates.",
                    remediation_script="Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot",
                    evidence={"critical_missing": critical_missing, "important_missing": important_missing})
        except Exception as e:
            return self._error(target, str(e))


class AutoUpdateEnabledCheck(BaseCheck):
    check_id = "PM-02"
    check_name = "Automatic Windows Updates Enabled"
    category = "Patch Management"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 6.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue)?.NoAutoUpdate"
            )
            # NoAutoUpdate = 1 means disabled, 0 or missing means enabled
            disabled = result.strip() == "1" if result.strip() else False

            if not disabled:
                return self._pass(target, "Automatic Windows Updates are enabled.")
            else:
                return self._fail(target,
                    "Automatic Windows Updates are disabled via Group Policy.",
                    remediation="Enable automatic Windows updates. At minimum, configure automatic download with scheduled install.",
                    evidence={"auto_update_disabled_by_gpo": True})
        except Exception as e:
            return self._error(target, str(e))


class PendingRebootCheck(BaseCheck):
    check_id = "PM-03"
    check_name = "Pending Reboot (Updates Awaiting Restart)"
    category = "Patch Management"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 2.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $pending = $false
                if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $pending = $true }
                if (Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations') { $pending = $true }
                $pending.ToString()
                """.strip()
            )
            pending = result.strip().lower() == "true"

            if not pending:
                return self._pass(target, "No pending reboot required.")
            else:
                return self._fail(target,
                    "System has pending updates that require a reboot.",
                    remediation="Schedule a maintenance window to reboot this machine and apply pending updates.",
                    evidence={"pending_reboot": True})
        except Exception as e:
            return self._error(target, str(e))
