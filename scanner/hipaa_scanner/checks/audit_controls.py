"""Module 3: Audit Controls (HIPAA 45 CFR 164.312(b))"""

from .base import BaseCheck
from ..models import Severity, Target, TargetRole


class AuditPolicyLogonCheck(BaseCheck):
    check_id = "AU-01"
    check_name = "Audit Policy — Logon Events"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 6.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "auditpol /get /subcategory:'Logon' /r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'"
            )
            setting = (result or "").strip().lower()
            if "success and failure" in setting or "success" in setting:
                return self._pass(target, f"Logon auditing is enabled: {setting}.",
                    evidence={"logon_audit_setting": setting})
            else:
                return self._fail(target,
                    f"Logon auditing setting '{setting}' is insufficient. Success and Failure events must be logged.",
                    remediation="Enable logon auditing for Success and Failure events via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy.",
                    remediation_script="auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
                    evidence={"logon_audit_setting": setting})
        except Exception as e:
            return self._error(target, str(e))


class AuditPolicyAccountMgmtCheck(BaseCheck):
    check_id = "AU-02"
    check_name = "Audit Policy — Account Management"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.DOMAIN_CONTROLLER, TargetRole.SERVER]
    points = 5.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "auditpol /get /subcategory:'User Account Management' /r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'"
            )
            setting = (result or "").strip().lower()
            if "success and failure" in setting or "success" in setting:
                return self._pass(target, f"Account management auditing enabled: {setting}.")
            else:
                return self._fail(target,
                    "Account management events are not being audited.",
                    remediation="Enable account management auditing for Success and Failure.",
                    remediation_script="auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable",
                    evidence={"account_mgmt_audit": setting})
        except Exception as e:
            return self._error(target, str(e))


class EventLogSizeCheck(BaseCheck):
    check_id = "AU-03"
    check_name = "Security Event Log Size"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 3.0

    MIN_SIZE_KB = 204_800  # 200 MB

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-WinEvent -ListLog Security).MaximumSizeInBytes"
            )
            size_bytes = int(result.strip()) if result.strip().isdigit() else 0
            size_kb = size_bytes // 1024
            size_mb = size_kb // 1024

            if size_kb >= self.MIN_SIZE_KB:
                return self._pass(target, f"Security event log maximum size is {size_mb} MB.",
                    evidence={"security_log_max_size_bytes": size_bytes})
            else:
                return self._fail(target,
                    f"Security event log max size is {size_mb} MB (recommended: {self.MIN_SIZE_KB // 1024} MB+).",
                    remediation="Increase security event log size to at least 200 MB via Group Policy.",
                    remediation_script=f"wevtutil sl Security /ms:{self.MIN_SIZE_KB * 1024}",
                    evidence={"security_log_max_size_bytes": size_bytes})
        except Exception as e:
            return self._error(target, str(e))


class AuditLogRetentionCheck(BaseCheck):
    check_id = "AU-04"
    check_name = "Audit Log Retention Policy"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 4.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-WinEvent -ListLog Security).LogMode"
            )
            mode = (result or "").strip()
            # "Circular" means old events are overwritten — not HIPAA-compliant
            # "Retain" or "AutoBackup" is better
            if mode.lower() in ("retain", "autobackup"):
                return self._pass(target, f"Security event log retention mode is '{mode}'.",
                    evidence={"log_retention_mode": mode})
            else:
                return self._fail(target,
                    f"Security event log mode is '{mode}' — events may be overwritten before being archived.",
                    remediation="Configure log forwarding (Windows Event Forwarding or SIEM) to preserve logs for 6+ years as required by HIPAA. Alternatively set log mode to 'AutoBackup'.",
                    evidence={"log_retention_mode": mode})
        except Exception as e:
            return self._error(target, str(e))
