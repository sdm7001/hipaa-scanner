"""
Centralized logging and SIEM compliance checks.
HIPAA reference: 164.312(b) — Audit Controls (REQUIRED)
NIST SP 800-66r2: Section 3.5 — Audit Controls

Healthcare organizations must maintain and review audit logs.
OCR audits routinely find missing or unreviewed logs as a compliance gap.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class CentralizedLoggingCheck(BaseCheck):
    """
    SIEM-01: Verify a centralized logging/SIEM solution is deployed.
    Tests: Windows Event Forwarding (WEF/WEC), Splunk Universal Forwarder, Elastic agent,
           Sentinel/Defender for Cloud, common SIEM agents.
    """
    check_id = "SIEM-01"
    check_name = "Centralized Logging / SIEM Deployment"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check 1: Windows Event Forwarding — subscription configured (WEC client)
            wef_configured = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' "
                r"-ErrorAction SilentlyContinue) -ne $null"
            )

            # Check 2: Splunk Universal Forwarder
            splunk = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'SplunkForwarder' -ErrorAction SilentlyContinue | "
                r"Select-Object -ExpandProperty Status"
            )

            # Check 3: Elastic Agent / Winlogbeat
            elastic = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'Elastic Agent','winlogbeat' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Check 4: Microsoft Sentinel / Defender for Cloud (Azure Monitor Agent)
            azure_monitor = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'AzureMonitorAgent','MicrosoftMonitoringAgent','HealthService' "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            # Check 5: Other SIEM agents
            other_siem = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'nxlog','ossec','wazuh','LogRhythm*','QRadar*','AlienVault*' "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Select-Object Name | ConvertTo-Json"
            )

            wef = wef_configured.strip().lower() == "true"
            has_splunk = "running" in splunk.strip().lower()
            elastic_count = int(elastic.strip()) if elastic.strip().isdigit() else 0
            azure_count = int(azure_monitor.strip()) if azure_monitor.strip().isdigit() else 0
            has_other = other_siem.strip() not in ("", "null", "[]")

            has_siem = wef or has_splunk or elastic_count > 0 or azure_count > 0 or has_other

            evidence = {
                "windows_event_forwarding": wef,
                "splunk_forwarder": has_splunk,
                "elastic_agent": elastic_count > 0,
                "azure_monitor_agent": azure_count > 0,
                "other_siem": has_other,
            }

            if has_siem:
                active = [
                    k for k, v in evidence.items() if v is True or v is not False and v
                ]
                return self._pass(
                    target,
                    details=f"Centralized logging configured: {', '.join(active)}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No centralized logging or SIEM agent detected. Security events are siloed on individual machines and cannot be correlated or reviewed centrally.",
                    remediation=(
                        "Implement centralized logging under HIPAA 164.312(b) Audit Controls: "
                        "1. Microsoft Sentinel — Azure-native SIEM, integrates with Defender. "
                        "2. Splunk (on-prem or cloud) with Universal Forwarder on each endpoint. "
                        "3. Elastic SIEM with Elastic Agent — open source, self-hosted option. "
                        "4. Windows Event Forwarding (WEF/WEC) — free, built-in Windows log centralization. "
                        "Minimum: configure Windows Event Collector on a central server and push security, "
                        "system, and application logs from all endpoints. "
                        "Log retention: minimum 6 years for HIPAA-related events."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Configure Windows Event Forwarding (WEF) subscription on source computers:\n"
                        "# 1. On the collector server, run: wecutil qc\n"
                        "# 2. Set Group Policy: Computer Config > Admin Templates > Windows Components >\n"
                        "#    Event Forwarding > Configure target Subscription Manager\n"
                        "#    Value: Server=http://COLLECTOR_SERVER:5985/wsman/SubscriptionManager/WEC\n"
                        "# 3. On collector: wecutil cs subscription.xml"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class LogRetentionPolicyCheck(BaseCheck):
    """
    SIEM-02: Verify security event logs are retained for minimum 6 years (HIPAA record retention).
    Tests: Windows Event Log maximum size, Splunk/SIEM retention configuration, archive policies.
    """
    check_id = "SIEM-02"
    check_name = "Security Log Retention Policy (6-Year HIPAA Requirement)"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 6.0

    # HIPAA requires 6 years (per 45 CFR 164.530(j)) — most state laws align or exceed this
    MIN_LOG_SIZE_MB = 1024  # 1GB minimum for local Security log — inadequate alone but indicates intent

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Security event log max size
            security_log_size = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' "
                r"-Name MaxSize -ErrorAction SilentlyContinue).MaxSize"
            )

            # Also check via GPO setting
            security_log_gpo = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' "
                r"-Name MaxSize -ErrorAction SilentlyContinue).MaxSize"
            )

            # Check log retention behavior (OverwriteAsNeeded vs Archive)
            retention_behavior = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' "
                r"-Name Retention -ErrorAction SilentlyContinue).Retention"
            )

            # Check for log archiving to file share or backup
            archive_path = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' "
                r"-Name AutoBackupLogFiles -ErrorAction SilentlyContinue).AutoBackupLogFiles"
            )

            # Parse log size (in bytes from registry)
            raw_size = security_log_gpo.strip() or security_log_size.strip()
            log_size_bytes = int(raw_size) if raw_size.isdigit() else 0
            log_size_mb = log_size_bytes // (1024 * 1024)

            # Retention: -1 or None = overwrite as needed (bad), 0 = never overwrite, positive = days
            ret_val = int(retention_behavior.strip()) if retention_behavior.strip().lstrip("-").isdigit() else None
            auto_archive = archive_path.strip() == "1"

            evidence = {
                "security_log_size_mb": log_size_mb,
                "retention_value": retention_behavior.strip(),
                "auto_archive_enabled": auto_archive,
                "raw_size_registry": raw_size,
            }

            if log_size_mb >= self.MIN_LOG_SIZE_MB and auto_archive:
                return self._pass(
                    target,
                    details=f"Security log configured at {log_size_mb}MB with auto-archive enabled.",
                    evidence=evidence,
                )
            elif log_size_mb >= self.MIN_LOG_SIZE_MB:
                return self._fail(
                    target,
                    details=f"Security log is {log_size_mb}MB (adequate size) but auto-archive is not configured. Logs will be overwritten and 6-year retention cannot be met locally.",
                    remediation=(
                        "Configure log archiving to a central log store: "
                        "Enable 'Archive the log when full, do not overwrite events' in Event Log policy, "
                        "or use Windows Event Forwarding to centralize logs with long-term retention. "
                        "HIPAA 164.530(j) requires records to be retained for 6 years."
                    ),
                    evidence=evidence,
                )
            else:
                size_display = f"{log_size_mb}MB" if log_size_mb else "default (20MB)"
                return self._fail(
                    target,
                    details=f"Security event log maximum size is {size_display} — too small for meaningful retention. Logs will be overwritten within hours on busy servers.",
                    remediation=(
                        "Increase Security log maximum size via Group Policy: "
                        "Computer Configuration > Windows Settings > Security Settings > "
                        "Event Log > Maximum security log size. "
                        "Set to minimum 1GB (1048576 KB) as a local buffer. "
                        "For 6-year retention, implement centralized log aggregation (see SIEM-01). "
                        "PowerShell: wevtutil sl Security /ms:1073741824"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Set Security log to 1GB and archive when full\n"
                        "wevtutil sl Security /ms:1073741824 /rt:false /ab:true\n"
                        "# Set via registry:\n"
                        "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security' "
                        "-Name MaxSize -Value 1073741824 -Type DWord"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
