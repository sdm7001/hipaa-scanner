"""Module 6: Antivirus / EDR (HIPAA 164.308(a)(5)(ii)(B))"""

from .base import BaseCheck
from ..models import Severity, Target, TargetRole
from datetime import datetime, timedelta, timezone


class AntivirusPresentCheck(BaseCheck):
    check_id = "AV-01"
    check_name = "Antivirus Software Installed"
    category = "Antivirus/EDR"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 10.0

    def run(self, target, context):
        try:
            # Query Windows Security Center (WMI root/SecurityCenter2)
            result = context.winrm.run_ps(
                target.hostname,
                """
                $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
                if ($av) {
                    ($av | Select-Object displayName,productState | ConvertTo-Json -Compress)
                } else { "none" }
                """.strip()
            )
            if not result or result.strip() == "none":
                return self._fail(target,
                    "No antivirus product detected via Windows Security Center.",
                    remediation="Install a reputable antivirus/EDR solution. Recommended: Microsoft Defender (included with Windows), CrowdStrike, SentinelOne, or Malwarebytes for Business.",
                    evidence={"antivirus_products": []})

            import json
            raw = result.strip()
            products = json.loads(raw) if raw.startswith("[") or raw.startswith("{") else []
            if isinstance(products, dict):
                products = [products]

            return self._pass(target,
                f"Antivirus detected: {', '.join(p.get('displayName', 'Unknown') for p in products)}",
                evidence={"antivirus_products": [p.get("displayName") for p in products]})
        except Exception as e:
            return self._error(target, str(e))


class AntivirusUpdatedCheck(BaseCheck):
    check_id = "AV-02"
    check_name = "Antivirus Definitions Up to Date"
    category = "Antivirus/EDR"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 7.0

    MAX_DEFINITION_AGE_DAYS = 3

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($defender) {
                    $age = (Get-Date) - $defender.AntivirusSignatureLastUpdated
                    "$([int]$age.TotalDays)|$($defender.AntivirusSignatureLastUpdated)"
                } else { "no_defender" }
                """.strip()
            )

            if not result or result.strip() == "no_defender":
                return self._na(target, "Microsoft Defender not active — verify definitions via installed AV console.")

            parts = result.strip().split("|")
            age_days = int(parts[0]) if parts[0].isdigit() else 999

            if age_days <= self.MAX_DEFINITION_AGE_DAYS:
                return self._pass(target,
                    f"Antivirus definitions are current ({age_days} day(s) old).",
                    evidence={"definition_age_days": age_days})
            else:
                return self._fail(target,
                    f"Antivirus definitions are {age_days} days old (max recommended: {self.MAX_DEFINITION_AGE_DAYS} days).",
                    remediation="Update antivirus definitions immediately and verify automatic updates are configured.",
                    remediation_script="Update-MpSignature",
                    evidence={"definition_age_days": age_days})
        except Exception as e:
            return self._error(target, str(e))


class AntivirusRunningCheck(BaseCheck):
    check_id = "AV-03"
    check_name = "Antivirus Real-Time Protection Active"
    category = "Antivirus/EDR"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 8.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-MpComputerStatus -ErrorAction SilentlyContinue)?.RealTimeProtectionEnabled"
            )
            enabled = result.strip().lower() == "true" if result.strip() else None

            if enabled is None:
                return self._na(target, "Microsoft Defender not available — verify via installed AV console.")
            elif enabled:
                return self._pass(target, "Real-time antivirus protection is active.")
            else:
                return self._fail(target,
                    "Real-time antivirus protection is disabled.",
                    remediation="Enable real-time protection in Windows Security or your AV management console.",
                    remediation_script="Set-MpPreference -DisableRealtimeMonitoring $false",
                    evidence={"realtime_protection": False})
        except Exception as e:
            return self._error(target, str(e))
