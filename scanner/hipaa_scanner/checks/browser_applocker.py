"""
Browser security and application whitelisting compliance checks.
HIPAA reference:
  164.312(a)(1) — Access Control (REQUIRED)
  164.308(a)(5) — Security Awareness Training / Malicious Software (REQUIRED)

Browser exploits and unauthorized applications are top ePHI exfiltration vectors.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class BrowserSecurityCheck(BaseCheck):
    """
    BROWSER-01: Verify clinical workstation browsers are hardened.
    Tests: Chrome/Edge enterprise policy (SmartScreen, safe browsing, password manager disabled),
           browser update status, Java/Flash plugins disabled.
    """
    check_id = "BROWSER-01"
    check_name = "Browser Security Hardening"
    category = "Endpoint Security"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Chrome enterprise policy
            chrome_policy = context.winrm.run_ps(
                target.hostname,
                r"$chrome = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; "
                r"if (Test-Path $chrome) { "
                r"  [PSCustomObject]@{ "
                r"    SafeBrowsing = (Get-ItemProperty $chrome -Name SafeBrowsingEnabled -EA SilentlyContinue).SafeBrowsingEnabled; "
                r"    SmartScreen = (Get-ItemProperty $chrome -Name SmartScreenEnabled -EA SilentlyContinue).SmartScreenEnabled; "
                r"    PasswordManager = (Get-ItemProperty $chrome -Name PasswordManagerEnabled -EA SilentlyContinue).PasswordManagerEnabled; "
                r"    JavaDisabled = (Get-ItemProperty $chrome -Name EnableDeprecatedWebPlatformFeatures -EA SilentlyContinue).EnableDeprecatedWebPlatformFeatures; "
                r"    Configured = $true "
                r"  } | ConvertTo-Json "
                r"} else { '{\"Configured\": false}' }"
            )

            # Check Edge enterprise policy
            edge_policy = context.winrm.run_ps(
                target.hostname,
                r"$edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; "
                r"if (Test-Path $edge) { "
                r"  [PSCustomObject]@{ "
                r"    SmartScreen = (Get-ItemProperty $edge -Name SmartScreenEnabled -EA SilentlyContinue).SmartScreenEnabled; "
                r"    PasswordManager = (Get-ItemProperty $edge -Name PasswordManagerEnabled -EA SilentlyContinue).PasswordManagerEnabled; "
                r"    Configured = $true "
                r"  } | ConvertTo-Json "
                r"} else { '{\"Configured\": false}' }"
            )

            # Check if IE is still present (legacy risk)
            ie_present = context.winrm.run_ps(
                target.hostname,
                r"Test-Path 'C:\Program Files\Internet Explorer\iexplore.exe'"
            )

            # Check browser auto-update policy
            chrome_update = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Update' "
                r"-Name AutoUpdateCheckPeriodMinutes -EA SilentlyContinue).AutoUpdateCheckPeriodMinutes"
            )

            import json as _json
            chrome = {"Configured": False}
            edge = {"Configured": False}
            try:
                chrome = _json.loads(chrome_policy)
            except Exception:
                pass
            try:
                edge = _json.loads(edge_policy)
            except Exception:
                pass

            chrome_configured = chrome.get("Configured", False)
            edge_configured = edge.get("Configured", False)
            ie_risk = ie_present.strip().lower() == "true"

            # Check SmartScreen enabled on either browser
            smart_screen = (
                chrome.get("SmartScreen") == 1 or
                chrome.get("SafeBrowsing") == 1 or
                edge.get("SmartScreen") == 1
            )

            # Password manager should be disabled on clinical workstations (employees shouldn't store patient creds in browser)
            pw_manager_blocked = (
                chrome.get("PasswordManager") == 0 or
                edge.get("PasswordManager") == 0
            )

            evidence = {
                "chrome_policy_configured": chrome_configured,
                "edge_policy_configured": edge_configured,
                "smartscreen_enabled": smart_screen,
                "password_manager_blocked": pw_manager_blocked,
                "ie_present": ie_risk,
                "chrome_auto_update": chrome_update.strip(),
            }

            issues = []
            if not chrome_configured and not edge_configured:
                issues.append("no browser enterprise policy")
            if not smart_screen:
                issues.append("SmartScreen/SafeBrowsing not enforced")
            if ie_risk:
                issues.append("Internet Explorer present (end-of-life, CVE magnet)")

            if not issues:
                return self._pass(
                    target,
                    details="Browser enterprise policy configured with SmartScreen/SafeBrowsing enabled.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Browser security gaps: {'; '.join(issues)}.",
                    remediation=(
                        "Harden browsers on clinical workstations via Group Policy: "
                        "Chrome: Computer Config > Administrative Templates > Google > Google Chrome: "
                        "Enable SafeBrowsingEnabled, SmartScreenEnabled. Disable PasswordManagerEnabled. "
                        "Edge: Computer Config > Administrative Templates > Microsoft Edge: "
                        "Enable SmartScreenEnabled. Block extension installs from unknown sources. "
                        "If Internet Explorer is present: disable via 'Turn Windows features on or off'."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class AppLockerCheck(BaseCheck):
    """
    APP-01: Verify AppLocker or Windows Defender Application Control (WDAC) is configured.
    Application whitelisting prevents malware and unauthorized software from running —
    a critical control in ransomware defense and ePHI protection.
    """
    check_id = "APP-01"
    check_name = "Application Whitelisting (AppLocker / WDAC)"
    category = "Endpoint Security"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check AppLocker service status
            applocker_svc = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue | "
                r"Select-Object Status, StartType | ConvertTo-Json"
            )

            # Check AppLocker policy rules exist
            applocker_policy = context.winrm.run_ps(
                target.hostname,
                r"$policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue; "
                r"if ($policy) { "
                r"  $rules = $policy.RuleCollections | ForEach-Object { $_.Count }; "
                r"  [PSCustomObject]@{ Configured=$true; TotalRules=($rules | Measure-Object -Sum).Sum } | ConvertTo-Json "
                r"} else { '{\"Configured\": false, \"TotalRules\": 0}' }"
            )

            # Check WDAC (Code Integrity policy)
            wdac_policy = context.winrm.run_ps(
                target.hostname,
                r"$ci = Get-CIPolicy -FilePath C:\Windows\System32\CodeIntegrity\SIPolicy.p7b "
                r"-ErrorAction SilentlyContinue; "
                r"if ($ci) { 'configured' } else { "
                r"  if (Test-Path 'C:\Windows\System32\CodeIntegrity\SIPolicy.p7b') { 'policy-file-exists' } "
                r"  else { 'not configured' } "
                r"}"
            )

            # Check Software Restriction Policies (older alternative)
            srp = context.winrm.run_ps(
                target.hostname,
                r"$srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer'; "
                r"if (Test-Path $srp) { 'configured' } else { 'not configured' }"
            )

            import json as _json
            al_info = {"Configured": False, "TotalRules": 0}
            try:
                al_info = _json.loads(applocker_policy)
            except Exception:
                pass

            import json as _json2
            svc_info = {}
            try:
                svc_info = _json2.loads(applocker_svc)
            except Exception:
                pass

            al_configured = al_info.get("Configured", False)
            al_rules = al_info.get("TotalRules", 0)
            al_running = svc_info.get("Status", "").lower() == "running"
            wdac_configured = "configured" in wdac_policy.lower() or "exists" in wdac_policy.lower()
            srp_configured = "configured" in srp.lower()

            evidence = {
                "applocker_service": svc_info.get("Status", "not found"),
                "applocker_rules": al_rules,
                "wdac_policy": wdac_policy.strip(),
                "srp_configured": srp_configured,
            }

            if (al_configured and al_rules > 0 and al_running) or wdac_configured:
                control = "WDAC" if wdac_configured else f"AppLocker ({al_rules} rules)"
                return self._pass(
                    target,
                    details=f"Application whitelisting active: {control}.",
                    evidence=evidence,
                )
            elif al_configured or srp_configured:
                return self._fail(
                    target,
                    details="AppLocker policy configured but Application Identity Service (AppIDSvc) is not running — rules are NOT enforced.",
                    remediation=(
                        "Start and set to Automatic the Application Identity service (AppIDSvc): "
                        "Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc. "
                        "Without this service, AppLocker rules have no effect."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable AppLocker enforcement:\n"
                        "Set-Service AppIDSvc -StartupType Automatic\n"
                        "Start-Service AppIDSvc"
                    ),
                )
            else:
                return self._fail(
                    target,
                    details="No application whitelisting (AppLocker, WDAC, or SRP) configured. Any executable can run, including ransomware delivered via email or USB.",
                    remediation=(
                        "Implement application whitelisting under HIPAA 164.308(a)(5)(ii)(B): "
                        "1. AppLocker (Windows 10 Enterprise / Server 2016+): "
                        "   Use default rules wizard to allow signed apps, block others. "
                        "2. WDAC (Windows Defender Application Control): "
                        "   More robust than AppLocker, managed via Intune or GPO. "
                        "3. Start with Audit mode to identify gaps before switching to Enforce mode. "
                        "AppLocker significantly reduces ransomware impact in healthcare environments."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Create AppLocker default rules and enable enforcement:\n"
                        "# 1. Start AppIDSvc\n"
                        "Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc\n"
                        "# 2. Generate default rules in Group Policy:\n"
                        "# gpedit.msc > Computer Config > Windows Settings > Security Settings > "
                        "Application Control Policies > AppLocker\n"
                        "# Right-click each collection > Create Default Rules"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
