"""Module 5: Network Security — Transmission Security (HIPAA 164.312(e)(1))"""

import socket
from .base import BaseCheck
from ..models import Severity, Target, TargetRole


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class OpenRdpPortCheck(BaseCheck):
    check_id = "NS-01"
    check_name = "RDP Port Exposed to Network"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 10.0

    def run(self, target, context):
        try:
            open_3389 = _port_open(target.ip_address, 3389)
            if not open_3389:
                return self._pass(target, "RDP port (3389) is not accessible from the scanner network.")
            else:
                return self._fail(target,
                    "RDP port (3389) is open and accessible. RDP should only be available via VPN or internal network.",
                    remediation="Block RDP (port 3389) at the perimeter firewall. Use VPN for remote access. Enable Windows Firewall rules to restrict RDP to specific management IPs.",
                    evidence={"port_3389_open": True})
        except Exception as e:
            return self._error(target, str(e))


class OpenTelnetPortCheck(BaseCheck):
    check_id = "NS-02"
    check_name = "Telnet Service Running"
    category = "Network Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 8.0

    def run(self, target, context):
        try:
            open_23 = _port_open(target.ip_address, 23)
            if not open_23:
                return self._pass(target, "Telnet port (23) is not open.")
            else:
                return self._fail(target,
                    "Telnet port (23) is open. Telnet transmits data in cleartext and must not be used.",
                    remediation="Disable and uninstall the Telnet service. Use SSH or PowerShell Remoting (WinRM with HTTPS) for remote management.",
                    remediation_script="Stop-Service TlntSvr -Force; Set-Service TlntSvr -StartupType Disabled",
                    evidence={"port_23_open": True})
        except Exception as e:
            return self._error(target, str(e))


class OpenFtpPortCheck(BaseCheck):
    check_id = "NS-03"
    check_name = "FTP Service Running"
    category = "Network Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    points = 7.0

    def run(self, target, context):
        try:
            open_21 = _port_open(target.ip_address, 21)
            if not open_21:
                return self._pass(target, "FTP port (21) is not open.")
            else:
                return self._fail(target,
                    "FTP port (21) is open. FTP transmits credentials and data in cleartext.",
                    remediation="Disable FTP. Use SFTP (SSH File Transfer Protocol) or FTPS for secure file transfers.",
                    evidence={"port_21_open": True})
        except Exception as e:
            return self._error(target, str(e))


class WindowsFirewallCheck(BaseCheck):
    check_id = "NS-04"
    check_name = "Windows Firewall Enabled"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 7.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $fw = Get-NetFirewallProfile -All | Select-Object Name,Enabled
                $fw | ForEach-Object { "$($_.Name):$($_.Enabled)" }
                """ .strip()
            )
            profiles = {}
            for line in (result or "").strip().splitlines():
                if ":" in line:
                    name, enabled = line.split(":", 1)
                    profiles[name.strip()] = enabled.strip().lower() == "true"

            disabled_profiles = [p for p, e in profiles.items() if not e]

            if not disabled_profiles:
                return self._pass(target, "Windows Firewall is enabled on all profiles (Domain, Private, Public).",
                    evidence={"firewall_profiles": profiles})
            else:
                return self._fail(target,
                    f"Windows Firewall is disabled on profile(s): {', '.join(disabled_profiles)}",
                    remediation="Enable Windows Firewall on all profiles.",
                    remediation_script="Set-NetFirewallProfile -All -Enabled True",
                    evidence={"disabled_profiles": disabled_profiles, "all_profiles": profiles})
        except Exception as e:
            return self._error(target, str(e))
