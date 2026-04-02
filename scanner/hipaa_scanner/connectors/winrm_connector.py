"""
WinRM connector — executes PowerShell on remote Windows machines.
Uses pywinrm library (WS-Management over HTTP/HTTPS).
"""

from __future__ import annotations
from typing import Optional
import winrm


class WinRMConnector:
    """
    Manages WinRM connections to remote Windows machines.
    One instance per scanner session (shared across checks for a target).
    """

    def __init__(self, username: str, password: str, domain: Optional[str] = None,
                 transport: str = "ntlm", ssl: bool = False):
        self.username = f"{domain}\\{username}" if domain else username
        self.password = password
        self.transport = transport
        self.ssl = ssl
        self.port = 5986 if ssl else 5985

    def run_ps(self, hostname: str, script: str) -> str:
        """
        Execute a PowerShell script on the remote host.
        Returns stdout as string. Raises on error.
        """
        protocol = winrm.Protocol(
            endpoint=f"{'https' if self.ssl else 'http'}://{hostname}:{self.port}/wsman",
            transport=self.transport,
            username=self.username,
            password=self.password,
            server_cert_validation="ignore",  # Self-signed certs common in SMB environments
        )
        shell_id = protocol.open_shell()
        try:
            cmd = f'powershell -NoProfile -NonInteractive -Command "{script.replace(chr(34), chr(92)+chr(34))}"'
            command_id = protocol.run_command(shell_id, "powershell", [
                "-NoProfile", "-NonInteractive", "-Command", script
            ])
            stdout, stderr, rc = protocol.get_command_output(shell_id, command_id)
            protocol.cleanup_command(shell_id, command_id)
            if rc != 0:
                raise RuntimeError(f"PowerShell error (rc={rc}): {stderr.decode('utf-8', errors='replace').strip()}")
            return stdout.decode("utf-8", errors="replace").strip()
        finally:
            protocol.close_shell(shell_id)

    def test_connection(self, hostname: str) -> bool:
        """Verify WinRM connectivity to a host."""
        try:
            result = self.run_ps(hostname, "echo 'ok'")
            return "ok" in result
        except Exception:
            return False
