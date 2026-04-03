"""
SSH connector — executes commands on remote Linux/macOS/Unix machines.
Uses Paramiko for SSH sessions. Supports key-based and password auth.
"""

from __future__ import annotations
from typing import Optional
import paramiko
import socket


class SSHConnector:
    """
    Manages SSH connections to remote Linux/macOS machines.
    One instance per scanner session (shared across checks for a target).
    """

    def __init__(
        self,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: float = 10.0,
    ):
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._current_host: Optional[str] = None

    def _connect(self, hostname: str) -> None:
        """Establish SSH connection to host."""
        if self._client and self._current_host == hostname:
            return  # reuse existing connection

        self._disconnect()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": hostname,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "allow_agent": True,
            "look_for_keys": self.key_path is None,
        }

        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password

        client.connect(**connect_kwargs)
        self._client = client
        self._current_host = hostname

    def _disconnect(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._current_host = None

    def run_command(self, hostname: str, command: str, use_sudo: bool = False) -> str:
        """
        Execute a shell command on the remote host.
        Returns stdout as a string. Raises on non-zero exit code.
        """
        self._connect(hostname)
        assert self._client is not None

        if use_sudo and not command.startswith("sudo "):
            command = f"sudo -n {command}"

        stdin, stdout, stderr = self._client.exec_command(command, timeout=30)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()

        if rc != 0 and not out:
            raise RuntimeError(f"SSH command failed (rc={rc}): {err or command[:60]}")
        return out

    def run_command_silent(self, hostname: str, command: str) -> tuple[str, int]:
        """Run command and return (stdout, returncode) without raising on non-zero exit."""
        self._connect(hostname)
        assert self._client is not None

        stdin, stdout, stderr = self._client.exec_command(command, timeout=30)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        return out, rc

    def test_connection(self, hostname: str) -> bool:
        """Verify SSH connectivity to a host."""
        try:
            out = self.run_command(hostname, "echo ok")
            return "ok" in out
        except Exception:
            return False

    def get_os_info(self, hostname: str) -> dict:
        """Retrieve basic OS information from the remote host."""
        result = {}
        try:
            result["uname"] = self.run_command(hostname, "uname -a")
        except Exception:
            pass
        try:
            result["os_release"] = self.run_command(hostname, "cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || echo unknown")
        except Exception:
            pass
        try:
            result["hostname"] = self.run_command(hostname, "hostname -f 2>/dev/null || hostname")
        except Exception:
            pass
        return result

    def __del__(self):
        self._disconnect()
