"""Credential management — never stored persistently, in-memory only."""

from __future__ import annotations
import getpass
from dataclasses import dataclass
from typing import Optional

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


@dataclass
class ScanCredentials:
    """
    Ephemeral credential container.
    NEVER serialize or write this to disk.
    """
    username: str
    _password: str
    domain: Optional[str] = None

    @property
    def password(self) -> str:
        return self._password

    @classmethod
    def from_prompt(cls) -> "ScanCredentials":
        """Interactive credential prompt. Creds stay in memory only."""
        print("\nEnter credentials for remote scanning:")
        domain = input("Domain (leave blank for workgroup): ").strip() or None
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        return cls(username=username, _password=password, domain=domain)

    @classmethod
    def from_credential_store(cls, label: str) -> "ScanCredentials":
        """Load from OS credential manager (Windows Credential Manager via keyring)."""
        if not KEYRING_AVAILABLE:
            raise RuntimeError("keyring library not installed. Use from_prompt() instead.")
        cred = keyring.get_credential(label, None)
        if not cred:
            raise ValueError(f"No credential found for '{label}' in OS credential store.")
        return cls(username=cred.username, _password=cred.password)

    def save_to_store(self, label: str) -> None:
        """Save to OS credential store (encrypted by OS). Optional convenience."""
        if not KEYRING_AVAILABLE:
            raise RuntimeError("keyring library not installed.")
        keyring.set_password(label, self.username, self._password)

    def wipe(self) -> None:
        """Best-effort in-memory credential wipe."""
        self._password = "\x00" * len(self._password)

    def __del__(self):
        self.wipe()

    def __repr__(self) -> str:
        domain_str = f"{self.domain}\\" if self.domain else ""
        return f"ScanCredentials({domain_str}{self.username}, ***)"
