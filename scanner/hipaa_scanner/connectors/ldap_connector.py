"""
LDAP connector — queries Active Directory for domain-level compliance data.
Uses ldap3 library.
"""

from __future__ import annotations
from typing import Optional
import ldap3
from datetime import datetime, timezone, timedelta


class LdapConnector:
    """Connects to AD and provides HIPAA-relevant query methods."""

    def __init__(self, domain_controller: str, username: str, password: str,
                 base_dn: Optional[str] = None, use_ssl: bool = False):
        self.domain_controller = domain_controller
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.use_ssl = use_ssl
        self._conn: Optional[ldap3.Connection] = None

    def connect(self) -> None:
        server = ldap3.Server(
            self.domain_controller,
            port=636 if self.use_ssl else 389,
            use_ssl=self.use_ssl,
            get_info=ldap3.ALL,
        )
        self._conn = ldap3.Connection(
            server,
            user=self.username,
            password=self.password,
            authentication=ldap3.NTLM,
            auto_bind=True,
        )
        if not self.base_dn:
            # Auto-detect base DN from server info
            self.base_dn = server.info.other.get("defaultNamingContext", [""])[0]

    def disconnect(self) -> None:
        if self._conn:
            self._conn.unbind()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def _ensure_connected(self):
        if not self._conn or not self._conn.bound:
            self.connect()

    def get_password_policy(self) -> dict:
        """Retrieve the Default Domain Password Policy."""
        self._ensure_connected()
        self._conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=domainDNS)",
            search_scope=ldap3.BASE,
            attributes=[
                "minPwdLength", "pwdHistoryLength", "pwdProperties",
                "maxPwdAge", "minPwdAge", "lockoutThreshold",
                "lockoutDuration", "lockOutObservationWindow"
            ]
        )
        if self._conn.entries:
            entry = self._conn.entries[0]
            return {attr: getattr(entry, attr).value for attr in [
                "minPwdLength", "pwdHistoryLength", "pwdProperties",
                "maxPwdAge", "minPwdAge", "lockoutThreshold",
            ] if hasattr(entry, attr)}
        return {}

    def get_all_users(self, enabled_only: bool = True) -> list[dict]:
        """Return all AD user accounts."""
        self._ensure_connected()
        filter_str = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
            if enabled_only else "(&(objectClass=user)(objectCategory=person))"
        self._conn.search(
            search_base=self.base_dn,
            search_filter=filter_str,
            attributes=["sAMAccountName", "displayName", "lastLogonTimestamp",
                       "userAccountControl", "memberOf", "pwdLastSet"]
        )
        return [entry.entry_attributes_as_dict for entry in self._conn.entries]

    def get_inactive_users(self, days: int = 90) -> list[str]:
        """Return enabled users who haven't logged in for {days} days."""
        self._ensure_connected()
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        # lastLogonTimestamp is stored as Windows FILETIME (100-nanosecond intervals since 1601-01-01)
        filetime_cutoff = int((cutoff - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)

        self._conn.search(
            search_base=self.base_dn,
            search_filter=f"(&(objectClass=user)(objectCategory=person)"
                          f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                          f"(lastLogonTimestamp<={filetime_cutoff}))",
            attributes=["sAMAccountName", "lastLogonTimestamp"]
        )
        return [entry.sAMAccountName.value for entry in self._conn.entries]

    def get_domain_admins(self) -> list[str]:
        """Return members of the Domain Admins group."""
        self._ensure_connected()
        self._conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=group)(cn=Domain Admins))",
            attributes=["member"]
        )
        if self._conn.entries:
            members = self._conn.entries[0].member.values
            # Extract CN from DN
            return [m.split(",")[0].replace("CN=", "") for m in members]
        return []

    def get_computers(self) -> list[dict]:
        """Return all domain-joined computers."""
        self._ensure_connected()
        self._conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=computer)",
            attributes=["cn", "dNSHostName", "operatingSystem",
                       "operatingSystemVersion", "lastLogonTimestamp"]
        )
        return [entry.entry_attributes_as_dict for entry in self._conn.entries]
