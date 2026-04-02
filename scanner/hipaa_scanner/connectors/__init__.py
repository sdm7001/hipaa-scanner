"""Remote Windows connection adapters."""

from .winrm_connector import WinRMConnector
from .ldap_connector import LdapConnector

__all__ = ["WinRMConnector", "LdapConnector"]
