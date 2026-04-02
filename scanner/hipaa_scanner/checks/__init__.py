"""
HIPAA check plugin registry.
Import all check modules here to auto-register them.
"""

from .base import BaseCheck
from .access_controls import (
    PasswordMinLengthCheck,
    PasswordComplexityCheck,
    PasswordMaxAgeCheck,
    AccountLockoutCheck,
    ScreenLockTimeoutCheck,
    InactiveAccountsCheck,
    LocalAdminAuditCheck,
    RdpSessionTimeoutCheck,
)
from .encryption import (
    BitLockerCheck,
    TlsProtocolCheck,
    RdpEncryptionCheck,
    SmbEncryptionCheck,
)
from .audit_controls import (
    AuditPolicyLogonCheck,
    AuditPolicyAccountMgmtCheck,
    EventLogSizeCheck,
    AuditLogRetentionCheck,
)
from .patch_management import (
    WindowsUpdateCheck,
    AutoUpdateEnabledCheck,
    PendingRebootCheck,
)
from .network_security import (
    OpenRdpPortCheck,
    OpenTelnetPortCheck,
    OpenFtpPortCheck,
    WindowsFirewallCheck,
)
from .antivirus import (
    AntivirusPresentCheck,
    AntivirusUpdatedCheck,
    AntivirusRunningCheck,
)
from .phi_detection import (
    PhiOnDesktopCheck,
    PhiOnSharedDriveCheck,
)

# All MVP checks — ordered by category + severity
MVP_CHECKS: list[type[BaseCheck]] = [
    # Access Controls
    PasswordMinLengthCheck,
    PasswordComplexityCheck,
    PasswordMaxAgeCheck,
    AccountLockoutCheck,
    ScreenLockTimeoutCheck,
    InactiveAccountsCheck,
    LocalAdminAuditCheck,
    RdpSessionTimeoutCheck,
    # Encryption
    BitLockerCheck,
    TlsProtocolCheck,
    RdpEncryptionCheck,
    SmbEncryptionCheck,
    # Audit Controls
    AuditPolicyLogonCheck,
    AuditPolicyAccountMgmtCheck,
    EventLogSizeCheck,
    AuditLogRetentionCheck,
    # Patch Management
    WindowsUpdateCheck,
    AutoUpdateEnabledCheck,
    PendingRebootCheck,
    # Network Security
    OpenRdpPortCheck,
    OpenTelnetPortCheck,
    OpenFtpPortCheck,
    WindowsFirewallCheck,
    # Antivirus
    AntivirusPresentCheck,
    AntivirusUpdatedCheck,
    AntivirusRunningCheck,
    # PHI Detection
    PhiOnDesktopCheck,
    PhiOnSharedDriveCheck,
]

__all__ = ["BaseCheck", "MVP_CHECKS"]
