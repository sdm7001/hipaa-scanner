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
from .mfa_checks import (
    MfaRemoteAccessCheck,
    MfaPrivilegedAccountsCheck,
    MfaWindowsHelloCheck,
)
from .certificate_checks import (
    CertificateExpirationCheck,
    SelfSignedCertificateCheck,
)
from .usb_checks import (
    UsbStorageBlockedCheck,
    UsbAutorunDisabledCheck,
)
from .backup_checks import (
    BackupEncryptionCheck,
    BackupRestorationTestCheck,
    OffSiteBackupCheck,
)
from .email_security import (
    DmarcCheck,
    SpfCheck,
    EmailTlsCheck,
)
from .vpn_wireless import (
    VpnEncryptionCheck,
    WirelessSecurityCheck,
    GuestNetworkIsolationCheck,
)
from .logging_siem import (
    CentralizedLoggingCheck,
    LogRetentionPolicyCheck,
)
from .browser_applocker import (
    BrowserSecurityCheck,
    AppLockerCheck,
)
from .database_security import (
    SqlServerTdeCheck,
    SqlServerAuthModeCheck,
)
from .administrative_safeguards import (
    SecurityPolicyDocumentCheck,
    IncidentResponsePlanCheck,
    WorkforceTrainingCheck,
)
from .physical_safeguards import (
    WorkstationPolicyCheck,
    MediaDisposalCheck,
    AssetInventoryCheck,
)
from .linux_checks import (
    LinuxSshRootLoginCheck,
    LinuxSshProtocolCheck,
    LinuxFirewallCheck,
    LinuxAuditdCheck,
    LinuxPasswordPolicyCheck,
)
from .privileged_access import (
    LapsCheck,
    PrivilegedAccountSeparationCheck,
    StalePrivilegedAccountsCheck,
)
from .network_hardening import (
    SmbV1DisabledCheck,
    LlmnrNbtnsDisabledCheck,
    SnmpHardeningCheck,
    WinRmSecurityCheck,
    DnsFilteringCheck,
)
from .endpoint_advanced import (
    WindowsDefenderAtpCheck,
    CredentialGuardCheck,
    SharedAccountDetectionCheck,
    PowershellLoggingCheck,
)
from .group_policy_checks import (
    NtlmRelayProtectionCheck,
    DefenderConfigurationCheck,
    SecureBootCheck,
    UserRightsAssignmentCheck,
    WindowsHelloForBusinessCheck,
    LocalFirewallRulesAuditCheck,
)
from .remote_access_checks import (
    RemoteDesktopGatewayCheck,
    AzureAdConditionalAccessCheck,
    RemoteManagementSecurityCheck,
    EntraIdSyncCheck,
)
from .windows_advanced_checks import (
    AutoRunAutoPlayCheck,
    ScheduledTaskAuditCheck,
    GuestAccountCheck,
    TimeServerSyncCheck,
    WindowsScriptingHostCheck,
    LocalSecurityPolicyCheck,
)
from .linux_advanced_checks import (
    LinuxSudoConfigCheck,
    LinuxUnattendedUpgradesCheck,
    LinuxFilePermissionsCheck,
    LinuxDiskEncryptionCheck,
    LinuxSyslogCheck,
)
from .phi_advanced_checks import (
    EhrApplicationSecurityCheck,
    EncryptedEmailCheck,
    PrinterSecurityCheck,
    CloudStorageControlCheck,
    RansomwareProtectionCheck,
    PasswordManagerCheck,
    ScreenPrivacyFilterCheck,
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
    # MFA
    MfaRemoteAccessCheck,
    MfaPrivilegedAccountsCheck,
    MfaWindowsHelloCheck,
    # Certificate Management
    CertificateExpirationCheck,
    SelfSignedCertificateCheck,
    # USB/Device Controls
    UsbStorageBlockedCheck,
    UsbAutorunDisabledCheck,
    # Contingency Plan / Backup
    BackupEncryptionCheck,
    BackupRestorationTestCheck,
    OffSiteBackupCheck,
    # Email Security
    DmarcCheck,
    SpfCheck,
    EmailTlsCheck,
    # VPN & Wireless
    VpnEncryptionCheck,
    WirelessSecurityCheck,
    GuestNetworkIsolationCheck,
    # Centralized Logging / SIEM
    CentralizedLoggingCheck,
    LogRetentionPolicyCheck,
    # Browser Security & Application Whitelisting
    BrowserSecurityCheck,
    AppLockerCheck,
    # Database Security
    SqlServerTdeCheck,
    SqlServerAuthModeCheck,
    # Administrative Safeguards
    SecurityPolicyDocumentCheck,
    IncidentResponsePlanCheck,
    WorkforceTrainingCheck,
    # Physical Safeguards
    WorkstationPolicyCheck,
    MediaDisposalCheck,
    AssetInventoryCheck,
    # Linux / Unix Checks (SSH connector)
    LinuxSshRootLoginCheck,
    LinuxSshProtocolCheck,
    LinuxFirewallCheck,
    LinuxAuditdCheck,
    LinuxPasswordPolicyCheck,
    # Privileged Access Management
    LapsCheck,
    PrivilegedAccountSeparationCheck,
    StalePrivilegedAccountsCheck,
    # Network Protocol Hardening
    SmbV1DisabledCheck,
    LlmnrNbtnsDisabledCheck,
    SnmpHardeningCheck,
    WinRmSecurityCheck,
    DnsFilteringCheck,
    # EDR / Advanced Endpoint Security
    WindowsDefenderAtpCheck,
    CredentialGuardCheck,
    SharedAccountDetectionCheck,
    # Advanced Audit Controls
    PowershellLoggingCheck,
    # Group Policy / Windows Security Hardening
    NtlmRelayProtectionCheck,
    DefenderConfigurationCheck,
    SecureBootCheck,
    UserRightsAssignmentCheck,
    WindowsHelloForBusinessCheck,
    LocalFirewallRulesAuditCheck,
    # Remote Access Security
    RemoteDesktopGatewayCheck,
    AzureAdConditionalAccessCheck,
    RemoteManagementSecurityCheck,
    EntraIdSyncCheck,
    # Windows Advanced Checks
    AutoRunAutoPlayCheck,
    ScheduledTaskAuditCheck,
    GuestAccountCheck,
    TimeServerSyncCheck,
    WindowsScriptingHostCheck,
    LocalSecurityPolicyCheck,
    # Linux Advanced Checks
    LinuxSudoConfigCheck,
    LinuxUnattendedUpgradesCheck,
    LinuxFilePermissionsCheck,
    LinuxDiskEncryptionCheck,
    LinuxSyslogCheck,
    # PHI Advanced / Healthcare-Specific
    EhrApplicationSecurityCheck,
    EncryptedEmailCheck,
    PrinterSecurityCheck,
    CloudStorageControlCheck,
    RansomwareProtectionCheck,
    PasswordManagerCheck,
    ScreenPrivacyFilterCheck,
]

__all__ = ["BaseCheck", "MVP_CHECKS"]
