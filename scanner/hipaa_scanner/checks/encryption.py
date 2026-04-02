"""Module 2: Encryption — At Rest and In Transit (HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii))"""

from .base import BaseCheck
from ..models import Severity, Target, TargetRole, Finding


class BitLockerCheck(BaseCheck):
    check_id = "EN-01"
    check_name = "BitLocker Drive Encryption"
    category = "Encryption at Rest"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 12.0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $drives = Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,ProtectionStatus,VolumeStatus
                if ($drives) {
                    $drives | ConvertTo-Json -Compress
                } else { "not_supported" }
                """.strip()
            )
            if not result or result.strip() == "not_supported":
                return self._error(target, "BitLocker cmdlet not available (requires Windows Pro/Enterprise/Server).")

            import json
            volumes = json.loads(result.strip())
            if isinstance(volumes, dict):
                volumes = [volumes]

            unencrypted = [v for v in volumes if v.get("ProtectionStatus") != "On"]

            if not unencrypted:
                return self._pass(target,
                    f"All {len(volumes)} drive(s) are BitLocker-encrypted.",
                    evidence={"volumes": volumes})
            else:
                mounts = [v["MountPoint"] for v in unencrypted]
                return self._fail(target,
                    f"{len(unencrypted)} drive(s) are not BitLocker-encrypted: {', '.join(mounts)}",
                    remediation="Enable BitLocker on all drives storing ePHI. Save recovery keys to Active Directory or a secure location.",
                    remediation_script="Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector",
                    evidence={"unencrypted_volumes": mounts, "all_volumes": volumes})
        except Exception as e:
            return self._error(target, str(e))


class TlsProtocolCheck(BaseCheck):
    check_id = "EN-02"
    check_name = "Deprecated TLS/SSL Protocols Disabled"
    category = "Encryption in Transit"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 8.0

    DEPRECATED_PROTOCOLS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                r"""
                $protocols = @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')
                $enabled = @()
                foreach ($proto in $protocols) {
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
                    $val = (Get-ItemProperty -Path $path -Name 'Enabled' -ErrorAction SilentlyContinue)?.Enabled
                    if ($val -ne 0) { $enabled += $proto }
                }
                $enabled -join ","
                """.strip()
            )
            enabled_deprecated = [p.strip() for p in (result or "").strip().split(",") if p.strip()]

            if not enabled_deprecated:
                return self._pass(target, "No deprecated SSL/TLS protocols are enabled.")
            else:
                return self._fail(target,
                    f"Deprecated protocol(s) enabled on server: {', '.join(enabled_deprecated)}",
                    remediation="Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 via registry. Only TLS 1.2 and TLS 1.3 should be active.",
                    evidence={"enabled_deprecated_protocols": enabled_deprecated})
        except Exception as e:
            return self._error(target, str(e))


class RdpEncryptionCheck(BaseCheck):
    check_id = "EN-03"
    check_name = "RDP Encryption Level"
    category = "Encryption in Transit"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION]
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue)?.MinEncryptionLevel"
            )
            level = int(result.strip()) if result.strip().isdigit() else -1
            # Level 3 = High (128-bit), 4 = FIPS compliant
            if level >= 3:
                return self._pass(target, f"RDP encryption level is {level} (High/FIPS).",
                    evidence={"rdp_encryption_level": level})
            else:
                return self._fail(target,
                    f"RDP encryption level is {level} (should be 3=High or 4=FIPS).",
                    remediation="Set RDP minimum encryption level to High via Group Policy.",
                    evidence={"rdp_encryption_level": level})
        except Exception as e:
            return self._error(target, str(e))


class SmbEncryptionCheck(BaseCheck):
    check_id = "EN-04"
    check_name = "SMB Signing and Encryption"
    category = "Encryption in Transit"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                """
                $cfg = Get-SmbServerConfiguration | Select RequireSecuritySignature,EncryptData
                "$($cfg.RequireSecuritySignature)|$($cfg.EncryptData)"
                """.strip()
            )
            parts = (result or "").strip().split("|")
            signing = parts[0].strip().lower() == "true" if parts else False
            encryption = parts[1].strip().lower() == "true" if len(parts) > 1 else False

            issues = []
            if not signing:
                issues.append("SMB signing not required")
            if not encryption:
                issues.append("SMB encryption not enabled")

            if not issues:
                return self._pass(target, "SMB signing required and SMB encryption enabled.",
                    evidence={"smb_signing": signing, "smb_encryption": encryption})
            else:
                return self._fail(target,
                    "; ".join(issues) + ".",
                    remediation="Enable SMB signing and encryption: Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true",
                    remediation_script="Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Force",
                    evidence={"smb_signing": signing, "smb_encryption": encryption})
        except Exception as e:
            return self._error(target, str(e))
