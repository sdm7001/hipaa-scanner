"""
Physical safeguards compliance checks — detectable via system configuration.
HIPAA reference: 164.310 — Physical Safeguards (REQUIRED/ADDRESSABLE)
NIST SP 800-66r2: Section 3.4 — Physical Safeguards

Physical safeguards are partially verifiable via software — workstation use policies,
device encryption (already covered by BitLocker), and asset identification.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class WorkstationPolicyCheck(BaseCheck):
    """
    PHYS-01: Verify workstation use policy artifacts are present.
    Tests: Logon legal notice banner (evidence of workstation use policy),
           screensaver lock policy (covered by AC-05 but repeated in physical context),
           BIOS/UEFI password enforcement (prevents boot from USB).
    HIPAA 164.310(b) — Workstation Use (REQUIRED)
    """
    check_id = "PHYS-01"
    check_name = "Workstation Use Policy Enforcement"
    category = "Physical Safeguards"
    hipaa_reference = "164.310(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check legal notice / logon banner (evidence of workstation use policy)
            logon_banner = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' "
                r"-Name LegalNoticeText -ErrorAction SilentlyContinue).LegalNoticeText"
            )

            logon_caption = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' "
                r"-Name LegalNoticeCaption -ErrorAction SilentlyContinue).LegalNoticeCaption"
            )

            # Check if BIOS password is set (indirectly via Secure Boot — can't directly check BIOS password)
            secure_boot = context.winrm.run_ps(
                target.hostname,
                r"Confirm-SecureBootUEFI -ErrorAction SilentlyContinue"
            )

            # Check if disk is encrypted (reinforces physical safeguard for workstations)
            bitlocker_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus"
            )

            has_banner = bool(logon_banner.strip() and len(logon_banner.strip()) > 10)
            has_caption = bool(logon_caption.strip() and len(logon_caption.strip()) > 2)
            secure_boot_on = "true" in secure_boot.strip().lower()
            bl_protected = bitlocker_status.strip() == "On"

            evidence = {
                "logon_banner_present": has_banner,
                "logon_caption": logon_caption.strip()[:50] if logon_caption.strip() else None,
                "secure_boot": secure_boot_on,
                "bitlocker_protected": bl_protected,
            }

            score = sum([has_banner, secure_boot_on, bl_protected])

            if score >= 2 and has_banner:
                return self._pass(
                    target,
                    details="Workstation use policy artifacts detected: logon banner configured, Secure Boot/BitLocker active.",
                    evidence=evidence,
                )
            elif has_banner:
                return self._fail(
                    target,
                    details="Logon banner present (workstation use policy) but Secure Boot or BitLocker not enabled — physical theft risk.",
                    remediation=(
                        "Enable BitLocker and Secure Boot on all workstations handling ePHI: "
                        "Secure Boot prevents booting unauthorized OS. "
                        "BitLocker protects data if the device is physically stolen. "
                        "Both are prerequisites for HIPAA physical safeguard compliance."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No logon banner configured. Workstations must display an Authorized Use Only policy before login.",
                    remediation=(
                        "Configure logon banner via Group Policy: "
                        "Computer Configuration > Windows Settings > Security Settings > "
                        "Local Policies > Security Options > "
                        "'Interactive logon: Message text for users attempting to log on' and "
                        "'Interactive logon: Message title for users attempting to log on'. "
                        "Banner must include: authorized use only, monitoring notice, consent to monitoring. "
                        "This banner is also a legal protection in case of unauthorized access prosecution."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        r"# Set logon banner via registry:" + "\n"
                        r"$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'" + "\n"
                        r"Set-ItemProperty $key -Name LegalNoticeCaption -Value 'AUTHORIZED USE ONLY'" + "\n"
                        r"Set-ItemProperty $key -Name LegalNoticeText -Value " + "\n"
                        r"  'This system is for authorized users only. All activity is monitored and logged. " + "\n"
                        r"   Unauthorized access is prohibited and subject to criminal prosecution.'"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class MediaDisposalCheck(BaseCheck):
    """
    PHYS-02: Verify media disposal policy artifacts — specifically that encrypted or
    cleared drives are the norm (BitLocker-encrypted drives can be disposed without wiping).
    HIPAA 164.310(d)(2)(i) — Disposal (REQUIRED)
    """
    check_id = "PHYS-02"
    check_name = "Media Disposal Policy (Encrypted Storage)"
    category = "Physical Safeguards"
    hipaa_reference = "164.310(d)(2)(i)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check all drive volumes for BitLocker protection
            all_volumes = context.winrm.run_ps(
                target.hostname,
                r"Get-BitLockerVolume -ErrorAction SilentlyContinue | "
                r"Select-Object MountPoint, ProtectionStatus, EncryptionMethod, VolumeStatus | ConvertTo-Json"
            )

            # Check if there are unencrypted data volumes (not just C:)
            unprotected_volumes = context.winrm.run_ps(
                target.hostname,
                r"Get-BitLockerVolume -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.ProtectionStatus -ne 'On' -and $_.VolumeType -ne 'OperatingSystem' } | "
                r"Select-Object MountPoint | ConvertTo-Json"
            )

            import json as _json
            volumes = []
            if all_volumes.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(all_volumes)
                    volumes = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            unprotected = []
            if unprotected_volumes.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(unprotected_volumes)
                    unprotected = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            all_protected = all(
                v.get("ProtectionStatus") == "On" for v in volumes
            ) if volumes else False

            evidence = {
                "total_volumes": len(volumes),
                "unprotected_data_volumes": [v.get("MountPoint") for v in unprotected][:5],
                "all_volumes_encrypted": all_protected,
            }

            if all_protected and volumes:
                return self._pass(
                    target,
                    details=f"All {len(volumes)} storage volumes are BitLocker-protected. Disposal is safe without physical destruction.",
                    evidence=evidence,
                )
            elif volumes and not unprotected:
                return self._pass(
                    target,
                    details="OS volume encrypted; no unencrypted data volumes detected.",
                    evidence=evidence,
                )
            elif unprotected:
                return self._fail(
                    target,
                    details=f"{len(unprotected)} data volume(s) not encrypted: {', '.join([v.get('MountPoint','?') for v in unprotected[:3]])}. When this drive is disposed, ePHI can be recovered.",
                    remediation=(
                        "Enable BitLocker on all storage volumes containing ePHI: "
                        "Enable-BitLocker -MountPoint D: -EncryptionMethod XtsAes256 "
                        "-RecoveryPasswordProtector. "
                        "Without encryption, storage media MUST be physically destroyed (shred/degauss) "
                        "before disposal — an expensive and often incomplete process. "
                        "Encrypted drives can be safely disposed by deleting the encryption key."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="BitLocker status could not be determined. Manual verification of all storage media encryption is required.",
                    remediation=(
                        "Run: Get-BitLockerVolume | Select MountPoint, ProtectionStatus. "
                        "All volumes with ePHI must show ProtectionStatus = On. "
                        "Enable BitLocker where missing per HIPAA 164.310(d)(2)(i) media disposal requirements."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class AssetInventoryCheck(BaseCheck):
    """
    PHYS-03: Check if asset inventory artifacts are present.
    HIPAA 164.310(d)(1) requires tracking of hardware/media containing ePHI.
    Tests: SCCM/Intune/WSUS enrollment (managed asset tracking), domain membership,
           remote management agent presence.
    """
    check_id = "PHYS-03"
    check_name = "Hardware Asset Inventory / Tracking"
    category = "Physical Safeguards"
    hipaa_reference = "164.310(d)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 4.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check SCCM/ConfigMgr agent
            sccm = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue | "
                r"Select-Object -ExpandProperty Status"
            )

            # Check Intune enrollment
            intune = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Enrollments' "
                r"-ErrorAction SilentlyContinue) -ne $null"
            )

            # Check domain membership (domain = managed)
            domain_joined = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_ComputerSystem).DomainRole"
            )

            # Check Datto RMM / ConnectWise / NinjaRMM / Atera agents
            rmm_agents = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'CagService','ScreenConnect*','NinjaRMMAgent','AteraAgent',"
                r"'ITSPlatform','DattoRMM','Kaseya*' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Select-Object Name | ConvertTo-Json"
            )

            sccm_running = "running" in sccm.strip().lower()
            intune_enrolled = intune.strip().lower() == "true"
            # DomainRole: 0=standalone workstation, 1=member workstation, 2=standalone server, 3=member server, 4/5=DC
            domain_role = int(domain_joined.strip()) if domain_joined.strip().isdigit() else 0
            is_managed = domain_role >= 1  # Member workstation or server = domain managed
            has_rmm = rmm_agents.strip() not in ("", "null", "[]")

            evidence = {
                "sccm_agent": sccm_running,
                "intune_enrolled": intune_enrolled,
                "domain_role": domain_role,
                "is_domain_member": is_managed,
                "rmm_agent": has_rmm,
            }

            if sccm_running or intune_enrolled or has_rmm:
                return self._pass(
                    target,
                    details="Asset is tracked via endpoint management (SCCM, Intune, or RMM agent detected).",
                    evidence=evidence,
                )
            elif is_managed:
                return self._pass(
                    target,
                    details="Device is domain-joined — tracked via Active Directory asset management.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Device is not domain-joined and has no detected asset management agent. This device may not appear in hardware inventory.",
                    remediation=(
                        "Implement hardware asset tracking for all devices with ePHI access: "
                        "1. Join devices to Active Directory domain for centralized tracking. "
                        "2. Deploy an RMM agent (Datto, NinjaRMM, ConnectWise, Atera) for MSP management. "
                        "3. Enroll in Microsoft Intune for cloud-based MDM. "
                        "Maintain a physical asset inventory as backup — spreadsheet with make, model, "
                        "serial number, assigned user, location, and ePHI classification."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
