"""
USB/Removable Media policy compliance checks.
HIPAA reference: 164.310(d)(1) — Device and Media Controls (REQUIRED)
NIST SP 800-66r2: Section 3.5 — Device and Media Controls

Uncontrolled USB use is a top data exfiltration and malware vector in healthcare.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class UsbStorageBlockedCheck(BaseCheck):
    """
    USB-01: Verify USB mass storage devices are blocked or restricted via Group Policy.
    Tests: Device Installation Restrictions, Storage Class GUID policy, BitLocker To Go enforcement.
    """
    check_id = "USB-01"
    check_name = "USB Storage Devices Blocked"
    category = "Device and Media Controls"
    hipaa_reference = "164.310(d)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    # Class GUIDs for USB storage and removable media
    USB_CLASS_GUID = "{36FC9E60-C465-11CF-8056-444553540000}"  # USB Device
    STORAGE_CLASS_GUID = "{4D36E967-E325-11CE-BFC1-08002BE10318}"  # Disk drives

    def run(self, target: Target, context) -> Finding:
        try:
            # Check 1: Device Installation Restriction for USB devices
            install_restriction = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' "
                r"-Name DenyDeviceIDs -ErrorAction SilentlyContinue).DenyDeviceIDs"
            )

            # Check 2: Class-based restriction (deny installation of all removable storage)
            class_restriction = context.winrm.run_ps(
                target.hostname,
                r"$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'; "
                r"if (Test-Path $path) { (Get-Item $path).Property } else { 'not configured' }"
            )

            # Check 3: Write-protect removable storage via policy
            write_protect = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' "
                r"-Name 'Removable Disks;Deny_Write' -ErrorAction SilentlyContinue).'Removable Disks;Deny_Write'"
            )

            # Check 4: BitLocker To Go enforcement (encrypt removable media)
            bltg_policy = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' "
                r"-Name RDVDenyWriteAccess -ErrorAction SilentlyContinue).RDVDenyWriteAccess"
            )

            evidence = {
                "device_install_restriction": install_restriction.strip(),
                "class_restriction": class_restriction.strip(),
                "write_protect_policy": write_protect.strip(),
                "bitlocker_to_go": bltg_policy.strip(),
            }

            # Evaluate: any control = partial credit; no control = fail
            has_install_block = "not configured" not in install_restriction.lower() and install_restriction.strip() not in ("", "null")
            has_class_block = "not configured" not in class_restriction.lower() and class_restriction.strip() != "not configured"
            has_write_protect = write_protect.strip() == "1"
            has_bltg = bltg_policy.strip() == "1"

            if has_install_block or has_class_block:
                return self._pass(
                    target,
                    details="USB device installation restrictions configured via Group Policy.",
                    evidence=evidence,
                )
            elif has_write_protect or has_bltg:
                return self._fail(
                    target,
                    details="USB write protection or BitLocker To Go enforced, but USB devices can still connect. Full block recommended.",
                    remediation=(
                        "Implement USB device installation restrictions via Group Policy in addition to write-protection: "
                        "Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions > "
                        "Prevent installation of devices using drivers that match these device setup classes. "
                        "Add GUID {4D36E967-E325-11CE-BFC1-08002BE10318} (Disk Drives) to block USB storage."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No USB storage restrictions detected. USB mass storage devices can connect and copy ePHI without restriction.",
                    remediation=(
                        "Implement USB storage controls under HIPAA 164.310(d)(1) Device and Media Controls: "
                        "1. Block USB storage devices via Group Policy Device Installation Restrictions. "
                        "2. Enforce BitLocker To Go for removable drives that ARE allowed. "
                        "3. Implement DLP (Data Loss Prevention) software to monitor USB activity. "
                        "4. If USB must be allowed, restrict to company-issued encrypted drives only (Apricorn, Kingston IronKey)."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# PowerShell: Block USB storage via registry (requires GPO for domain deployment)\n"
                        "# Deny write access to removable storage\n"
                        "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' -Force | Out-Null\n"
                        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' "
                        "-Name 'Removable Disks;Deny_Write' -Value 1 -Type DWord"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class UsbAutorunDisabledCheck(BaseCheck):
    """
    USB-02: Verify AutoRun/AutoPlay is disabled for removable media.
    AutoRun enables malware to execute automatically from inserted USB drives.
    """
    check_id = "USB-02"
    check_name = "USB AutoRun/AutoPlay Disabled"
    category = "Device and Media Controls"
    hipaa_reference = "164.310(d)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 4.0

    def run(self, target: Target, context) -> Finding:
        try:
            autorun_disabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' "
                r"-Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
            )

            autoplay_policy = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' "
                r"-Name NoAutoplayfornonVolume -ErrorAction SilentlyContinue).NoAutoplayfornonVolume"
            )

            evidence = {
                "autorun_value": autorun_disabled.strip(),
                "autoplay_policy": autoplay_policy.strip(),
            }

            # 0xFF (255) = disable AutoRun for all drive types, 0x91 = disable for removable and unknown
            autorun_val = int(autorun_disabled.strip()) if autorun_disabled.strip().isdigit() else 0
            autoplay_disabled = autoplay_policy.strip() == "1"

            if autorun_val >= 0x91 or autoplay_disabled:
                return self._pass(
                    target,
                    details=f"AutoRun disabled (NoDriveTypeAutoRun={autorun_val:#x}).",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"AutoRun/AutoPlay not properly disabled (NoDriveTypeAutoRun={autorun_val:#x}). Malware can auto-execute from USB drives.",
                    remediation=(
                        "Disable AutoRun for all drive types via Group Policy: "
                        "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > "
                        "Turn off AutoPlay (enable this setting, select All Drives). "
                        "Also set: Computer Configuration > Administrative Templates > System > Set the default behavior for AutoRun = Enabled, Do not execute any autorun commands."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable AutoRun for all drive types\n"
                        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                        "-Name NoDriveTypeAutoRun -Value 0xFF -Type DWord -Force"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
