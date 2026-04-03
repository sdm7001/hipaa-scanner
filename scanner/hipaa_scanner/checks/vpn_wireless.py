"""
VPN and wireless network security compliance checks.
HIPAA reference:
  164.312(e)(1) — Transmission Security (REQUIRED)
  164.312(e)(2)(ii) — Encryption in transit (ADDRESSABLE)
NIST SP 800-66r2: Section 3.7 — Transmission Security

Remote access VPN and wireless networks are high-risk ePHI transmission paths.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class VpnEncryptionCheck(BaseCheck):
    """
    VPN-01: Verify VPN is deployed and using strong encryption (IKEv2/AES-256 or equivalent).
    Tests: Windows RRAS VPN config, common VPN client software (Cisco, Palo Alto, OpenVPN, WireGuard),
           L2TP/PPTP (weak) vs IKEv2/OpenVPN/WireGuard (strong).
    """
    check_id = "VPN-01"
    check_name = "VPN Encryption Strength"
    category = "Transmission Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check 1: Active VPN connections / adapters
            vpn_adapters = context.winrm.run_ps(
                target.hostname,
                r"Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'VPN|WireGuard|OpenVPN|Cisco|"
                r"Palo Alto|GlobalProtect|Juniper|Fortinet|SonicWall|Check Point|Pulse|Ivanti' } | "
                r"Select-Object Name, InterfaceDescription, Status | ConvertTo-Json"
            )

            # Check 2: VPN client software installed
            vpn_software = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, "
                r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.DisplayName -match 'VPN|WireGuard|OpenVPN|GlobalProtect|AnyConnect|"
                r"Pulse Secure|Ivanti|Fortinet|SonicWall|NordVPN|ExpressVPN|Zscaler|Always On' } | "
                r"Select-Object DisplayName | ConvertTo-Json"
            )

            # Check 3: RRAS VPN server (Windows Routing and Remote Access)
            rras_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue | "
                r"Select-Object Status, StartType | ConvertTo-Json"
            )

            # Check 4: PPTP or L2TP (weak) vs IKEv2 (strong) on RRAS
            weak_protocols = context.winrm.run_ps(
                target.hostname,
                r"if (Get-Command netsh -ErrorAction SilentlyContinue) { "
                r"netsh ras show registeredserver 2>&1 } else { 'not available' }"
            )

            # Check 5: Always On VPN detection (modern Windows 10/11 enterprise VPN)
            always_on_vpn = context.winrm.run_ps(
                target.hostname,
                r"Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.TunnelType -in ('IKEv2','Sstp') } | "
                r"Select-Object Name, TunnelType, EncryptionLevel | ConvertTo-Json"
            )

            import json as _json
            adapters = []
            if vpn_adapters.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(vpn_adapters)
                    adapters = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            software_list = []
            if vpn_software.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(vpn_software)
                    software_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            has_vpn = bool(adapters) or bool(software_list)

            aovpn = []
            if always_on_vpn.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(always_on_vpn)
                    aovpn = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            # Detect weak protocols (PPTP is cryptographically broken)
            pptp_present = "pptp" in weak_protocols.lower() or "pptp" in vpn_adapters.lower()

            evidence = {
                "vpn_adapters": [a.get("InterfaceDescription", "") for a in adapters][:5],
                "vpn_software": [s.get("DisplayName", "") for s in software_list][:5],
                "always_on_vpn_connections": len(aovpn),
                "pptp_detected": pptp_present,
                "rras": rras_service.strip(),
            }

            if not has_vpn and not aovpn:
                return self._fail(
                    target,
                    details="No VPN client or server software detected. Remote access to ePHI systems may occur over unencrypted connections.",
                    remediation=(
                        "Deploy VPN for all remote access to ePHI systems under HIPAA 164.312(e): "
                        "1. Always On VPN (Windows Server 2016+ with IKEv2) — enterprise standard. "
                        "2. Cisco AnyConnect or Palo Alto GlobalProtect for managed endpoints. "
                        "3. WireGuard or OpenVPN for smaller practices. "
                        "AVOID PPTP — cryptographically broken since 1999. "
                        "Use AES-256 encryption with IKEv2 or OpenVPN protocols."
                    ),
                    evidence=evidence,
                )
            elif pptp_present:
                return self._fail(
                    target,
                    details="PPTP VPN detected. PPTP is cryptographically broken and provides no real security for ePHI in transit.",
                    remediation=(
                        "Immediately replace PPTP with IKEv2, L2TP/IPsec (temporary), or OpenVPN. "
                        "PPTP MS-CHAPv2 authentication can be cracked in hours with commodity tools. "
                        "Microsoft removed PPTP support from Windows Server 2022 for this reason."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable PPTP on Windows RRAS server:\n"
                        "netsh ras set type ipv4rras=1\n"
                        "# Remove PPTP port, add IKEv2 via Server Manager > Routing and Remote Access"
                    ),
                )
            else:
                vpn_names = [a.get("InterfaceDescription", "") for a in adapters[:2]] + \
                            [s.get("DisplayName", "") for s in software_list[:2]]
                return self._pass(
                    target,
                    details=f"VPN solution detected: {', '.join(filter(None, vpn_names[:3]))}. PPTP not detected.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class WirelessSecurityCheck(BaseCheck):
    """
    WIFI-01: Verify wireless networks use WPA2/WPA3 Enterprise and have guest network isolation.
    Tests: Windows Wireless profiles, security type (WEP/WPA/WPA2/WPA3), EAP/802.1X for enterprise auth.
    """
    check_id = "WIFI-01"
    check_name = "Wireless Network Security (WPA2/WPA3 Enterprise)"
    category = "Transmission Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Get all saved wireless profiles
            wifi_profiles = context.winrm.run_ps(
                target.hostname,
                r"$profiles = @(); "
                r"netsh wlan show profiles 2>&1 | Select-String 'All User Profile' | ForEach-Object { "
                r"  $name = ($_ -split ':')[1].Trim(); "
                r"  $detail = netsh wlan show profile name=$name key=clear 2>&1; "
                r"  $auth = ($detail | Select-String 'Authentication').Line; "
                r"  $cipher = ($detail | Select-String 'Cipher').Line; "
                r"  $profiles += [PSCustomObject]@{Name=$name; Auth=$auth; Cipher=$cipher} "
                r"}; "
                r"$profiles | ConvertTo-Json"
            )

            # Check for any WEP or WPA (TKIP) — both weak
            weak_check = context.winrm.run_ps(
                target.hostname,
                r"netsh wlan show profiles 2>&1 | Select-String 'All User Profile' | ForEach-Object { "
                r"  $name = ($_ -split ':')[1].Trim(); "
                r"  $detail = netsh wlan show profile name=$name key=clear 2>&1; "
                r"  $auth = ($detail | Select-String 'Authentication' | Select-Object -First 1).Line; "
                r"  if ($auth -match 'WEP|WPA2?-Personal' -and $auth -notmatch 'WPA2-Enterprise|WPA3') { $name } "
                r"}"
            )

            # Check for 802.1X / EAP (enterprise authentication)
            enterprise_check = context.winrm.run_ps(
                target.hostname,
                r"netsh wlan show profiles 2>&1 | Select-String 'All User Profile' | ForEach-Object { "
                r"  $name = ($_ -split ':')[1].Trim(); "
                r"  $detail = netsh wlan show profile name=$name 2>&1; "
                r"  if ($detail -match '802.1[xX]|EAP|Enterprise') { $name } "
                r"}"
            )

            # Check for wireless adapter presence
            has_wifi = context.winrm.run_ps(
                target.hostname,
                r"Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' } | "
                r"Measure-Object | Select-Object -ExpandProperty Count"
            )

            wifi_count = int(has_wifi.strip()) if has_wifi.strip().isdigit() else 0

            if wifi_count == 0:
                return self._na(target, "No wireless network adapter detected on this system.")

            import json as _json
            profiles = []
            if wifi_profiles.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(wifi_profiles)
                    profiles = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            weak_networks = [n.strip() for n in weak_check.strip().splitlines() if n.strip()]
            enterprise_networks = [n.strip() for n in enterprise_check.strip().splitlines() if n.strip()]

            evidence = {
                "wifi_adapter_count": wifi_count,
                "profile_count": len(profiles),
                "weak_networks": weak_networks[:5],
                "enterprise_networks": enterprise_networks[:5],
            }

            if weak_networks:
                return self._fail(
                    target,
                    details=f"Weak wireless security detected on profiles: {', '.join(weak_networks[:3])}. WEP and WPA-Personal are inadequate for ePHI environments.",
                    remediation=(
                        "Upgrade wireless infrastructure to WPA2-Enterprise or WPA3-Enterprise with 802.1X authentication: "
                        "1. Configure RADIUS server (Windows NPS or cloud RADIUS like JumpCloud/SecureW2). "
                        "2. Use EAP-TLS (certificate-based) for strongest security. "
                        "3. Segregate ePHI network from guest/IoT networks with VLANs. "
                        "4. Disable WEP and WPA-TKIP on all access points — these are trivially cracked. "
                        "Guest networks must be completely isolated from clinical systems."
                    ),
                    evidence=evidence,
                )
            elif enterprise_networks:
                return self._pass(
                    target,
                    details=f"WPA2/WPA3 Enterprise (802.1X) wireless profiles detected: {', '.join(enterprise_networks[:3])}.",
                    evidence=evidence,
                )
            elif profiles:
                return self._fail(
                    target,
                    details="Wireless profiles exist but use personal authentication (pre-shared key). WPA2-Personal allows shared passwords that cannot be revoked per-user.",
                    remediation=(
                        "Migrate clinical/staff wireless networks from WPA2-Personal to WPA2-Enterprise (802.1X): "
                        "This allows per-user authentication, prevents terminated employees from retaining access, "
                        "and meets HIPAA access control requirements under 164.312(a)(1)."
                    ),
                    evidence=evidence,
                )
            else:
                return self._na(target, "Wireless adapter present but no saved profiles found.")
        except Exception as e:
            return self._error(target, str(e))


class GuestNetworkIsolationCheck(BaseCheck):
    """
    WIFI-02: Verify guest wireless network is isolated from clinical/ePHI network.
    Guest WiFi on the same segment as EHR workstations is a direct compliance violation.
    Tests: VLAN configuration, guest SSID isolation flag, DNS/DHCP segregation.
    """
    check_id = "WIFI-02"
    check_name = "Guest Network Isolation from Clinical Network"
    category = "Transmission Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check for multiple network adapters (potential VLAN trunking or multiple NICs)
            adapters = context.winrm.run_ps(
                target.hostname,
                r"Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address | ConvertTo-Json"
            )

            # Check for Hyper-V virtual switches (could indicate VLAN segmentation via virtualization)
            hyperv_switches = context.winrm.run_ps(
                target.hostname,
                r"Get-VMSwitch -ErrorAction SilentlyContinue | Select-Object Name, SwitchType | ConvertTo-Json"
            )

            # Check DHCP server scopes for multiple subnets (indicates segmentation)
            dhcp_scopes = context.winrm.run_ps(
                target.hostname,
                r"Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | "
                r"Select-Object ScopeId, Name, SubnetMask | ConvertTo-Json"
            )

            import json as _json
            adapter_list = []
            if adapters.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(adapters)
                    adapter_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            dhcp_list = []
            if dhcp_scopes.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(dhcp_scopes)
                    dhcp_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            multi_subnet = len(dhcp_list) >= 2
            multi_adapter = len(adapter_list) >= 2

            evidence = {
                "network_adapters": len(adapter_list),
                "dhcp_scopes": len(dhcp_list),
                "dhcp_scope_names": [s.get("Name", "") for s in dhcp_list][:5],
                "hyperv_switches": hyperv_switches.strip() not in ("", "null", "[]"),
            }

            if multi_subnet:
                scope_names = [s.get("Name", "") for s in dhcp_list]
                has_guest = any("guest" in n.lower() or "visitor" in n.lower() for n in scope_names)
                return self._pass(
                    target,
                    details=f"Multiple DHCP scopes detected ({len(dhcp_list)} subnets) — network segmentation appears configured. Guest isolation {'likely present' if has_guest else 'scope names: ' + str(scope_names[:3])}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Single network segment detected. If guest WiFi is present, it may share the same subnet as clinical workstations — a direct HIPAA violation.",
                    remediation=(
                        "Segment guest WiFi from clinical network via VLANs: "
                        "1. Create a separate VLAN on your managed switch for guest traffic. "
                        "2. Configure your wireless access point to assign guest SSID to guest VLAN. "
                        "3. Set firewall rules: guest VLAN → Internet only (block access to clinical subnet). "
                        "4. Configure separate DHCP scope for guest network (192.168.100.0/24 or similar). "
                        "Guest devices must never be able to reach EHR servers or workstations."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
