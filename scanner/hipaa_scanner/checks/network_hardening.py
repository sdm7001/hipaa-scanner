"""
Network protocol hardening checks — SMBv1, SNMP, LLMNR, NetBIOS, DNS.
HIPAA reference: 164.312(a)(1) — Access Control, 164.312(e)(1) — Transmission Security
NIST SP 800-66r2: Section 3.7 — Network security hardening

Legacy network protocols are primary attack vectors in healthcare ransomware campaigns.
SMBv1 is the protocol exploited by EternalBlue/WannaCry/NotPetya.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class SmbV1DisabledCheck(BaseCheck):
    """
    NET-01: Verify SMBv1 is disabled.
    SMBv1 is the protocol exploited by EternalBlue (MS17-010), used in WannaCry and NotPetya.
    Healthcare was disproportionately targeted — NHS lost ~£92M to WannaCry.
    """
    check_id = "NET-01"
    check_name = "SMBv1 Protocol Disabled"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check SMBv1 server-side (client connections to this machine)
            smb1_server = context.winrm.run_ps(
                target.hostname,
                r"(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
            )

            # Check SMBv1 client-side (this machine connecting to others)
            smb1_client = context.winrm.run_ps(
                target.hostname,
                r"(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State"
            )

            # Also check registry (works on older Server versions)
            smb1_registry = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' "
                r"-Name SMB1 -ErrorAction SilentlyContinue).SMB1"
            )

            server_enabled = smb1_server.strip().lower() == "true"
            client_enabled = "enabled" in smb1_client.strip().lower()
            registry_enabled = smb1_registry.strip() == "1"

            evidence = {
                "smb1_server_enabled": server_enabled,
                "smb1_client_feature_state": smb1_client.strip(),
                "smb1_registry": smb1_registry.strip(),
            }

            if not server_enabled and not client_enabled and smb1_registry.strip() not in ("1", ""):
                return self._pass(
                    target,
                    details="SMBv1 is disabled (server-side and client-side).",
                    evidence=evidence,
                )
            elif server_enabled or registry_enabled:
                return self._fail(
                    target,
                    details="SMBv1 is ENABLED on this system. This is the protocol exploited by WannaCry and NotPetya. No legitimate use case requires SMBv1 in 2025.",
                    remediation=(
                        "Disable SMBv1 immediately:\n"
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n"
                        "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' SMB1 -Type DWORD -Value 0 -Force"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable SMBv1 (run as Administrator):\n"
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                        "Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force\n"
                        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n"
                        "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                        "-Name SMB1 -Type DWord -Value 0 -Force\n"
                        "# Restart required to fully apply"
                    ),
                )
            else:
                return self._fail(
                    target,
                    details="SMBv1 client feature state unclear. Verify manually that SMBv1 is fully disabled.",
                    remediation="Run: Get-SmbServerConfiguration | Select EnableSMB1Protocol — verify it is False.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LlmnrNbtnsDisabledCheck(BaseCheck):
    """
    NET-02: Verify LLMNR and NetBIOS name resolution are disabled.
    LLMNR and NBT-NS are exploited by Responder for credential theft via poisoning attacks.
    These protocols are unnecessary in domain environments with proper DNS.
    """
    check_id = "NET-02"
    check_name = "LLMNR and NetBIOS Disabled"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # LLMNR via GPO
            llmnr_disabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' "
                r"-Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast"
            )

            # NetBIOS over TCP/IP — check all network adapters
            netbios_status = context.winrm.run_ps(
                target.hostname,
                r"Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.IPEnabled -eq $true } | "
                r"Select-Object Description, TcpipNetbiosOptions | ConvertTo-Json"
            )

            # mDNS/Bonjour (additional passive protocol)
            mdns_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'Bonjour Service','mdnsNSP' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            llmnr_val = llmnr_disabled.strip()
            # TcpipNetbiosOptions: 0=default (use DHCP), 1=enable, 2=disable
            import json as _json
            adapters = []
            if netbios_status.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(netbios_status)
                    adapters = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            netbios_enabled = any(
                str(a.get("TcpipNetbiosOptions", "0")) in ("0", "1") for a in adapters
            )
            llmnr_enabled = llmnr_val != "0"  # 0 = disabled, anything else (or missing) = enabled

            evidence = {
                "llmnr_policy": f"EnableMulticast={llmnr_val}" if llmnr_val else "not configured (LLMNR enabled by default)",
                "netbios_adapters": len(adapters),
                "netbios_may_be_enabled": netbios_enabled,
                "mdns_service_running": mdns_service.strip() not in ("", "0"),
            }

            issues = []
            if llmnr_enabled:
                issues.append("LLMNR not disabled via Group Policy")
            if netbios_enabled:
                issues.append("NetBIOS over TCP/IP may be enabled on network adapters")

            if not issues:
                return self._pass(
                    target,
                    details="LLMNR disabled via Group Policy and NetBIOS disabled on network adapters.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Credential theft risk: {'; '.join(issues)}. Responder/Inveigh can capture NTLMv2 hashes.",
                    remediation=(
                        "Disable LLMNR via Group Policy: "
                        "Computer Configuration > Administrative Templates > Network > DNS Client > "
                        "Turn off multicast name resolution: ENABLED. "
                        "Disable NetBIOS on all adapters: "
                        "Network adapter properties > TCP/IPv4 > Advanced > WINS tab > "
                        "Disable NetBIOS over TCP/IP."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable LLMNR via registry (or use GPO):\n"
                        "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null\n"
                        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
                        "-Name EnableMulticast -Value 0 -Type DWord\n"
                        "# Disable NetBIOS on all adapters:\n"
                        "$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }\n"
                        "$adapters | ForEach-Object { $_.SetTcpipNetbios(2) }"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class SnmpHardeningCheck(BaseCheck):
    """
    NET-03: Verify SNMP v1/v2c is disabled or uses v3 with authentication and privacy.
    SNMP with default community strings ("public"/"private") exposes device configuration
    and can be used to reconfigure network equipment.
    """
    check_id = "NET-03"
    check_name = "SNMP v3 or SNMP Disabled"
    category = "Network Security"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check SNMP service
            snmp_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue | "
                r"Select-Object Status, StartType | ConvertTo-Json"
            )

            # Check SNMP community string (default public/private = bad)
            snmp_community = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' "
                r"-ErrorAction SilentlyContinue).PSObject.Properties | "
                r"Select-Object Name | ConvertTo-Json"
            )

            # Check if SNMP v3 traps are configured (Windows SNMP is v1/v2c only -- v3 requires third-party)
            snmp_permitted_managers = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers' "
                r"-ErrorAction SilentlyContinue).PSObject.Properties | "
                r"Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' } | "
                r"Select-Object Name, Value | ConvertTo-Json"
            )

            import json as _json
            svc = {}
            if snmp_service.strip() not in ("", "null", "[]"):
                try:
                    svc = _json.loads(snmp_service)
                except Exception:
                    pass

            snmp_running = svc.get("Status", "").lower() == "running"

            communities = []
            if snmp_community.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(snmp_community)
                    communities = [c.get("Name", "") for c in (raw if isinstance(raw, list) else [raw])]
                except Exception:
                    pass

            default_communities = [c for c in communities if c.lower() in ("public", "private")]

            evidence = {
                "snmp_service_status": svc.get("Status", "not installed"),
                "community_strings": communities[:5],
                "default_communities_present": default_communities,
                "snmp_permitted_managers": snmp_permitted_managers.strip()[:100],
            }

            if not snmp_running:
                return self._pass(
                    target,
                    details="SNMP service is not running on this host.",
                    evidence=evidence,
                )
            elif default_communities:
                return self._fail(
                    target,
                    details=f"SNMP is running with default community string(s): {', '.join(default_communities)}. Any host can query or manipulate this device.",
                    remediation=(
                        "Immediately change SNMP community strings from default values: "
                        "1. Open Services > SNMP Service > Properties > Security tab. "
                        "2. Remove 'public' and 'private' community strings. "
                        "3. Add a non-guessable community string if SNMP is required. "
                        "4. Restrict SNMP to specific management IPs in PermittedManagers. "
                        "5. Consider disabling SNMP entirely if not needed — SNMPv3 is preferred."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Remove default SNMP community strings:\n"
                        "Remove-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities' "
                        "-Name 'public','private' -ErrorAction SilentlyContinue\n"
                        "# Or stop SNMP entirely:\n"
                        "Stop-Service SNMP -Force; Set-Service SNMP -StartupType Disabled"
                    ),
                )
            elif snmp_running:
                return self._fail(
                    target,
                    details="SNMP is running with non-default community strings. Windows SNMP is v1/v2c only — consider disabling if not required.",
                    remediation=(
                        "SNMP v1/v2c is unencrypted and unauthenticated beyond community strings. "
                        "If SNMP monitoring is required, use an agent that supports SNMPv3 with authPriv mode. "
                        "If SNMP is not actively used, disable the service."
                    ),
                    evidence=evidence,
                )
            else:
                return self._pass(
                    target,
                    details="SNMP service is not installed or not running.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class WinRmSecurityCheck(BaseCheck):
    """
    NET-04: Verify WinRM uses HTTPS and has restricted access.
    WinRM is used by the scanner itself but must be secured — open WinRM over HTTP
    transmits credentials in cleartext and is a lateral movement vector.
    """
    check_id = "NET-04"
    check_name = "WinRM Secured (HTTPS / Restricted Access)"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check WinRM HTTPS listener
            https_listener = context.winrm.run_ps(
                target.hostname,
                r"Get-WSManInstance -ResourceURI winrm/config/Listener "
                r"-SelectorSet @{Transport='HTTPS'} -ErrorAction SilentlyContinue | "
                r"Select-Object Transport, Port, Enabled | ConvertTo-Json"
            )

            # Check if HTTP listener is enabled (insecure)
            http_listener = context.winrm.run_ps(
                target.hostname,
                r"Get-WSManInstance -ResourceURI winrm/config/Listener "
                r"-SelectorSet @{Transport='HTTP'} -ErrorAction SilentlyContinue | "
                r"Select-Object Transport, Port, Enabled | ConvertTo-Json"
            )

            # Check WinRM access restricted to specific hosts
            trusted_hosts = context.winrm.run_ps(
                target.hostname,
                r"(Get-WSManInstance -ResourceURI winrm/config/client -ErrorAction SilentlyContinue).TrustedHosts"
            )

            # Check if AllowUnencrypted is enabled (very bad)
            unencrypted = context.winrm.run_ps(
                target.hostname,
                r"(Get-WSManInstance -ResourceURI winrm/config/service -ErrorAction SilentlyContinue).AllowUnencrypted"
            )

            has_https = https_listener.strip() not in ("", "null", "[]")
            has_http = http_listener.strip() not in ("", "null", "[]")
            unencrypted_allowed = "true" in unencrypted.strip().lower()
            trusted = trusted_hosts.strip()

            evidence = {
                "https_listener": has_https,
                "http_listener": has_http,
                "allow_unencrypted": unencrypted_allowed,
                "trusted_hosts": trusted[:100] if trusted else "not configured",
            }

            if unencrypted_allowed:
                return self._fail(
                    target,
                    details="WinRM AllowUnencrypted=true. WinRM credentials and data transmitted in plaintext — trivial to intercept on the network.",
                    remediation=(
                        "Disable unencrypted WinRM immediately:\n"
                        "Set-WSManInstance -ResourceURI winrm/config/service -ValueSet @{AllowUnencrypted=$false}\n"
                        "Enable HTTPS listener with a valid certificate:\n"
                        "New-WSManInstance -ResourceURI winrm/config/Listener "
                        "-SelectorSet @{Transport='HTTPS'} -ValueSet @{Hostname='server.domain.com'; CertificateThumbprint='...'}"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Secure WinRM (require HTTPS, disable HTTP cleartext):\n"
                        "Set-WSManInstance winrm/config/service -ValueSet @{AllowUnencrypted=$false}\n"
                        "# Remove HTTP listener if HTTPS is configured:\n"
                        "# Remove-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTP'}"
                    ),
                )
            elif has_https and not has_http:
                return self._pass(
                    target,
                    details="WinRM HTTPS listener configured; HTTP listener not present.",
                    evidence=evidence,
                )
            elif has_http and not has_https:
                return self._fail(
                    target,
                    details="WinRM uses HTTP only (no HTTPS listener). Kerberos provides authentication but not encryption — data is still readable on the network.",
                    remediation=(
                        "Configure WinRM HTTPS listener using a machine certificate: "
                        "1. Obtain or create a machine certificate (use auto-enrollment via AD CA). "
                        "2. New-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTPS'} "
                        "   -ValueSet @{Hostname='FQDN'; CertificateThumbprint='THUMBPRINT'}. "
                        "3. Remove or restrict the HTTP listener."
                    ),
                    evidence=evidence,
                )
            else:
                return self._pass(
                    target,
                    details="WinRM appears configured with Kerberos authentication (no unencrypted flag set).",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class DnsFilteringCheck(BaseCheck):
    """
    NET-05: Verify DNS filtering is configured to block malicious domains.
    DNS filtering is the first line of defense against phishing, ransomware C2, and malware delivery.
    Particularly important for healthcare — attacks often use DNS-based C2 to avoid firewall detection.
    """
    check_id = "NET-05"
    check_name = "DNS Filtering / Protective DNS"
    category = "Network Security"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 5.0

    # Known DNS filtering provider IP ranges
    FILTERING_DNS = {
        "1.1.1.2": "Cloudflare Gateway",
        "1.0.0.2": "Cloudflare Gateway",
        "208.67.222.222": "Cisco OpenDNS",
        "208.67.220.220": "Cisco OpenDNS",
        "208.67.222.123": "Cisco OpenDNS Familyshield",
        "9.9.9.9": "Quad9",
        "149.112.112.112": "Quad9",
        "76.76.19.19": "Alternate DNS",
        "185.228.168.9": "CleanBrowsing",
    }

    def run(self, target: Target, context) -> Finding:
        try:
            # Get DNS server configuration
            dns_servers = context.winrm.run_ps(
                target.hostname,
                r"Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.ServerAddresses.Count -gt 0 } | "
                r"Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json"
            )

            # Also check if DNS over HTTPS (DoH) is configured
            doh_config = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' "
                r"-Name EnableAutoDoh -ErrorAction SilentlyContinue).EnableAutoDoh"
            )

            # Check if Cisco Umbrella, DNSFilter, etc. agent is installed
            dns_agent = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.DisplayName -match 'Umbrella|DNSFilter|Webroot DNS|Zscaler|BlueShield|Comodo Dome' } | "
                r"Select-Object DisplayName | ConvertTo-Json"
            )

            import json as _json
            all_dns_ips = []
            if dns_servers.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(dns_servers)
                    interfaces = raw if isinstance(raw, list) else [raw]
                    for iface in interfaces:
                        servers = iface.get("ServerAddresses", [])
                        if isinstance(servers, list):
                            all_dns_ips.extend(servers)
                        elif isinstance(servers, str):
                            all_dns_ips.append(servers)
                except Exception:
                    pass

            has_filtering_dns = any(ip in self.FILTERING_DNS for ip in all_dns_ips)
            has_dns_agent = dns_agent.strip() not in ("", "null", "[]")
            has_doh = doh_config.strip() in ("1", "2", "3")

            matched_providers = list({self.FILTERING_DNS[ip] for ip in all_dns_ips if ip in self.FILTERING_DNS})

            evidence = {
                "dns_servers": all_dns_ips[:8],
                "filtering_providers_detected": matched_providers,
                "dns_agent_installed": has_dns_agent,
                "dns_over_https": has_doh,
            }

            if has_filtering_dns or has_dns_agent:
                providers = matched_providers or ["DNS filtering agent"]
                return self._pass(
                    target,
                    details=f"DNS filtering detected: {', '.join(providers)}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No DNS filtering solution detected. DNS queries route to unfiltered resolvers — phishing and malware domains are accessible.",
                    remediation=(
                        "Implement Protective DNS (DNS filtering) for all endpoints: "
                        "1. Cisco Umbrella — enterprise DNS security, blocks C2 traffic, CISA PDNS partner. "
                        "2. Cloudflare Gateway (1.1.1.2) — free tier with malware blocking. "
                        "3. Quad9 (9.9.9.9) — free, blocks known malicious domains. "
                        "4. DNSFilter, Webroot DNS, or Infoblox for enterprise management. "
                        "Configure via DHCP option 6 to push to all clients, or deploy DNS filtering agent."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
