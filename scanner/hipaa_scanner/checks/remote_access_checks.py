"""
Remote access and cloud identity security checks.
HIPAA reference: 164.312(a)(1) — Access Control, 164.312(e)(1) — Transmission Security

Remote access is the #1 healthcare breach vector. COVID-19 dramatically increased
remote work at medical practices, often without proper security controls.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class RemoteDesktopGatewayCheck(BaseCheck):
    """
    RMT-01: Verify RDP is behind a Remote Desktop Gateway or VPN, not exposed directly.
    Direct RDP exposure (port 3389 open to internet) is the most common ransomware
    entry point in healthcare. RD Gateway adds certificate auth + TLS wrapping.
    """
    check_id = "RMT-01"
    check_name = "Remote Desktop Gateway or VPN Enforcement"
    category = "Network Security"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 12.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check if RD Gateway is installed/running
            rdg_service = context.winrm.run_ps(
                target.hostname,
                r"(Get-Service -Name TSGateway -ErrorAction SilentlyContinue).Status"
            )

            # Check if RD Gateway is configured in RDP settings
            rdg_configured = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKCU:\Software\Microsoft\Terminal Server Client\Default\AddIns\RDPDR' "
                r"-ErrorAction SilentlyContinue).GatewayHostname"
            )

            # Check Always-On VPN client (Windows built-in)
            vpn_connections = context.winrm.run_ps(
                target.hostname,
                r"(Get-VpnConnection -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.ConnectionStatus -eq 'Connected' }).Count"
            )

            # Check RD Gateway server role features
            rdg_role = context.winrm.run_ps(
                target.hostname,
                r"(Get-WindowsFeature RDS-Gateway -ErrorAction SilentlyContinue).Installed"
            )

            # Check NLA (Network Level Authentication) as minimum RDP hardening
            nla_enabled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' "
                r"-Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication"
            )

            rdg_running = rdg_service.strip().lower() == "running"
            rdg_installed = rdg_role.strip().lower() == "true"

            try:
                vpn_count = int(vpn_connections.strip())
            except (ValueError, AttributeError):
                vpn_count = 0

            nla_ok = nla_enabled.strip() == "1"

            evidence = {
                "rdgateway_service": rdg_service.strip() or "not present",
                "rdgateway_role_installed": rdg_installed,
                "vpn_connected": vpn_count > 0,
                "nla_enabled": nla_ok,
            }

            if rdg_running or rdg_installed:
                return self._pass(
                    target,
                    details="Remote Desktop Gateway is installed/running. RDP access is wrapped in TLS with certificate authentication.",
                    evidence=evidence,
                )
            elif vpn_count > 0:
                return self._pass(
                    target,
                    details=f"VPN connection active — RDP likely tunneled through VPN. {vpn_count} active VPN connection(s).",
                    evidence=evidence,
                )
            elif nla_ok:
                return self._fail(
                    target,
                    details="No RD Gateway or VPN detected, but NLA is enabled (partial protection). Direct RDP may still be exposed.",
                    remediation=(
                        "Deploy Remote Desktop Gateway to protect RDP: "
                        "1. Install RDS-Gateway role: Install-WindowsFeature RDS-Gateway -IncludeManagementTools. "
                        "2. Configure RD Gateway Manager: Set certificate, create connection authorization policies. "
                        "3. Firewall: Block port 3389 externally. Allow only RD Gateway HTTPS (443). "
                        "4. Alternative: Always On VPN (Windows) or third-party VPN. "
                        "Direct RDP = most common healthcare ransomware entry point. "
                        "NLA helps but doesn't prevent brute force against valid accounts."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No RD Gateway, VPN, or NLA detected. RDP may be directly exposed without strong authentication.",
                    remediation=(
                        "CRITICAL — secure RDP access immediately: "
                        "1. Enable NLA: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                        "   -Name UserAuthentication -Value 1. "
                        "2. Deploy RD Gateway or VPN as described above. "
                        "3. Block port 3389 at the network perimeter firewall. "
                        "4. Consider disabling RDP entirely if not needed. "
                        "Direct RDP with no NLA is a critical vulnerability — change default port does NOT protect against scanners."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class AzureAdConditionalAccessCheck(BaseCheck):
    """
    RMT-02: Verify Azure AD Conditional Access policies are enforcing MFA and
    compliant device requirements for cloud application access.
    Most healthcare organizations now use M365/Azure — CA policies are the
    primary control for cloud-based PHI access.
    """
    check_id = "RMT-02"
    check_name = "Azure AD Conditional Access Policies"
    category = "Multi-Factor Authentication"
    hipaa_reference = "164.312(d)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check if device is Azure AD joined or registered
            aad_join_status = context.winrm.run_ps(
                target.hostname,
                r"$status = dsregcmd /status 2>$null; "
                r"$aad = ($status | Select-String 'AzureAdJoined\s*:\s*(\w+)').Matches.Groups[1].Value; "
                r"$hybrid = ($status | Select-String 'DomainJoined\s*:\s*(\w+)').Matches.Groups[1].Value; "
                r"$reg = ($status | Select-String 'WorkplaceJoined\s*:\s*(\w+)').Matches.Groups[1].Value; "
                r"\"AzureAD=$aad,DomainJoined=$hybrid,WorkplaceJoined=$reg\""
            )

            # Check for Intune MDM enrollment (managed = CA compliant device possible)
            mdm_enrolled = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Microsoft\Enrollments' "
                r"-ErrorAction SilentlyContinue) -ne $null"
            )

            # Check if SSPR/MFA registration is present (M365 MFA indicator)
            mfa_indicator = context.winrm.run_ps(
                target.hostname,
                r"Test-Path 'HKCU:\Software\Microsoft\MicrosoftAccount\Authentication' "
                r"-ErrorAction SilentlyContinue"
            )

            # Check for Work Account registered (M365 account)
            work_account = context.winrm.run_ps(
                target.hostname,
                r"$accounts = Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD\Storage' "
                r"-ErrorAction SilentlyContinue; "
                r"if ($accounts) { $accounts.Count } else { 0 }"
            )

            aad_status = aad_join_status.strip()
            aad_joined = "AzureAD=YES" in aad_status or "AzureAD=True" in aad_status.replace("YES", "True")
            hybrid_joined = "DomainJoined=YES" in aad_status

            mdm_ok = mdm_enrolled.strip().lower() == "true"

            try:
                work_count = int(work_account.strip())
            except (ValueError, AttributeError):
                work_count = 0

            evidence = {
                "aad_join_status": aad_status[:200],
                "azure_ad_joined": aad_joined,
                "hybrid_joined": hybrid_joined,
                "mdm_enrolled": mdm_ok,
                "work_accounts": work_count,
            }

            if aad_joined and mdm_ok:
                return self._pass(
                    target,
                    details="Device is Azure AD joined and MDM enrolled — eligible for Conditional Access compliant device policies.",
                    evidence=evidence,
                )
            elif aad_joined or hybrid_joined:
                return self._fail(
                    target,
                    details=f"Device is {'Azure AD' if aad_joined else 'hybrid'} joined but MDM enrollment not confirmed. Conditional Access compliant device enforcement may not apply.",
                    remediation=(
                        "Enroll device in Intune MDM for full Conditional Access compliance: "
                        "1. Settings → Accounts → Access work or school → Enroll in device management. "
                        "2. Or auto-enroll via GPO: Computer Config > Admin Templates > Windows Components > MDM. "
                        "3. Verify CA policies in Azure AD portal require 'Compliant device' or 'Hybrid Azure AD joined'. "
                        "4. Without MDM: CA can enforce MFA but not device compliance (weaker control)."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Device not Azure AD joined or registered. Conditional Access policies may not apply to this device's cloud access.",
                    remediation=(
                        "Join device to Azure AD or register for work: "
                        "1. Azure AD Join (cloud-only/modern): Settings → Accounts → Access work or school → Connect → Join this device. "
                        "2. Hybrid Azure AD Join (on-prem domain): Configure Azure AD Connect seamless SSO, "
                        "   enable hybrid join in AAD Connect, assign Computer GPO. "
                        "3. After join: create CA policies requiring MFA + compliant device for M365/Azure access. "
                        "Without Azure AD integration, cloud PHI access cannot be controlled by CA policies."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class RemoteManagementSecurityCheck(BaseCheck):
    """
    RMT-03: Verify remote management tools (PSRemoting, RMM agents) are secured.
    RMM tools used by MSPs are prime targets — attackers compromise RMMs to
    push ransomware across all managed clients simultaneously.
    """
    check_id = "RMT-03"
    check_name = "Remote Management Tool Security"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check WinRM/PSRemoting listener
            winrm_listeners = context.winrm.run_ps(
                target.hostname,
                r"Get-WSManInstance -ResourceURI winrm/config/Listener "
                r"-SelectorSet @{Address='*';Transport='HTTP'} "
                r"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Transport"
            )

            # Detect RMM agents installed (common MSP RMMs)
            rmm_agents = context.winrm.run_ps(
                target.hostname,
                r"$rmms = @("
                r"  'ConnectWise Automate', 'LabTech', 'Kaseya', 'N-central', "
                r"  'NinjaRMM', 'Atera', 'Syncro', 'Datto', 'Pulseway', "
                r"  'TeamViewer', 'AnyDesk', 'LogMeIn', 'Splashtop', 'RemotePC'"
                r"); "
                r"$found = Get-Service -ErrorAction SilentlyContinue | "
                r"Where-Object { $name = $_.DisplayName; $rmms | Where-Object { $name -like \"*$_*\" } }; "
                r"if ($found) { ($found | Select-Object -ExpandProperty DisplayName) -join ',' } else { '' }"
            )

            # Check for TeamViewer unattended access (common attack target)
            tv_unattended = context.winrm.run_ps(
                target.hostname,
                r"$tv = Get-Process -Name TeamViewer -ErrorAction SilentlyContinue; "
                r"if ($tv) { "
                r"  $key = (Get-ItemProperty 'HKLM:\SOFTWARE\TeamViewer' "
                r"  -Name ClientID -ErrorAction SilentlyContinue).ClientID; "
                r"  \"Running,ID=$key\" "
                r"} else { 'Not running' }"
            )

            # Check PowerShell remoting state
            psremoting = context.winrm.run_ps(
                target.hostname,
                r"(Get-Item WSMan:\localhost\Service\AllowRemoteAccess "
                r"-ErrorAction SilentlyContinue).Value"
            )

            # Check if PSRemoting is restricted to HTTPS
            http_listener = winrm_listeners.strip().lower()
            http_only = "http" in http_listener and "https" not in http_listener

            rmm_list = [r.strip() for r in rmm_agents.strip().split(",") if r.strip()]
            tv_running = "Running" in tv_unattended

            evidence = {
                "winrm_transport": winrm_listeners.strip() or "none",
                "rmm_agents_detected": rmm_list[:5],
                "teamviewer_status": tv_unattended.strip()[:100],
                "psremoting_enabled": psremoting.strip(),
                "http_only_winrm": http_only,
            }

            issues = []
            if http_only:
                issues.append("WinRM/PSRemoting using HTTP (unencrypted) — switch to HTTPS")
            if tv_running:
                issues.append("TeamViewer is actively running — ensure access controls and MFA are configured")

            if not issues:
                return self._pass(
                    target,
                    details=f"Remote management appears secured. RMM agents: {', '.join(rmm_list) or 'none detected'}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Remote management security issues: {'; '.join(issues)}",
                    remediation=(
                        "Secure remote management tools: "
                        "1. WinRM HTTPS only: winrm set winrm/config/service '@{AllowUnencrypted=\"false\"}'. "
                        "   Create HTTPS listener: New-WSManInstance -ResourceURI winrm/config/Listener "
                        "   -SelectorSet @{Address=\"*\";Transport=\"HTTPS\"} "
                        "   -ValueSet @{Hostname=\"server.domain.com\";CertificateThumbprint=\"<thumbprint>\"}. "
                        "2. TeamViewer: Enable 2FA, set Access Control to 'Confirm all', disable unattended access if not needed. "
                        "3. RMM agents: Ensure RMM platform enforces MFA for all technician accounts. "
                        "4. Restrict RMM agents via firewall to known MSP IP ranges only."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class EntraIdSyncCheck(BaseCheck):
    """
    RMT-04: Verify Azure AD Connect (Entra Connect) is syncing and healthy.
    Stale or broken AAD sync means on-prem AD changes (disabled accounts, password resets)
    don't propagate to cloud — ex-employees retain M365/cloud PHI access.
    """
    check_id = "RMT-04"
    check_name = "Azure AD Connect (Entra Connect) Sync Health"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.HIGH
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check if AAD Connect is installed
            aad_connect = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Azure* "
                r"-ErrorAction SilentlyContinue | "
                r"Where-Object { $_.DisplayName -like '*Azure AD Connect*' -or "
                r"  $_.DisplayName -like '*Entra Connect*' } | "
                r"Select-Object DisplayName,DisplayVersion | ConvertTo-Json"
            )

            # Check ADSync service
            adsync_service = context.winrm.run_ps(
                target.hostname,
                r"(Get-Service -Name ADSync -ErrorAction SilentlyContinue).Status"
            )

            # Check last sync time
            last_sync = context.winrm.run_ps(
                target.hostname,
                r"try { "
                r"  Import-Module ADSync -ErrorAction SilentlyContinue; "
                r"  $connectors = Get-ADSyncConnector -ErrorAction SilentlyContinue; "
                r"  if ($connectors) { "
                r"    $aad = $connectors | Where-Object { $_.Type -eq 'Extensible2' }; "
                r"    $aad.LastSyncTime "
                r"  } "
                r"} catch { 'module not available' }"
            )

            # Check sync errors
            sync_errors = context.winrm.run_ps(
                target.hostname,
                r"try { "
                r"  Import-Module ADSync -ErrorAction SilentlyContinue; "
                r"  (Get-ADSyncConnectorRunStatus -ErrorAction SilentlyContinue).Result "
                r"} catch { 'N/A' }"
            )

            aad_installed = bool(aad_connect.strip() and aad_connect.strip() not in ("", "null"))
            adsync_running = adsync_service.strip().lower() == "running"

            evidence = {
                "aad_connect_installed": aad_installed,
                "adsync_service_status": adsync_service.strip() or "not found",
                "last_sync_time": last_sync.strip()[:100] if last_sync.strip() else "unknown",
                "sync_status": sync_errors.strip()[:100] if sync_errors.strip() else "unknown",
            }

            if aad_installed and adsync_running:
                return self._pass(
                    target,
                    details="Azure AD Connect is installed and ADSync service is running. Directory sync active.",
                    evidence=evidence,
                )
            elif aad_installed and not adsync_running:
                return self._fail(
                    target,
                    details=f"Azure AD Connect is installed but ADSync service is {adsync_service.strip() or 'stopped'}. Directory sync may be broken — cloud accounts may be out of sync.",
                    remediation=(
                        "Restart ADSync service and investigate: "
                        "Start-Service ADSync; "
                        "Get-ADSyncConnectorRunStatus — check for errors. "
                        "Common causes: expired service account password, network connectivity to Azure. "
                        "CRITICAL: While sync is broken, disabled/deleted on-prem accounts remain active in M365."
                    ),
                    evidence=evidence,
                )
            else:
                # No AAD Connect — check if org might be cloud-only (acceptable) or broken
                return self._na(
                    target,
                    "Azure AD Connect not detected on this DC. If organization uses M365, verify sync is running on another DC or that cloud-only identity is intentional.",
                )
        except Exception as e:
            return self._error(target, str(e))
