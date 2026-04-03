# HIPAA Network Compliance Scanner -- Architecture Specification

**Version**: 1.0
**Date**: 2026-04-03
**Author**: Senior Architect Agent
**Status**: APPROVED FOR IMPLEMENTATION
**Input Documents**: HIPAA-RESEARCH-2026-04-03.md, CODEBASE-ANALYSIS-2026-04-03.md

---

## 1. System Overview

### 1.1 Component Diagram

```
+=====================================================================+
|                     CLOUD (MSP Portal)                               |
|                                                                      |
|  +-------------------+   +-------------------+   +-----------------+ |
|  |   React/TS/Vite   |   |  FastAPI Backend   |   |  PostgreSQL DB  | |
|  |   Frontend SPA    |<->|  (uvicorn + nginx) |<->|  (encrypted)    | |
|  |                   |   |                    |   |                 | |
|  | - Dashboard       |   | - REST API v1      |   | - msp_orgs      | |
|  | - Agent Mgmt      |   | - WebSocket /ws    |   | - users          | |
|  | - Network Map     |   | - JWT + API Key    |   | - clients        | |
|  | - Scan Results    |   | - Agent Registry   |   | - agents         | |
|  | - Reports         |   | - Scan Scheduler   |   | - scans          | |
|  | - Settings        |   | - Report Generator |   | - findings       | |
|  +-------------------+   +---+------+----+----+   | - hosts          | |
|                              |      |    |        | - audit_log      | |
|                              |      |    |        +-----------------+ |
+==============================|======|====|===========================+
                               |      |    |
                    HTTPS/TLS  |      |    |  HTTPS/TLS
                   (API calls) |      |    | (WebSocket)
                               |      |    |
         +---------------------+      |    +---------------------+
         |                            |                          |
+========|============================|==========================|=====+
|        v         CLIENT NETWORK A   v          CLIENT NETWORK B v    |
|                                                                      |
|  +---------------------------+    +---------------------------+      |
|  |  Collector Agent (Win)    |    |  Collector Agent (Linux)  |      |
|  |  Python Windows Service   |    |  Python systemd daemon    |      |
|  |                           |    |                           |      |
|  | - Enrollment (one-time)   |    | - Enrollment (one-time)   |      |
|  | - Heartbeat (5 min)       |    | - Heartbeat (5 min)       |      |
|  | - Scheduled scans         |    | - Scheduled scans         |      |
|  | - Network discovery       |    | - Network discovery       |      |
|  | - Check execution         |    | - Check execution         |      |
|  | - Result upload           |    | - Result upload           |      |
|  | - Config pull             |    | - Config pull             |      |
|  | - Auto-update             |    | - Auto-update             |      |
|  +-------+---+---+-----------+    +-------+---+---+-----------+      |
|          |   |   |                        |   |   |                  |
|   WinRM  | LDAP |  SNMP            SSH    | SNMP |  HTTP             |
|          |   |   |                        |   |   |                  |
|    +-----+   |   +------+          +------+   |   +------+          |
|    v         v          v          v          v          v          |
| [Windows] [Active   [Switches] [Linux   [Firewalls] [Web         |
| [Servers] Directory] [Routers]  Servers]  [Printers] Mgmt UIs]   |
| [Desktops]           [APs]                                        |
+===================================================================+
```

### 1.2 Data Flow: Collector to Portal to Reports

```
1. ENROLLMENT
   Agent installs -> generates keypair -> POST /api/v1/agents/enroll (one-time token)
   Portal validates token -> stores agent public key -> returns agent_id + config

2. HEARTBEAT (every 5 minutes)
   Agent -> POST /api/v1/agents/{id}/heartbeat (status, uptime, version)
   Portal -> 200 OK + optional command queue (scan-now, update-config, update-agent)

3. SCAN EXECUTION
   Portal schedule triggers OR heartbeat returns scan-now command
   Agent -> Network discovery (nmap ping sweep + port scan)
   Agent -> Per-node check dispatch (WinRM/SSH/SNMP/HTTP based on OS detection)
   Agent -> All checks run via BaseCheck plugin architecture
   Agent -> POST /api/v1/scans/upload (HMAC-signed, gzip compressed)

4. REPORT GENERATION
   User clicks "Generate Report" in portal UI
   Backend -> WeasyPrint renders HTML template with scan data
   Backend -> Returns PDF (executive or technical variant)

5. SCHEDULED REPORTS
   APScheduler cron -> generates report -> emails to configured recipients
```

### 1.3 Network Topology

```
                    INTERNET
                       |
              +--------+--------+
              | Cloud VPS       |
              | (104.248.x.x)  |
              | - nginx :443    |
              | - FastAPI :8000 |
              | - PostgreSQL    |
              +--------+--------+
                       |
          HTTPS/TLS 1.2+ only
                       |
       +---------------+---------------+
       |               |               |
  +----+----+    +-----+-----+   +-----+-----+
  |Client A |    | Client B  |   | Client C  |
  |Agent    |    | Agent     |   | Agent     |
  |10.0.1.x |    | 192.168.x |   | 172.16.x  |
  +---------+    +-----------+   +-----------+
```

All agent-to-portal communication is outbound HTTPS from the client network. No inbound ports needed on client firewalls. The agent polls the portal; the portal never initiates connections to agents.

---

## 2. Collector Agent Design

### 2.1 Windows Service Architecture

The collector agent runs as a Windows service via **pywin32** (`win32serviceutil`). PyInstaller packages the entire Python runtime + dependencies into a single EXE. NSSM is available as a fallback for environments where pywin32 service registration fails.

**Service name**: `HIPAAScannerAgent`
**Display name**: `HIPAA Compliance Scanner Agent`
**Startup type**: Automatic (delayed start)
**Run as**: Local System (needs WinRM/LDAP/network access)
**Log location**: `C:\ProgramData\HIPAAScanner\logs\`
**Config location**: `C:\ProgramData\HIPAAScanner\config.json`

**Internal architecture**:

```
HIPAAScannerAgent (Windows Service)
  |
  +-- AgentCore (main loop)
  |     |
  |     +-- HeartbeatThread (every 5 min, checks command queue)
  |     +-- ScanScheduler (cron-like, reads from config)
  |     +-- UpdateChecker (compares version, downloads new EXE)
  |
  +-- NetworkDiscovery (nmap wrapper)
  |     +-- PingSweep
  |     +-- PortScan
  |     +-- OSDetection
  |
  +-- CheckEngine (existing scanner/engine.py, refactored)
  |     +-- ConnectorFactory (WinRM, SSH, SNMP, HTTP)
  |     +-- CheckRunner (loads BaseCheck plugins, dispatches per node)
  |
  +-- ResultUploader (HTTPS POST, HMAC-signed, gzip)
  +-- ConfigManager (pull config from portal, merge with local)
```

### 2.2 Agent Enrollment Protocol

1. MSP admin generates a one-time enrollment token in the portal UI (POST /api/v1/agents/enroll-token). Token is a 32-byte random hex string, valid for 24 hours, scoped to a specific client_id.

2. During agent installation, the tech enters the enrollment token and portal URL. The agent:
   a. Generates an Ed25519 keypair (stored in `C:\ProgramData\HIPAAScanner\agent.key`)
   b. POST /api/v1/agents/enroll with: `{enrollment_token, public_key, hostname, os_version, agent_version}`
   c. Portal validates token (single-use, not expired, client_id match)
   d. Portal stores agent record: `{agent_id, client_id, public_key, enrolled_at}`
   e. Portal returns: `{agent_id, agent_secret (HMAC key), portal_ca_cert (for pinning), initial_config}`

3. Agent stores agent_id and agent_secret in encrypted local config (DPAPI on Windows, keyring on Linux).

4. All subsequent requests are authenticated via: `Authorization: HMAC-SHA256 agent_id:signature` where signature = HMAC(agent_secret, request_body + timestamp). Timestamp included in `X-Agent-Timestamp` header; portal rejects requests with timestamp skew > 5 minutes.

### 2.3 Heartbeat / Status Reporting

**Interval**: Every 5 minutes (configurable from portal, minimum 1 minute, maximum 60 minutes).

**Request**: POST /api/v1/agents/{id}/heartbeat
```json
{
  "agent_version": "1.2.0",
  "uptime_seconds": 86400,
  "last_scan_at": "2026-04-03T10:00:00Z",
  "last_scan_status": "completed",
  "cpu_percent": 12.5,
  "memory_mb": 256,
  "disk_free_gb": 45.2,
  "discovered_hosts": 34,
  "os": "Windows Server 2022",
  "ip_address": "10.0.1.50"
}
```

**Response**: 200 OK
```json
{
  "status": "ok",
  "commands": [
    {"type": "scan-now", "profile": "full"},
    {"type": "update-config", "config_version": 3}
  ]
}
```

**Command types**: `scan-now`, `update-config`, `update-agent`, `restart`, `disenroll`.

Portal marks agent as "offline" if no heartbeat received for 3x the heartbeat interval (default: 15 minutes).

### 2.4 Scheduled Scan Execution

Schedules are stored in the `scan_schedules` table and pushed to the agent via config. The agent uses APScheduler (already in the Python ecosystem) with a CronTrigger.

**Config example pushed from portal**:
```json
{
  "schedules": [
    {
      "id": "sched-001",
      "cron": "0 2 * * 0",
      "profile": "full",
      "cidr_ranges": ["10.0.1.0/24", "10.0.2.0/24"],
      "enabled": true
    }
  ]
}
```

The agent also accepts on-demand scans via the heartbeat command queue or direct POST /api/v1/agents/{id}/scan from the portal.

### 2.5 Encrypted Upload to Portal

1. Agent serializes scan results to JSON (same format as existing CLI uploader).
2. Gzip compress the JSON payload.
3. Sign: `HMAC-SHA256(agent_secret, gzip_payload + timestamp_header)`.
4. POST /api/v1/scans/upload with headers:
   - `Content-Encoding: gzip`
   - `X-Scanner-API-Key: {agent_id}` (reuse existing header for backward compat)
   - `X-Agent-Signature: {hmac_hex}`
   - `X-Agent-Timestamp: {iso8601}`
5. Portal validates HMAC, decompresses, creates Scan + Host + Finding records.
6. All transport over TLS 1.2+. Agent validates portal certificate against pinned CA cert received during enrollment.

### 2.6 Auto-Update Mechanism

1. Agent checks version via heartbeat response or dedicated GET /api/v1/agents/updates/latest.
2. If newer version available, agent downloads the update package (signed ZIP containing new EXE + manifest).
3. Agent verifies Ed25519 signature of the package against a hardcoded portal signing public key.
4. Agent extracts to staging directory, stops current service, replaces EXE, restarts service.
5. On failed update (service doesn't start within 60 seconds), rolls back to previous EXE.

**Update distribution**: Portal serves update packages from a `/api/v1/agents/updates/{version}` endpoint. MSP admins control rollout (immediate or staged by percentage).

### 2.7 Agent Config Push from Portal

Agent polls GET /api/v1/agents/{id}/config on startup and when heartbeat returns `update-config` command. Config includes:
- Scan schedules (cron expressions)
- CIDR ranges to scan
- Credential references (encrypted, see Section 11)
- Heartbeat interval
- Check profile (which check categories to run)
- Excluded hosts/IPs
- WinRM/SSH port overrides

Config is versioned. Agent stores `config_version` locally and only fetches when portal indicates a newer version.

### 2.8 Linux Daemon Variant

Identical Python codebase, packaged differently:
- **Service manager**: systemd unit file (`hipaa-scanner-agent.service`)
- **Install location**: `/opt/hipaa-scanner/`
- **Config**: `/etc/hipaa-scanner/config.json`
- **Logs**: journald (systemd journal)
- **Key storage**: `/etc/hipaa-scanner/agent.key` (mode 0600, root only)
- **Packaging**: .deb package for Ubuntu/Debian, .rpm for RHEL/CentOS
- **No pywin32 dependency**: conditional imports, OS detection at startup

### 2.9 MSI / Installer Packaging

**Windows**:
- PyInstaller produces single EXE (`hipaa-scanner-agent.exe`)
- WiX Toolset wraps into MSI with:
  - Custom action: prompt for enrollment token + portal URL
  - Service registration (pywin32 or NSSM fallback)
  - Firewall rule: allow outbound HTTPS
  - Start menu shortcut for agent status tray app
- MSI must be **Authenticode code-signed** to avoid AV false positives (prior learning)
- Silent install: `msiexec /i HIPAAScanner.msi ENROLLMENT_TOKEN=xxx PORTAL_URL=https://... /quiet`

**Linux**:
- .deb package with postinst script that prompts for enrollment token
- systemd unit file installed to `/etc/systemd/system/`
- `dpkg -i hipaa-scanner-agent.deb && hipaa-scanner-enroll --token xxx --portal https://...`

### 2.10 Security: Agent Identity and mTLS Option

**Default authentication**: HMAC-SHA256 with agent_secret (simpler, works through proxies).

**Optional mTLS**: For high-security environments, the enrollment flow can issue a client certificate signed by the portal's internal CA. The agent presents this certificate on every TLS connection. This is opt-in per MSP organization because mTLS complicates proxy/inspection environments.

**Agent key protection**:
- Windows: DPAPI encryption for `agent.key` and `agent_secret`
- Linux: File permissions (root:root, 0600) + optional TPM2 binding

---

## 3. Network Discovery Engine

### 3.1 Phase 1: Ping Sweep (Host Discovery)

```python
# Uses nmap (already in scanner dependencies, never called)
import nmap

def discover_hosts(cidr_ranges: list[str]) -> list[DiscoveredHost]:
    nm = nmap.PortScanner()
    targets = " ".join(cidr_ranges)
    # -sn = ping scan only (no port scan), -PE = ICMP echo, --arp-ping for local subnet
    nm.scan(hosts=targets, arguments="-sn -PE --unprivileged")
    hosts = []
    for ip in nm.all_hosts():
        hosts.append(DiscoveredHost(
            ip=ip,
            hostname=nm[ip].hostname(),
            status=nm[ip].state(),
            mac=nm[ip]["addresses"].get("mac", ""),
            vendor=nm[ip].get("vendor", {}).get(mac, "")
        ))
    return hosts
```

**Fallback**: If nmap is not installed on the agent host, fall back to native ICMP ping via `subprocess` (Windows: `ping -n 1 -w 500`, Linux: `ping -c 1 -W 1`). Slower but no dependency.

**ARP discovery**: On local subnets, ARP is more reliable than ICMP (many hosts block ping). Nmap's `-PR` (ARP ping) handles this automatically when the agent is on the same subnet.

### 3.2 Phase 2: Port Scan and OS Detection

```python
def scan_ports(hosts: list[str]) -> dict:
    nm = nmap.PortScanner()
    # -O = OS detection, -sV = service version, top 100 ports
    nm.scan(hosts=" ".join(hosts), arguments="-O -sV --top-ports 100 -T4")
    results = {}
    for ip in nm.all_hosts():
        results[ip] = {
            "os_match": nm[ip].get("osmatch", [{}])[0].get("name", "Unknown"),
            "os_family": classify_os(nm[ip]),  # "windows", "linux", "network_device"
            "open_ports": [(p, nm[ip]["tcp"][p]) for p in nm[ip].get("tcp", {})],
            "services": extract_services(nm[ip])
        }
    return results
```

**OS classification** determines which connector to use:
- Windows -> WinRM connector
- Linux/macOS -> SSH connector
- Network device (Cisco IOS, Junos, FortiOS, etc.) -> SNMP connector
- Web management interface detected -> HTTP connector (supplemental)

### 3.3 Phase 3: Per-Node Check Dispatch

```python
def dispatch_checks(node: DiscoveredHost, os_family: str) -> list[Finding]:
    connector = ConnectorFactory.create(os_family, node.ip, credentials)
    applicable_checks = CheckRegistry.get_checks_for(os_family)
    findings = []
    for check_cls in applicable_checks:
        check = check_cls(connector)
        if check.applies_to(node):
            result = check.run(node)
            findings.append(result)
    return findings
```

### 3.4 CIDR Range Input and AD-Joined Enumeration

**CIDR input**: User specifies ranges in portal UI (e.g., `10.0.1.0/24, 10.0.2.0/24`). Stored in agent config.

**AD-joined enumeration** (existing LDAP connector, preserved):
```python
# Query AD for all computer objects
ldap_filter = "(objectClass=computer)"
# Returns hostname, OS, last logon, OU
# Merge with nmap results for comprehensive inventory
```

**Hybrid mode**: Run both AD enumeration AND nmap ping sweep. AD provides hostnames and organizational context. Nmap provides live status and non-domain-joined devices. Merge by IP/hostname.

### 3.5 Passive Discovery (Future Enhancement)

- SNMP trap listener: agent listens on UDP 162 for traps from managed switches (new devices, link up/down)
- NetBIOS name resolution: `nbtstat -a` scan for Windows workgroup environments
- DHCP lease monitoring: parse DHCP server logs for new leases

These are Phase 5 enhancements. Not required for MVP.

---

## 4. New Scanner Connectors

### 4.1 SSH Connector (Paramiko)

**Library**: `paramiko` (pure Python, well-maintained, async wrapper available)

```python
class SSHConnector:
    def __init__(self, host: str, port: int = 22,
                 username: str = None, password: str = None,
                 key_path: str = None):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Support both password and key-based auth
        connect_kwargs = {"hostname": host, "port": port, "username": username}
        if key_path:
            connect_kwargs["key_filename"] = key_path
        else:
            connect_kwargs["password"] = password
        self.client.connect(**connect_kwargs, timeout=30)

    def run_command(self, command: str, timeout: int = 60) -> CommandResult:
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        return CommandResult(
            exit_code=stdout.channel.recv_exit_status(),
            stdout=stdout.read().decode("utf-8", errors="replace"),
            stderr=stderr.read().decode("utf-8", errors="replace")
        )

    def close(self):
        self.client.close()
```

**Used for**: Linux servers, macOS workstations, some network devices with SSH management.

### 4.2 SNMP v2c/v3 Connector

**Library**: `pysnmp` (pure Python, supports v1/v2c/v3)

```python
class SNMPConnector:
    def __init__(self, host: str, version: str = "v3",
                 community: str = None,       # v2c
                 user: str = None,             # v3
                 auth_key: str = None,         # v3
                 priv_key: str = None,         # v3
                 auth_proto: str = "SHA256",   # v3
                 priv_proto: str = "AES256"):  # v3
        self.host = host
        self.version = version
        # Build credentials based on version
        if version == "v3":
            self.credentials = UsmUserData(user, auth_key, priv_key,
                                           authProtocol=AUTH_PROTOCOLS[auth_proto],
                                           privProtocol=PRIV_PROTOCOLS[priv_proto])
        else:
            self.credentials = CommunityData(community)

    def get(self, oid: str) -> str:
        """GET a single OID value."""
        ...

    def walk(self, oid: str) -> list[tuple[str, str]]:
        """Walk an OID subtree."""
        ...

    def get_bulk(self, oids: list[str]) -> dict[str, str]:
        """Bulk GET multiple OIDs."""
        ...
```

**Common OIDs for HIPAA checks**:
- `1.3.6.1.2.1.1.1.0` -- sysDescr (device type/OS)
- `1.3.6.1.2.1.1.5.0` -- sysName (hostname)
- `1.3.6.1.2.1.1.3.0` -- sysUpTime
- `1.3.6.1.2.1.4.20.1.1` -- ipAddrTable (interfaces)
- `1.3.6.1.4.1.9.9.25.1.1.1.2.3` -- Cisco IOS version
- `1.3.6.1.2.1.2.2.1` -- ifTable (interface status)

**Used for**: Managed switches, routers, firewalls, printers, UPS devices, wireless APs.

### 4.3 HTTP Connector

**Library**: `httpx` (async-capable, already common in Python ecosystems)

```python
class HTTPConnector:
    def __init__(self, base_url: str, auth: tuple = None,
                 verify_ssl: bool = True, timeout: int = 30):
        self.client = httpx.Client(
            base_url=base_url, auth=auth,
            verify=verify_ssl, timeout=timeout
        )

    def get(self, path: str) -> HTTPResponse:
        return self.client.get(path)

    def check_tls(self) -> TLSInfo:
        """Check TLS version, cipher suite, certificate details."""
        ...
```

**Used for**: Checking web management interfaces (firewall admin panels, printer web UIs), verifying TLS configurations on internal services, checking for default credentials on web interfaces.

---

## 5. Complete HIPAA Check Specification

### 5.1 Check Numbering Convention

Checks use a category prefix + sequential number. New checks start after the highest existing ID in each category to avoid conflicts with the 27 existing checks.

### 5.2 Access Controls -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| AC-13 | MFA for Remote Access | Access Control | CRITICAL | 164.312(d), NPRM 164.312(a)(2)(ii) | MFA is required for VPN/remote access | **WinRM**: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowDefaultCredentials` + check for Duo/Azure MFA registry keys at `HKLM:\SOFTWARE\Duo Security` or Azure AD Conditional Access via `Get-MgIdentityConditionalAccessPolicy` | MFA solution detected and enforced for remote access | No MFA detected for remote access methods | Deploy MFA solution (Duo, Azure AD Conditional Access, or equivalent) for all remote access. NPRM will make this mandatory. |
| AC-14 | MFA for Admin Accounts | Access Control | CRITICAL | 164.312(d), NPRM | MFA required for all privileged accounts | **WinRM**: Check Azure AD/Entra ID: `Get-MgIdentityConditionalAccessPolicy \| Where-Object {$_.Conditions.Users.IncludeRoles -contains 'admin'}` OR check Duo: `reg query HKLM\SOFTWARE\Duo Security\DuoCredProv` | MFA enforced for domain admin, local admin groups | Admin accounts can authenticate without MFA | Enable MFA for all accounts in Domain Admins, Enterprise Admins, and local Administrators groups. |
| AC-15 | MFA for ePHI Applications | Access Control | HIGH | 164.312(d), NPRM | MFA on EHR and practice management systems | **WinRM**: Application-specific check -- query registry/config for known EHR systems (Epic, Cerner, Athena, eClinicalWorks) MFA settings | MFA detected on identified ePHI applications | ePHI applications accessible without MFA | Configure MFA on all applications that access ePHI. |
| AC-16 | MFA Method Strength | Access Control | MEDIUM | 164.312(d) | MFA uses strong methods (not SMS-only) | **WinRM**: Check MFA provider registry keys for method type: FIDO2, TOTP, push notification vs. SMS | FIDO2, authenticator app, or hardware token in use | SMS-only MFA configured | Upgrade to phishing-resistant MFA (FIDO2 keys or authenticator apps). SMS is vulnerable to SIM swap attacks. |
| AC-17 | Service Account Password Age | Access Control | HIGH | 164.312(a)(1) | Service accounts have passwords rotated | **WinRM**: `Get-ADServiceAccount -Filter * -Properties PasswordLastSet \| Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-365)}` OR `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties PasswordLastSet` | All service account passwords changed within 365 days | Service accounts with passwords older than 365 days | Implement managed service accounts (gMSA) or rotate service account passwords at least annually. |
| AC-18 | Service Account Least Privilege | Access Control | HIGH | 164.308(a)(4) | Service accounts have minimum needed permissions | **WinRM**: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties MemberOf \| ForEach-Object { $_.MemberOf }` -- check for Domain Admins membership | No service accounts in Domain Admins or Enterprise Admins | Service accounts in high-privilege groups | Remove service accounts from Domain Admins. Use dedicated security groups with minimum required permissions. |
| AC-19 | Shared/Guest Accounts | Access Control | CRITICAL | 164.312(a)(2)(i) | No shared or guest accounts with interactive logon | **WinRM**: `Get-LocalUser \| Where-Object {$_.Name -match 'guest\|shared\|generic\|frontdesk\|reception\|test\|temp' -and $_.Enabled}` + `Get-ADUser -Filter {Enabled -eq $true} -Properties Description \| Where-Object {$_.Name -match 'shared\|generic\|frontdesk'}` | Zero shared/generic/guest accounts enabled | Any matching account with interactive logon enabled | Disable shared accounts. Create individual accounts for each user per HIPAA unique user identification requirement. |

### 5.3 Backup/Contingency -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| BK-01 | Backup Solution Present | Backup | CRITICAL | 164.308(a)(7)(ii)(A) | A backup solution is installed and running | **WinRM**: `Get-Service -Name 'veeam*','acronis*','backup*','wbengine','vss' \| Where-Object {$_.Status -eq 'Running'}` + check for Windows Server Backup: `Get-WBSummary` | At least one backup service running | No backup solution detected | Install and configure an enterprise backup solution (Veeam, Acronis, Windows Server Backup, or equivalent). |
| BK-02 | Recent Backup Exists | Backup | CRITICAL | 164.308(a)(7)(ii)(A) | Backups completed within last 24 hours | **WinRM**: `Get-WBSummary \| Select-Object LastSuccessfulBackupTime` or `Get-WinEvent -LogName 'Veeam Backup' -MaxEvents 1` or check shadow copies: `vssadmin list shadows` | Successful backup within last 24 hours | No backup within 24 hours | Investigate backup failures. Ensure backup jobs are scheduled and completing successfully. |
| BK-03 | Backup Encryption | Backup | HIGH | 164.312(a)(2)(iv) | Backups are encrypted at rest | **WinRM**: Check backup software configuration for encryption flags. Veeam: `Get-VBRBackupRepository \| Select-Object Name, @{N='Encrypted';E={$_.Options.Encryption.Enabled}}`. Windows Backup: Check if backup target is BitLocker-encrypted volume. | Backup encryption enabled | Backups stored unencrypted | Enable encryption on all backup jobs. Use AES-256 encryption. HIPAA requires ePHI backups to be encrypted. |
| BK-04 | Backup Offsite/Replication | Backup | HIGH | 164.308(a)(7)(ii)(B) | Backups are replicated offsite or to cloud | **WinRM**: Check for cloud backup agent: `Get-Service -Name '*cloud*backup*','*azure*backup*','*aws*backup*'` or Veeam cloud connect: `Get-VBRCloudProvider` | Offsite or cloud backup detected | All backups local only | Configure offsite backup replication or cloud backup. Protect against site-level disasters per HIPAA contingency planning requirements. |
| BK-05 | Backup Restore Test | Backup | HIGH | 164.308(a)(7)(ii)(D) | Backup restore has been tested | **Policy check**: Check for restore test documentation. **WinRM supplemental**: `Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Backup'] and EventID=4]]" -MaxEvents 5` for recent restore events. | Evidence of restore test within last 12 months | No restore test evidence | Perform and document a backup restore test at least annually. HIPAA requires testing of contingency plans. |

### 5.4 Email Security -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| EM-01 | SPF Record | Email Security | HIGH | 164.312(e)(1) | SPF record exists for email domain | **SSH/HTTP**: `dig TXT {domain} +short` or `nslookup -type=TXT {domain}` -- parse for `v=spf1` | Valid SPF record exists with `-all` or `~all` | No SPF record or `+all` (allow all) | Configure SPF DNS record to prevent email spoofing. Use `-all` (hard fail) for strictest protection. |
| EM-02 | DKIM Configured | Email Security | HIGH | 164.312(e)(1) | DKIM signing active for email domain | **SSH/HTTP**: `dig TXT {selector}._domainkey.{domain}` -- common selectors: `google`, `selector1`, `default` | DKIM public key record found | No DKIM record found | Configure DKIM signing for your email domain to ensure email integrity and prevent spoofing. |
| EM-03 | DMARC Record | Email Security | HIGH | 164.312(e)(1) | DMARC policy exists for email domain | **SSH/HTTP**: `dig TXT _dmarc.{domain}` -- parse for `v=DMARC1` | DMARC record with `p=quarantine` or `p=reject` | No DMARC record or `p=none` without monitoring | Configure DMARC with enforcement policy (quarantine or reject) to prevent email spoofing and phishing. |
| EM-04 | Email TLS Enforced | Email Security | CRITICAL | 164.312(e)(2)(ii) | TLS required for email transmission | **SSH/HTTP**: Test SMTP STARTTLS: connect to MX on port 25, issue EHLO, check for STARTTLS. Parse MTA-STS record: `dig TXT _mta-sts.{domain}` | TLS enforced (MTA-STS or STARTTLS required) | Email can be sent/received without TLS | Enable mandatory TLS for email. Configure MTA-STS policy. ePHI transmitted via email MUST be encrypted per HIPAA. |
| EM-05 | Email Encryption for ePHI | Email Security | CRITICAL | 164.312(e)(2)(ii) | ePHI email uses encryption beyond opportunistic TLS | **Policy check**: Verify email encryption gateway/solution (Virtru, Zix, Proofpoint, M365 OME) | Dedicated email encryption solution in place | No email encryption beyond basic TLS | Deploy email encryption solution for messages containing ePHI. Basic TLS is not sufficient for ePHI content. |

### 5.5 USB / Removable Media -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| RM-01 | USB Storage Blocked | Removable Media | HIGH | 164.310(d)(1) | USB mass storage is blocked or restricted | **WinRM**: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start` (value 4 = disabled) + GPO: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Name Deny_All` | USB storage disabled or policy-controlled | USB storage unrestricted | Block USB mass storage via Group Policy or endpoint protection. HIPAA requires controls on removable media containing ePHI. |
| RM-02 | Autorun Disabled | Removable Media | MEDIUM | 164.308(a)(5)(ii)(B) | Autorun/autoplay disabled for removable media | **WinRM**: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun` (value 255 = all disabled) | Autorun disabled for all drive types | Autorun enabled | Disable autorun via Group Policy to prevent malicious code execution from removable media. |
| RM-03 | Removable Media Encryption | Removable Media | HIGH | 164.312(a)(2)(iv) | BitLocker To Go or equivalent required for USB drives | **WinRM**: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name RDVDenyWriteAccess` (1 = deny write to non-encrypted) | Write access denied to non-encrypted removable media | Unencrypted removable media writable | Enable "Deny write access to removable drives not protected by BitLocker" via Group Policy. |

### 5.6 VPN Configuration -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| NS-05 | VPN Solution Present | Network Security | HIGH | 164.312(e)(1) | VPN solution available for remote access | **WinRM**: `Get-Service -Name 'RasMan','IKEEXT','OpenVPNService','FortiClient*','PanGPS*','CiscoAnyConnect*' \| Where-Object {$_.Status -eq 'Running'}` + check for VPN adapters: `Get-NetAdapter \| Where-Object {$_.InterfaceDescription -match 'VPN\|Tunnel\|TAP'}` | VPN service or client detected | No VPN solution detected | Deploy a VPN solution for all remote access to the network. Direct RDP/SMB over the internet is prohibited. |
| NS-06 | VPN Encryption Standard | Network Security | CRITICAL | 164.312(e)(2)(ii) | VPN uses AES-256 encryption | **WinRM**: `Get-VpnConnection \| Select-Object Name, EncryptionLevel, AuthenticationMethod` + check IKEv2: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters'` | AES-256 encryption with IKEv2 or OpenVPN | PPTP, L2TP without IPsec, or weak encryption | Configure VPN with AES-256 encryption using IKEv2 or OpenVPN protocol. Disable PPTP and other weak protocols. |
| NS-07 | VPN MFA Required | Network Security | CRITICAL | 164.312(d) | VPN requires multi-factor authentication | **WinRM**: Check for RADIUS/NPS with MFA: `Get-NpsRadiusClient` or Duo plugin: `reg query HKLM\SOFTWARE\Duo Security` | MFA enforced on VPN authentication | VPN allows password-only auth | Enable MFA for VPN connections. Use RADIUS integration with Duo, Azure MFA, or equivalent. |
| NS-08 | Split Tunneling Policy | Network Security | HIGH | 164.312(e)(1) | Split tunneling disabled or ePHI traffic forced through tunnel | **WinRM**: `Get-VpnConnection \| Select-Object Name, SplitTunneling` (should be False) | Split tunneling disabled or ePHI-routes forced | Split tunneling enabled with no route enforcement | Disable split tunneling or configure forced tunneling for ePHI network segments. |

### 5.7 Wireless Security -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| NS-09 | Wireless Encryption Standard | Network Security | CRITICAL | 164.312(e)(2)(ii) | WiFi uses WPA2-Enterprise or WPA3 | **SNMP** (wireless controller): OID `1.3.6.1.4.1.14179.2.1.1.1.30` (Cisco WLC encryption type). **WinRM** (client check): `netsh wlan show profiles \| ForEach-Object { netsh wlan show profile name="$_" key=clear }` -- parse Authentication/Cipher | WPA2-Enterprise (AES-CCMP) or WPA3 | WEP, WPA-PSK, or open network | Configure WPA2-Enterprise with RADIUS/802.1X or WPA3 for all clinical wireless networks. |
| NS-10 | 802.1X Authentication | Network Security | HIGH | 164.312(a)(1) | RADIUS/802.1X for wireless auth on clinical network | **SNMP**: Query RADIUS server association on wireless controller. **WinRM**: `netsh wlan show profiles` -- check for EAP type | 802.1X/EAP authentication configured | Pre-shared key (PSK) authentication | Deploy RADIUS server and configure 802.1X for wireless network authentication. |
| NS-11 | Guest Network Isolation | Network Security | CRITICAL | 164.312(a)(1) | Guest WiFi isolated from clinical network | **SNMP**: Query VLAN assignments on wireless controller. Check for inter-VLAN routing between guest and clinical VLANs via `show ip route` equivalent | Guest SSID on separate VLAN with no route to ePHI | Guest network can reach clinical systems | Isolate guest WiFi on a separate VLAN with firewall rules blocking access to clinical network segments. |
| NS-12 | Rogue AP Detection | Network Security | MEDIUM | 164.312(a)(1) | Wireless IDS or rogue AP scanning | **SNMP**: Query wireless controller for rogue AP detection feature: Cisco `1.3.6.1.4.1.14179.2.1.8` | Rogue AP detection enabled | No rogue AP detection | Enable rogue AP detection on wireless controller or deploy wireless IDS. |

### 5.8 Certificate Expiration -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| EN-05 | SSL/TLS Certificate Expiry | Encryption | CRITICAL | 164.312(e)(2)(ii) | Certificates not expired or expiring soon | **HTTP**: Connect to each HTTPS service, extract cert expiry: `ssl.get_server_certificate((host, 443))` then `x509.load_pem_x509_certificate()` | Certificate valid for > 30 days | Certificate expired or expiring within 30 days | Renew SSL/TLS certificates before expiration. Configure automated renewal (Let's Encrypt/ACME). |
| EN-06 | Internal CA Certificate Expiry | Encryption | HIGH | 164.312(e) | Internal CA certificates not expiring | **WinRM**: `Get-ChildItem Cert:\LocalMachine\CA \| Where-Object {$_.NotAfter -lt (Get-Date).AddDays(90)}` | No CA certs expiring within 90 days | CA certificate expiring within 90 days | Renew internal Certificate Authority certificates. CA expiration will invalidate all issued certificates. |
| EN-07 | Self-Signed Certificate Detection | Encryption | HIGH | 164.312(e)(2)(ii) | No self-signed certs on production ePHI services | **HTTP**: Check cert issuer == subject for external-facing services | No self-signed certs on ePHI-facing services | Self-signed certificate on ePHI service | Replace self-signed certificates with certificates from a trusted CA. |
| EN-08 | Weak Certificate Algorithm | Encryption | HIGH | 164.312(e)(2)(ii) | Certificates use SHA-256+ signature | **HTTP**: Check cert signature algorithm: `cert.signature_hash_algorithm` | SHA-256 or stronger | SHA-1 or MD5 signature algorithm | Reissue certificates with SHA-256 or SHA-384 signature algorithm. SHA-1 is deprecated and insecure. |

### 5.9 SIEM / Centralized Logging -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| AU-05 | Centralized Log Collection | Audit Controls | HIGH | 164.312(b) | Logs forwarded to central SIEM/syslog | **WinRM**: Check for Sysmon: `Get-Service Sysmon*`. Check for WEF: `Get-WinEvent -ListLog ForwardedEvents`. Check for agents: `Get-Service -Name 'SplunkForwarder','nxlog','winlogbeat','fluentd','ossec'` | Log forwarding agent or WEF configured | No centralized log collection | Deploy centralized log collection (Splunk, Elastic, Graylog, or Windows Event Forwarding). HIPAA requires audit logs be protected and reviewed. |
| AU-06 | Log Retention Configuration | Audit Controls | HIGH | 164.316(b)(2)(i) | Logs retained for minimum required period | **WinRM**: Check SIEM retention policy OR `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name Retention, MaxSize` | Security log retention >= 180 days (on SIEM) or >= 200MB local with archival | Logs overwritten before archival | Configure log retention: 90+ days searchable in SIEM, archived for 6 years per HIPAA documentation requirements. |
| AU-07 | Security Event Alerting | Audit Controls | MEDIUM | 164.312(b) | Automated alerts for critical security events | **WinRM**: Check for scheduled tasks monitoring events: `Get-ScheduledTask \| Where-Object {$_.TaskName -match 'alert\|monitor\|security'}`. Check SIEM agent config for alerting. | Automated alerting configured for failed logins, privilege escalation | No automated security alerting | Configure alerts for: failed login (>5 attempts), privilege escalation, after-hours ePHI access, account lockout. |
| AU-08 | Audit Log Access Restricted | Audit Controls | HIGH | 164.312(b) | Only authorized users can access/modify logs | **WinRM**: `Get-Acl 'C:\Windows\System32\winevt\Logs\Security.evtx' \| Select-Object -ExpandProperty Access` | Only SYSTEM, Administrators, and Event Log Readers have access | General users can read/modify security logs | Restrict security log access to authorized security personnel only. |

### 5.10 Browser Security -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| BS-01 | Browser Auto-Update | Browser Security | MEDIUM | 164.308(a)(1) | Browsers configured to auto-update | **WinRM**: Chrome: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Update' -Name UpdateDefault` (1=auto). Edge: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name UpdateDefault` | Auto-update enabled or managed update | Auto-update disabled with no managed deployment | Enable browser auto-update or deploy updates via WSUS/SCCM within 30 days of release. |
| BS-02 | Browser Password Manager | Browser Security | MEDIUM | 164.312(a)(1) | Browser password saving disabled for ePHI apps | **WinRM**: Chrome: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name PasswordManagerEnabled` (0=disabled). Edge: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name PasswordManagerEnabled'` | Password manager disabled via policy | Browser password saving enabled on ePHI workstations | Disable browser password saving via Group Policy. Use a dedicated password manager instead. |
| BS-03 | TLS Settings | Browser Security | HIGH | 164.312(e) | Browser does not allow TLS < 1.2 | **WinRM**: Check SChannel: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name Enabled` (should be 0 or absent) | TLS 1.0 and 1.1 disabled at OS level | TLS 1.0 or 1.1 enabled | Disable TLS 1.0 and TLS 1.1 via registry/GPO. Enforce TLS 1.2 minimum. |
| BS-04 | Pop-up and Extension Policy | Browser Security | LOW | 164.308(a)(5)(ii)(B) | Browser extensions managed via policy | **WinRM**: Chrome: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name ExtensionInstallBlocklist` | Extension whitelist or blocklist enforced | No extension management policy | Configure browser extension management via Group Policy to prevent malicious extension installation. |

### 5.11 Application Whitelisting -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| AS-01 | AppLocker / WDAC Enabled | App Security | HIGH | 164.308(a)(5)(ii)(B) | Application whitelisting solution deployed | **WinRM**: `Get-AppLockerPolicy -Effective \| Select-Object -ExpandProperty RuleCollections` OR `Get-CimInstance -Namespace root/Microsoft/Windows/CI -ClassName MSFT_CI_POLICY` | AppLocker or WDAC policy configured with rules | No application whitelisting | Deploy AppLocker or Windows Defender Application Control (WDAC) to prevent unauthorized software execution. |
| AS-02 | AppLocker Enforcement Mode | App Security | HIGH | 164.308(a)(5)(ii)(B) | AppLocker in enforce mode (not just audit) | **WinRM**: `Get-AppLockerPolicy -Effective \| ForEach-Object { $_.RuleCollections } \| Select-Object RuleCollectionType, EnforcementMode` | EnforcementMode = Enabled (enforce) | EnforcementMode = AuditOnly | Switch AppLocker from audit mode to enforce mode after validating rules. |
| AS-03 | Unauthorized Software Detection | App Security | MEDIUM | 164.308(a)(1) | No unauthorized applications running | **WinRM**: `Get-Process \| Select-Object Name, Path \| Sort-Object -Unique` -- compare against known-good software baseline | Only authorized applications running | Unauthorized applications detected (P2P, remote access tools, crypto miners) | Remove unauthorized software. Maintain an approved software list and enforce via application whitelisting. |

### 5.12 Database Encryption -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| EN-09 | SQL Server TDE | Encryption | CRITICAL | 164.312(a)(2)(iv) | SQL Server databases use Transparent Data Encryption | **WinRM**: `Invoke-Sqlcmd -Query "SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4" -ServerInstance localhost` | All user databases have is_encrypted = 1 | User databases without TDE enabled | Enable Transparent Data Encryption on all SQL Server databases containing ePHI. |
| EN-10 | SQL Server TLS Connection | Encryption | HIGH | 164.312(e)(2)(ii) | SQL Server requires encrypted connections | **WinRM**: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib' -Name ForceEncryption` | ForceEncryption = 1 | ForceEncryption = 0 or absent | Enable ForceEncryption on SQL Server to require TLS for all client connections. |
| EN-11 | Database Backup Encryption | Encryption | HIGH | 164.312(a)(2)(iv) | Database backups are encrypted | **WinRM**: `Invoke-Sqlcmd -Query "SELECT bs.database_name, bmf.is_encrypted FROM msdb.dbo.backupset bs JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id ORDER BY bs.backup_finish_date DESC" -ServerInstance localhost` | Recent backups show is_encrypted = 1 | Unencrypted database backups | Enable backup encryption in SQL Server backup jobs using AES-256 and a certificate or asymmetric key. |

### 5.13 Physical Safeguards -- Policy Document Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| PS-01 | Workstation Policy via GPO | Physical | HIGH | 164.310(b) | Workstation configuration enforced technically | **WinRM**: `gpresult /R /SCOPE COMPUTER` -- parse for applied GPOs | GPOs applied for screen lock, USB, software restriction | No GPOs applied | Configure Group Policy Objects to enforce workstation security policies (screen lock, USB control, software restrictions). |
| PS-02 | Asset Inventory | Physical | HIGH | 164.310(d)(1), NPRM | Hardware asset inventory maintained | **Policy check**: Request asset inventory document. **WinRM supplemental**: `Get-ADComputer -Filter * -Properties * \| Measure-Object` to count domain-joined vs. documented | Asset inventory current and matches network discovery | No asset inventory or significant discrepancies | Maintain a complete hardware asset inventory. Cross-reference with network discovery results. NPRM will make this mandatory. |
| PS-03 | Media Disposal Policy | Physical | HIGH | 164.310(d)(2) | Secure media disposal process documented | **Policy check**: Request certificate of destruction documentation or data wiping policy | Documented media disposal with certificates of destruction | No evidence of secure media disposal | Implement secure media disposal using NIST 800-88 guidelines. Maintain certificates of destruction. |
| PS-04 | Facility Access Controls | Physical | MEDIUM | 164.310(a)(1) | Physical access controls documented and enforced | **Policy check**: Request facility security documentation (badge access, visitor logs, camera systems) | Documented physical access controls | No documented physical access controls | Document and enforce physical access controls: badge readers, visitor logs, camera surveillance for areas with ePHI systems. |
| PS-05 | Workstation Positioning | Physical | LOW | 164.310(c) | ePHI workstations positioned to prevent unauthorized viewing | **Policy check**: Request workstation placement assessment or privacy screen deployment records | Privacy screens deployed or workstations positioned to prevent shoulder surfing | No evidence of workstation positioning assessment | Deploy privacy screens on workstations in public areas. Position monitors away from patient/visitor view. |

### 5.14 Administrative Safeguards -- Policy Document Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| AD-01 | Risk Assessment Current | Administrative | CRITICAL | 164.308(a)(1)(ii)(A) | Risk assessment completed within 12 months | **Policy check**: Request risk assessment document with date | Risk assessment dated within last 12 months | No risk assessment or older than 12 months | Conduct a comprehensive HIPAA risk assessment. This is the #1 OCR enforcement target. |
| AD-02 | Risk Management Plan | Administrative | CRITICAL | 164.308(a)(1)(ii)(B) | Documented risk mitigation plan | **Policy check**: Request risk management plan with identified risks and mitigations | Documented plan addressing identified risks | No risk management plan | Create a risk management plan documenting how each identified risk will be mitigated. |
| AD-03 | Incident Response Plan | Administrative | CRITICAL | 164.308(a)(6) | Documented incident response procedures | **Policy check**: Request IRP document | IRP exists with roles, procedures, contact lists | No incident response plan | Create an incident response plan covering: detection, containment, eradication, recovery, lessons learned. |
| AD-04 | IRP Testing | Administrative | HIGH | 164.308(a)(6) | IRP tested within 12 months | **Policy check**: Request tabletop exercise or drill documentation | Test conducted within 12 months with documented results | No IRP testing evidence | Conduct annual incident response testing (tabletop exercise minimum). Document results and improvements. |
| AD-05 | Security Training Current | Administrative | HIGH | 164.308(a)(5) | Security awareness training within 12 months | **Policy check**: Request training records/completion certificates | All workforce members trained within 12 months | Training not current for all workforce | Conduct annual HIPAA security awareness training for all workforce members. Maintain completion records. |
| AD-06 | Sanction Policy | Administrative | MEDIUM | 164.308(a)(1)(ii)(C) | Documented sanctions for security violations | **Policy check**: Request sanction policy | Sanction policy exists and is communicated to workforce | No sanction policy | Create a sanction policy defining consequences for HIPAA security violations. |
| AD-07 | BAA Inventory | Administrative | CRITICAL | 164.308(b)(1) | All vendors with ePHI access have BAAs | **Policy check**: Request BAA inventory and vendor list | All ePHI vendors have current BAAs | Missing BAAs for ePHI vendors | Execute Business Associate Agreements with all vendors who access, store, or transmit ePHI. |
| AD-08 | Disaster Recovery Plan | Administrative | CRITICAL | 164.308(a)(7) | Documented DR plan with RTO/RPO | **Policy check**: Request DR plan | DR plan exists with defined RTO/RPO, tested within 12 months | No DR plan | Create a disaster recovery plan. NPRM proposes 72-hour recovery requirement. |

### 5.15 Network Device Hardening -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| ND-01 | Default SNMP Community Strings | Network Devices | CRITICAL | 164.312(a)(1) | No default SNMP community strings | **SNMP**: Attempt connect with community strings `public`, `private`, `community` | Connection refused with default strings | Device responds to default community string | Change default SNMP community strings. Migrate to SNMPv3 with authentication and encryption. |
| ND-02 | Switch/Router Firmware Current | Network Devices | HIGH | 164.308(a)(1) | Network device firmware within support lifecycle | **SNMP**: `1.3.6.1.2.1.1.1.0` (sysDescr) to get firmware version, compare against vendor EOL database | Firmware within vendor support and < 2 major versions behind | EOL firmware or severely outdated | Update network device firmware to a supported version. EOL firmware does not receive security patches. |
| ND-03 | SSH Enabled (Telnet Disabled) on Network Devices | Network Devices | CRITICAL | 164.312(e)(2)(ii) | Network devices managed via SSH, not Telnet | **Port scan**: Check port 23 (Telnet) closed, port 22 (SSH) open on network device IPs. **SNMP**: Check line configuration for transport input | SSH enabled, Telnet disabled | Telnet enabled on network device | Disable Telnet management. Enable SSH v2 only for network device administration. |
| ND-04 | Network Device Password Complexity | Network Devices | HIGH | 164.312(a)(1) | Network device has password policy | **SNMP/SSH**: Check for password service (Cisco: `service password-encryption`). Verify enable secret uses type 8 or 9 hash. | Strong password policy configured | Default or weak passwords, type 7 encryption | Configure strong password policies on all network devices. Use type 8/9 password hashing (not type 7). |
| ND-05 | Unused Ports Disabled | Network Devices | MEDIUM | 164.312(a)(1) | Unused switch ports are shutdown | **SNMP**: Walk `1.3.6.1.2.1.2.2.1.7` (ifAdminStatus) and `1.3.6.1.2.1.2.2.1.8` (ifOperStatus). Count ports that are admin up but oper down for extended period | Unused ports in shutdown state | Unused ports left enabled | Shut down unused switch ports to prevent unauthorized physical access. Enable port-security on active ports. |
| ND-06 | Port Security / 802.1X Wired | Network Devices | HIGH | 164.312(a)(1) | Port security or 802.1X on access switch ports | **SNMP**: Check `1.3.6.1.4.1.9.9.315.1.2.1.1.1` (Cisco dot1x) or `1.3.6.1.2.1.164` (IEEE 802.1X MIB) | Port security or 802.1X enabled on access ports | No port security on access ports | Enable port security (MAC address limiting) or 802.1X on switch access ports. |

### 5.16 Linux-Specific Checks -- New Checks

| Check ID | Name | Category | Severity | HIPAA CFR | What It Tests | How to Test | Pass Criteria | Fail Criteria | Remediation |
|----------|------|----------|----------|-----------|---------------|-------------|---------------|---------------|-------------|
| LX-01 | SSH Root Login Disabled | Linux | CRITICAL | 164.312(a)(1) | Root cannot login directly via SSH | **SSH**: `grep -E '^PermitRootLogin' /etc/ssh/sshd_config` | PermitRootLogin no | PermitRootLogin yes or not set | Set `PermitRootLogin no` in `/etc/ssh/sshd_config`. Use sudo for privilege escalation. |
| LX-02 | SSH Password Auth Disabled | Linux | HIGH | 164.312(d) | SSH uses key-based auth, not passwords | **SSH**: `grep -E '^PasswordAuthentication' /etc/ssh/sshd_config` | PasswordAuthentication no (key-based only) | PasswordAuthentication yes | Disable password authentication in SSH. Use key-based authentication only. |
| LX-03 | Firewall Active (iptables/nftables/ufw) | Linux | HIGH | 164.312(a)(1) | Host firewall is running | **SSH**: `systemctl is-active ufw` or `iptables -L -n \| wc -l` or `nft list ruleset \| wc -l` | Firewall active with rules loaded | No firewall or empty ruleset | Enable and configure host firewall (ufw, iptables, or nftables). |
| LX-04 | Unattended Upgrades | Linux | HIGH | 164.308(a)(1) | Automatic security updates enabled | **SSH**: `systemctl is-enabled unattended-upgrades` (Debian/Ubuntu) or `systemctl is-enabled dnf-automatic` (RHEL) | Automatic security updates enabled | No automatic update mechanism | Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/CentOS) for security patches. |
| LX-05 | LUKS Disk Encryption | Linux | CRITICAL | 164.312(a)(2)(iv) | Disk volumes encrypted with LUKS | **SSH**: `lsblk -o NAME,FSTYPE,MOUNTPOINT \| grep crypt` or `dmsetup status \| grep crypt` | System/data partitions LUKS-encrypted | Unencrypted partitions containing ePHI | Enable LUKS full disk encryption. For existing systems, encrypt data partitions or migrate to encrypted volumes. |
| LX-06 | Fail2ban or Equivalent | Linux | MEDIUM | 164.312(a)(1) | Brute-force protection active | **SSH**: `systemctl is-active fail2ban` or `systemctl is-active sshguard` | Brute-force protection service running | No brute-force protection | Install and configure fail2ban to protect against SSH and other brute-force attacks. |
| LX-07 | Audit Framework (auditd) | Linux | HIGH | 164.312(b) | Linux audit framework running | **SSH**: `systemctl is-active auditd` and `auditctl -l \| wc -l` | auditd running with rules loaded | auditd not running or no rules | Enable auditd and configure rules for login events, privilege escalation, and file access to ePHI directories. |
| LX-08 | SELinux/AppArmor Enforcing | Linux | MEDIUM | 164.308(a)(5)(ii)(B) | Mandatory access control enforcing | **SSH**: `getenforce` (SELinux) or `aa-status` (AppArmor) | Enforcing mode | Disabled or permissive | Enable SELinux (enforcing) or AppArmor with profiles for ePHI-related services. |

### 5.17 Check Summary

| Category | Existing Checks | New Checks | Total |
|----------|----------------|------------|-------|
| Access Control | 8 (AC-01..AC-12) | 7 (AC-13..AC-19) | 15 |
| Encryption | 4 (EN-01..EN-04) | 7 (EN-05..EN-11) | 11 |
| Audit Controls | 4 (AU-01..AU-04) | 4 (AU-05..AU-08) | 8 |
| Patch Management | 3 (PM-01..PM-03) | 0 | 3 |
| Network Security | 4 (NS-01..NS-04) | 8 (NS-05..NS-12) | 12 |
| Antivirus | 3 (AV-01..AV-03) | 0 | 3 |
| PHI Discovery | 2 (PHI-01..PHI-02) | 0 | 2 |
| Backup | 0 | 5 (BK-01..BK-05) | 5 |
| Email Security | 0 | 5 (EM-01..EM-05) | 5 |
| Removable Media | 0 | 3 (RM-01..RM-03) | 3 |
| Browser Security | 0 | 4 (BS-01..BS-04) | 4 |
| App Security | 0 | 3 (AS-01..AS-03) | 3 |
| Physical Safeguards | 0 | 5 (PS-01..PS-05) | 5 |
| Administrative | 0 | 8 (AD-01..AD-08) | 8 |
| Network Devices | 0 | 6 (ND-01..ND-06) | 6 |
| Linux | 0 | 8 (LX-01..LX-08) | 8 |
| **TOTAL** | **28** | **73** | **101** |

---

## 6. Database Schema Changes

### 6.1 New Tables

```sql
-- Agent registry: collector agents enrolled from client networks
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    msp_id UUID NOT NULL REFERENCES msp_organizations(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    os_version VARCHAR(255),
    agent_version VARCHAR(50),
    public_key TEXT,                          -- Ed25519 public key (PEM)
    agent_secret_hash VARCHAR(128),           -- HMAC key hash (argon2)
    status VARCHAR(20) DEFAULT 'enrolled',    -- enrolled, online, offline, retired
    last_heartbeat_at TIMESTAMPTZ,
    last_scan_at TIMESTAMPTZ,
    config_version INTEGER DEFAULT 1,
    cpu_percent NUMERIC(5,2),
    memory_mb INTEGER,
    disk_free_gb NUMERIC(10,2),
    discovered_hosts INTEGER DEFAULT 0,
    enrolled_at TIMESTAMPTZ DEFAULT NOW(),
    retired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_agents_client ON agents(client_id);
CREATE INDEX idx_agents_msp ON agents(msp_id);
CREATE INDEX idx_agents_status ON agents(status);

-- Agent enrollment tokens (one-time use)
CREATE TABLE agent_enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    msp_id UUID NOT NULL REFERENCES msp_organizations(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL,         -- SHA-256 hash of the token
    created_by UUID NOT NULL REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_by_agent_id UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_enroll_tokens_hash ON agent_enrollment_tokens(token_hash);

-- Agent config push
CREATE TABLE agent_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    config_version INTEGER NOT NULL,
    config_data JSONB NOT NULL,               -- full config blob
    pushed_by UUID REFERENCES users(id),
    pushed_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ              -- when agent confirmed receipt
);
CREATE INDEX idx_agent_configs_agent ON agent_configs(agent_id);
CREATE UNIQUE INDEX idx_agent_configs_version ON agent_configs(agent_id, config_version);

-- Scan schedules (portal-managed, pushed to agents)
CREATE TABLE scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    msp_id UUID NOT NULL REFERENCES msp_organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,     -- e.g., "0 2 * * 0"
    profile VARCHAR(50) DEFAULT 'full',        -- full, quick, network-only
    cidr_ranges JSONB,                         -- ["10.0.1.0/24", ...]
    enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_schedules_client ON scan_schedules(client_id);
CREATE INDEX idx_schedules_agent ON scan_schedules(agent_id);

-- Network discovery results (pre-scan host inventory)
CREATE TABLE network_discovery_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    ip_address VARCHAR(45) NOT NULL,
    hostname VARCHAR(255),
    mac_address VARCHAR(17),
    vendor VARCHAR(255),
    os_guess VARCHAR(255),
    os_family VARCHAR(50),                    -- windows, linux, network_device, unknown
    open_ports JSONB,                         -- [{port: 22, service: "ssh", version: "..."}]
    status VARCHAR(20) DEFAULT 'discovered',  -- discovered, scanned, unreachable
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_discovery_client ON network_discovery_results(client_id);
CREATE INDEX idx_discovery_ip ON network_discovery_results(ip_address);
CREATE UNIQUE INDEX idx_discovery_client_ip ON network_discovery_results(client_id, ip_address);

-- API keys (per MSP org, supports rotation)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msp_id UUID NOT NULL REFERENCES msp_organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,                -- human-readable label
    key_prefix VARCHAR(8) NOT NULL,            -- first 8 chars for identification
    key_hash VARCHAR(128) NOT NULL,            -- argon2 hash of full key
    scopes JSONB DEFAULT '["scan:upload"]',    -- permission scopes
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_api_keys_msp ON api_keys(msp_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- MSP branding / white-label
CREATE TABLE msp_branding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msp_id UUID NOT NULL REFERENCES msp_organizations(id) ON DELETE CASCADE UNIQUE,
    company_name VARCHAR(255),
    logo_url VARCHAR(512),
    logo_data BYTEA,                          -- inline logo for PDF reports
    primary_color VARCHAR(7) DEFAULT '#1e40af',
    secondary_color VARCHAR(7) DEFAULT '#3b82f6',
    report_header_text VARCHAR(500),
    report_footer_text VARCHAR(500),
    email_from_name VARCHAR(255),
    email_reply_to VARCHAR(255),
    custom_domain VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log (immutable append-only)
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    msp_id UUID NOT NULL REFERENCES msp_organizations(id),
    user_id UUID REFERENCES users(id),
    agent_id UUID REFERENCES agents(id),
    action VARCHAR(100) NOT NULL,             -- e.g., "scan.created", "user.login", "finding.updated"
    resource_type VARCHAR(50),                -- e.g., "scan", "user", "agent", "finding"
    resource_id UUID,
    details JSONB,                            -- action-specific metadata
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_msp ON audit_log(msp_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_user ON audit_log(user_id);
-- Consider partitioning by month for large deployments
```

### 6.2 Table Modifications

```sql
-- Add columns to users table
ALTER TABLE users ADD COLUMN invited_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN invited_by UUID REFERENCES users(id);
ALTER TABLE users ADD COLUMN last_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64);

-- Add columns to hosts table
ALTER TABLE hosts ADD COLUMN agent_id UUID REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE hosts ADD COLUMN mac_address VARCHAR(17);
ALTER TABLE hosts ADD COLUMN os_family VARCHAR(50);          -- windows, linux, network_device
ALTER TABLE hosts ADD COLUMN connector_type VARCHAR(20);      -- winrm, ssh, snmp, http
ALTER TABLE hosts ADD COLUMN discovery_result_id UUID REFERENCES network_discovery_results(id);
ALTER TABLE hosts ADD COLUMN open_ports JSONB;

-- Add columns to scans table
ALTER TABLE scans ADD COLUMN agent_id UUID REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN schedule_id UUID REFERENCES scan_schedules(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN is_scheduled BOOLEAN DEFAULT FALSE;
ALTER TABLE scans ADD COLUMN discovery_phase_completed_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN scan_phase_completed_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN cidr_ranges JSONB;

-- Add columns to msp_organizations
ALTER TABLE msp_organizations ADD COLUMN subscription_tier VARCHAR(50) DEFAULT 'standard';
ALTER TABLE msp_organizations ADD COLUMN max_agents INTEGER DEFAULT 10;
ALTER TABLE msp_organizations ADD COLUMN max_clients INTEGER DEFAULT 50;
```

---

## 7. API Contract (All New Endpoints)

### 7.1 MSP Management

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| POST | `/api/v1/msp/` | Super Admin | `{name, contact_email, subscription_tier}` | `201 {id, name, api_key (plaintext, shown once)}` | Creates MSP org + initial API key |
| GET | `/api/v1/msp/` | Super Admin | -- | `200 [{id, name, client_count, agent_count, is_active}]` | List all MSP orgs |
| PATCH | `/api/v1/msp/{id}` | Super Admin | `{name?, contact_email?, is_active?, max_agents?, max_clients?}` | `200 {updated MSP}` | Update MSP org |
| GET | `/api/v1/msp/{id}/branding` | MSP Admin | -- | `200 {branding config}` | Get white-label config |
| PUT | `/api/v1/msp/{id}/branding` | MSP Admin | `{company_name?, logo_url?, primary_color?, ...}` | `200 {updated branding}` | Update white-label |

### 7.2 User Management

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/users/` | MSP Admin | -- | `200 [{id, email, role, is_active, last_login_at}]` | Filtered by msp_id |
| POST | `/api/v1/users/` | MSP Admin | `{email, role, client_id?, password}` | `201 {user}` | Direct create |
| POST | `/api/v1/users/invite` | MSP Admin | `{email, role, client_id?}` | `201 {invite_token, expires_at}` | Sends invite email |
| PATCH | `/api/v1/users/{id}` | MSP Admin | `{email?, role?, is_active?, client_id?}` | `200 {updated user}` | |
| DELETE | `/api/v1/users/{id}` | MSP Admin | -- | `200 {deactivated}` | Soft-delete (is_active=false) |

### 7.3 API Key Management

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/api-keys/` | MSP Admin | -- | `200 [{id, name, key_prefix, scopes, expires_at, last_used_at, is_active}]` | Never returns full key |
| POST | `/api/v1/api-keys/` | MSP Admin | `{name, scopes?, expires_at?}` | `201 {id, name, key (plaintext, shown ONCE), key_prefix}` | Key shown only at creation |
| DELETE | `/api/v1/api-keys/{id}` | MSP Admin | -- | `200 {revoked}` | Sets is_active=false, records revoked_at |

### 7.4 Agent Management

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/agents/` | MSP User | `?client_id=...&status=...` | `200 [{id, hostname, status, agent_version, last_heartbeat_at, ...}]` | Filtered by msp_id |
| POST | `/api/v1/agents/enroll-token` | MSP Admin | `{client_id}` | `201 {token (plaintext, shown once), expires_at}` | Generates enrollment token |
| POST | `/api/v1/agents/enroll` | Enrollment Token | `{enrollment_token, public_key, hostname, os_version, agent_version}` | `201 {agent_id, agent_secret, portal_ca_cert, initial_config}` | One-time enrollment |
| GET | `/api/v1/agents/{id}` | MSP User | -- | `200 {full agent details}` | |
| POST | `/api/v1/agents/{id}/heartbeat` | Agent HMAC | `{agent_version, uptime_seconds, last_scan_at, ...}` | `200 {status, commands: [...]}` | |
| GET | `/api/v1/agents/{id}/config` | Agent HMAC | `?current_version=N` | `200 {config_version, config_data}` or `304` | Agent pulls config |
| POST | `/api/v1/agents/{id}/scan` | MSP Admin | `{profile?, cidr_ranges?}` | `202 {scan_id, status: "queued"}` | Queues scan-now command |
| DELETE | `/api/v1/agents/{id}` | MSP Admin | -- | `200 {retired}` | Marks agent retired |

### 7.5 Scan Scheduling

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/clients/{id}/schedules` | MSP User | -- | `200 [{schedule}]` | |
| POST | `/api/v1/clients/{id}/schedules` | MSP Admin | `{name, cron_expression, profile, cidr_ranges, agent_id?, enabled}` | `201 {schedule}` | |
| PATCH | `/api/v1/clients/{id}/schedules/{sid}` | MSP Admin | `{name?, cron_expression?, enabled?, ...}` | `200 {updated schedule}` | |
| DELETE | `/api/v1/clients/{id}/schedules/{sid}` | MSP Admin | -- | `204` | |

### 7.6 Network Discovery

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/clients/{id}/discovery` | MSP User | -- | `200 [{discovered host}]` | Latest discovery results |
| POST | `/api/v1/clients/{id}/discovery/run` | MSP Admin | `{cidr_ranges, agent_id}` | `202 {status: "started"}` | Triggers discovery-only (no checks) |

### 7.7 Audit Log

| Method | Path | Auth | Request Body | Response | Notes |
|--------|------|------|-------------|----------|-------|
| GET | `/api/v1/audit-log` | MSP Admin | `?action=...&user_id=...&from=...&to=...&limit=100&offset=0` | `200 {items: [...], total}` | Read-only, no delete |

### 7.8 Fix Existing

| Method | Path | Fix Required |
|--------|------|-------------|
| POST | `/api/v1/auth/refresh` | Remove `raise HTTPException(501)`, implement JWT refresh using httponly cookie |
| POST | `/api/v1/scans/upload` | Fix to create Host records from scan results (currently only creates Scan + Finding) |

### 7.9 WebSocket Endpoint

| Path | Auth | Purpose |
|------|------|---------|
| `/ws/scans/{scan_id}` | JWT (query param `token`) | Real-time scan progress updates: `{phase, hosts_discovered, hosts_scanned, current_host, checks_completed, findings_count}` |

---

## 8. Frontend Pages Required

### 8.1 Settings / Admin Page (`#/settings`)

**Components**:
- `SettingsPage` (tab layout)
  - `OrganizationTab` -- MSP org name, contact info, subscription
  - `UserManagementTab` -- user table, invite modal, role dropdown, deactivate button
  - `APIKeyManagementTab` -- key table (prefix only), generate button (shows key once in modal), revoke button
  - `BrandingTab` -- logo upload, color pickers, report header/footer text
  - `SecurityTab` -- password policy display, MFA enforcement toggle (future)

### 8.2 Agent Management Page (`#/agents`)

**Components**:
- `AgentListPage` -- table of enrolled agents with status indicators (green=online, yellow=stale, red=offline, gray=retired)
  - `AgentStatusBadge` -- real-time status dot
  - `AgentRow` -- hostname, IP, client, version, last heartbeat, last scan, actions dropdown
  - `EnrollAgentModal` -- generates enrollment token, shows install instructions (copy-paste commands)
  - `AgentDetailDrawer` -- full agent details, config editor (JSON), scan history, log viewer
  - `TriggerScanButton` -- immediate scan with profile selector
  - `AgentConfigPushModal` -- edit CIDR ranges, schedule, check profile

### 8.3 Network Discovery Page (`#/clients/{id}/discovery`)

**Components**:
- `DiscoveryPage`
  - `NetworkTopologyMap` -- visual node map (use `react-flow` or `d3-force`) showing discovered hosts by OS type with status indicators
  - `DiscoveryTable` -- sortable/filterable table: IP, hostname, OS, MAC, open ports, last seen, scan status
  - `RunDiscoveryButton` -- triggers discovery-only scan
  - `HostDetailDrawer` -- full details of discovered host, link to scan findings

### 8.4 Reports Page (`#/reports`)

**Components**:
- `ReportsPage`
  - `TrendCharts` -- Recharts line/area charts: overall score over time, category scores over time, findings by severity over time
  - `ReportGeneratorPanel` -- select client, scan(s), report type (executive/technical/trend), generate PDF
  - `ScheduledReportsTable` -- list of automated report schedules (cron, recipients, format)
  - `CreateScheduledReportModal` -- cron builder, email recipient list, format selector
  - `ExportDropdown` -- CSV, Excel, PDF options for current view

### 8.5 Scan Initiation from UI

**Modify existing** `#/scans` page:
- `ScanInitiateButton` -- select client, agent, profile (full/quick/network-only), CIDR override
- `ScanProgressPanel` -- WebSocket-driven real-time progress: discovery phase -> scan phase -> upload phase
  - `ProgressBar` -- overall percentage
  - `PhaseIndicator` -- current phase with count (e.g., "Scanning: 12/34 hosts")
  - `LiveFindingsFeed` -- findings appear as they are generated (critical/high highlighted)

### 8.6 Finding Remediation Workflow

**Modify existing** `#/scans/{id}` page:
- `FindingCard` -- add status workflow buttons: Open -> In Progress -> Remediated -> Verified -> Closed
- `AssigneeDropdown` -- assign finding to user
- `NotesPanel` -- threaded notes/comments on each finding
- `RemediationScriptButton` -- copy remediation PowerShell/bash to clipboard
- `BulkActionToolbar` -- select multiple findings, bulk assign/status change

### 8.7 Host Inventory View (`#/clients/{id}/hosts`)

**Components**:
- `HostInventoryPage`
  - `HostTable` -- all hosts across all scans for this client, deduplicated by IP/hostname
  - `HostScoreCard` -- per-host compliance score, findings by severity
  - `HostHistoryTimeline` -- scan results over time for a single host
  - `HostComparisonView` -- side-by-side comparison of two scan results for same host

---

## 9. Implementation Phases

### Phase 1 -- Critical Fixes (implement first, unblocks everything)

1. **Fix refresh token endpoint**: `backend/app/api/v1/auth.py` -- implement JWT refresh using the httponly cookie. Read the refresh token from cookie, validate expiry, issue new access token.

2. **Fix scan upload to create Host records**: `backend/app/api/v1/scans.py` -- in the `upload_scan` function, iterate through the findings' host data and create/update Host records in the hosts table. Link findings to hosts via host_id.

3. **Add ping sweep before WinRM scanning**: `scanner/hipaa_scanner/engine.py` -- add a `discover_live_hosts()` step using nmap (`python-nmap` already in deps) before the check execution loop. Only scan hosts that respond to ping/ARP.

4. **Fix scoring to use category weights**: `scanner/hipaa_scanner/scoring.py` -- apply the weight dict that already exists in the file but is not used in the score calculation.

5. **Add user management API endpoints**: Create `backend/app/api/v1/users.py` -- CRUD for users (list, create, invite, update, deactivate). Add router to `backend/app/main.py`.

6. **Add API key management endpoints**: Create `backend/app/api/v1/api_keys.py` -- CRUD for API keys (list, generate, revoke). Hash keys with argon2 before storage. Add `api_keys` table migration.

7. **Add audit log middleware**: Create `backend/app/middleware/audit.py` -- FastAPI middleware that logs all mutating requests (POST/PATCH/PUT/DELETE) to the audit_log table. Add `audit_log` table migration.

8. **Run Alembic migrations**: Create migration for all new tables (agents, agent_enrollment_tokens, agent_configs, scan_schedules, network_discovery_results, api_keys, msp_branding, audit_log) and table modifications.

### Phase 2 -- Collector Agent MVP

1. **Create agent package structure**: `scanner/hipaa_scanner/agent/` with:
   - `__init__.py`
   - `core.py` -- main AgentCore class (heartbeat loop, command dispatch)
   - `enrollment.py` -- enrollment protocol implementation
   - `config_manager.py` -- local config storage, merge with portal config
   - `service_win.py` -- Windows service wrapper (pywin32)
   - `service_linux.py` -- systemd integration
   - `updater.py` -- auto-update logic

2. **Add agent enrollment endpoints**: Create `backend/app/api/v1/agents.py` -- enrollment token generation, agent enrollment, heartbeat, config push, scan trigger. Add router to main.

3. **Implement HMAC authentication middleware**: Create `backend/app/auth/agent_auth.py` -- validate HMAC-SHA256 signatures on agent requests. Add as dependency to agent endpoints.

4. **Implement heartbeat with command queue**: Agent sends status, portal responds with pending commands (scan-now, update-config). Store pending commands in Redis or in-memory queue (start with DB-backed for simplicity).

5. **Implement network discovery in agent**: Refactor `scanner/hipaa_scanner/engine.py` to use nmap for ping sweep + port scan + OS detection. Store results in network_discovery_results table via upload.

6. **Implement scan result upload from agent**: Reuse existing `scanner/hipaa_scanner/uploader.py` with HMAC signing added. Ensure Host records are created.

7. **Build Windows MSI installer**: Create `installer/` directory with WiX manifest. PyInstaller spec file for single EXE. Batch script for building.

8. **Build Linux .deb package**: Create `installer/linux/` with debian packaging files (control, postinst, prerm, systemd unit).

### Phase 3 -- New HIPAA Checks (73 new checks)

**Batch 1 -- WinRM checks (highest value, uses existing connector)**:
1. AC-13 through AC-19 (MFA, service accounts, shared accounts) -- `scanner/hipaa_scanner/checks/access_controls.py`
2. BK-01 through BK-05 (backup) -- create `scanner/hipaa_scanner/checks/backup.py`
3. RM-01 through RM-03 (USB/removable media) -- create `scanner/hipaa_scanner/checks/removable_media.py`
4. NS-05 through NS-08 (VPN) -- add to `scanner/hipaa_scanner/checks/network_security.py`
5. BS-01 through BS-04 (browser) -- create `scanner/hipaa_scanner/checks/browser_security.py`
6. AS-01 through AS-03 (AppLocker) -- create `scanner/hipaa_scanner/checks/app_security.py`
7. EN-09 through EN-11 (database encryption) -- add to `scanner/hipaa_scanner/checks/encryption.py`
8. AU-05 through AU-08 (SIEM/logging) -- add to `scanner/hipaa_scanner/checks/audit_controls.py`
9. PS-01 (GPO enforcement) -- create `scanner/hipaa_scanner/checks/physical.py`

**Batch 2 -- SSH connector + Linux checks**:
1. Create `scanner/hipaa_scanner/connectors/ssh_connector.py` (Paramiko)
2. LX-01 through LX-08 -- create `scanner/hipaa_scanner/checks/linux.py`

**Batch 3 -- SNMP connector + Network device checks**:
1. Create `scanner/hipaa_scanner/connectors/snmp_connector.py` (pysnmp)
2. ND-01 through ND-06 -- create `scanner/hipaa_scanner/checks/network_devices.py`
3. NS-09 through NS-12 (wireless) -- add to network_security.py or network_devices.py

**Batch 4 -- HTTP connector + certificate/email checks**:
1. Create `scanner/hipaa_scanner/connectors/http_connector.py` (httpx)
2. EN-05 through EN-08 (certificate checks) -- add to encryption.py
3. EM-01 through EM-05 (email security) -- create `scanner/hipaa_scanner/checks/email_security.py`

**Batch 5 -- Policy/document checks (semi-automated)**:
1. PS-02 through PS-05, AD-01 through AD-08 -- create `scanner/hipaa_scanner/checks/policy_checks.py`
2. These require user attestation via portal UI (checkbox + document upload)

### Phase 4 -- Full Portal UI

1. **Settings/Admin page**: `frontend/src/pages/SettingsPage.tsx` with tab components
2. **Agent Management page**: `frontend/src/pages/AgentsPage.tsx` with enrollment modal
3. **Network Discovery page**: `frontend/src/pages/DiscoveryPage.tsx` with topology visualization
4. **Reports page**: `frontend/src/pages/ReportsPage.tsx` with trend charts (Recharts)
5. **Scan initiation from UI**: Modify `frontend/src/pages/ScansPage.tsx` -- add initiate button, progress panel
6. **WebSocket integration**: `frontend/src/hooks/useWebSocket.ts` for real-time scan progress
7. **Finding remediation workflow**: Modify `frontend/src/pages/ScanDetailPage.tsx` -- status workflow, assignment
8. **Host inventory view**: `frontend/src/pages/HostsPage.tsx`
9. **Router migration**: Switch from hash routing to TanStack Router (already in package.json)

### Phase 5 -- Commercial Readiness

1. **White-label / MSP branding**: Portal reads msp_branding table, applies colors/logo throughout UI and PDF reports
2. **Scheduled reports**: APScheduler in backend generates reports on cron, emails via SMTP
3. **Email delivery**: Configure SMTP settings per MSP, use `aiosmtplib` for async email sending
4. **CSV/Excel export**: Add export endpoints using `openpyxl` for Excel, stdlib `csv` for CSV
5. **Compliance certificate**: Generate a one-page PDF certificate for clients who pass all CRITICAL checks
6. **HIPAA Risk Assessment document**: Generate a structured risk assessment PDF from scan results
7. **Agent auto-update system**: Portal serves signed update packages, agent downloads and installs
8. **Billing integration hooks**: API endpoints for usage metering (agents, scans, clients per MSP)

---

## 10. Technology Decisions

### TD-01: Agent-to-Portal Communication

**Decision**: HTTP polling via heartbeat endpoint
**Rationale**: Works through corporate firewalls and proxies without special configuration. Agents only make outbound HTTPS requests. No inbound ports required on client networks. WebSocket or gRPC would require persistent connections that may be blocked by firewalls/proxies and complicate NAT traversal.
**Alternatives considered**:
- WebSocket: Better latency for commands, but requires persistent connection through firewalls. Rejected for agent communication.
- gRPC: Efficient binary protocol, but adds complexity (protobuf definitions, HTTP/2 requirement) and may be blocked by HTTP-inspecting proxies. Rejected.
**WebSocket is used** for portal UI scan progress (browser to server, same-origin, no firewall issues).

### TD-02: Agent Update Mechanism

**Decision**: Agent downloads signed ZIP from portal on heartbeat notification
**Rationale**: Portal controls rollout timing. Ed25519 signature prevents tampering. Agent self-replaces and restarts. MSP admins can stage rollouts. No external update infrastructure needed.
**Alternatives considered**:
- MSI auto-update (push from portal): Portal cannot push to agents (no inbound access). Rejected.
- Manual MSI reinstall: Too much friction for MSP techs managing many clients. Rejected for primary mechanism (kept as fallback).

### TD-03: Agent Authentication

**Decision**: HMAC-SHA256 with per-agent secret
**Rationale**: Simple, stateless, works through proxies. Agent secret established during enrollment. No certificate management overhead. Replay protection via timestamp header.
**Alternatives considered**:
- mTLS: Strongest authentication but complicates proxy/TLS inspection environments common in medical offices. Offered as opt-in for high-security environments.
- JWT: Requires token refresh cycle, adds complexity. Agent secret is simpler for machine-to-machine auth.
- API key only: No request signing, vulnerable to replay attacks. Rejected.

### TD-04: Real-time Scan Progress (UI)

**Decision**: WebSocket (browser to FastAPI backend)
**Rationale**: True real-time updates for scan progress. FastAPI has native WebSocket support. TanStack Query handles REST; WebSocket handles streaming. Browser-to-server WebSocket works reliably (no firewall issues like agent communication).
**Alternatives considered**:
- SSE (Server-Sent Events): Simpler (HTTP-based), but unidirectional. WebSocket allows future bidirectional use (cancel scan, pause scan). SSE would work but WebSocket is slightly more flexible.

### TD-05: Network Discovery

**Decision**: nmap via python-nmap wrapper (subprocess)
**Rationale**: nmap is already in scanner dependencies (never used). Industry-standard tool for host discovery, port scanning, OS detection. python-nmap wraps nmap CLI cleanly. Vastly more reliable than raw socket programming.
**Alternatives considered**:
- Scapy: Pure Python packet manipulation. Powerful but requires raw socket privileges and reimplements what nmap already does better. Rejected as primary (useful for specific ARP operations).
- Native ping subprocess: Works for host discovery but cannot do port scanning or OS detection. Used as fallback when nmap is unavailable.

### TD-06: SSH Library

**Decision**: Paramiko
**Rationale**: Pure Python, well-maintained (18+ years), synchronous API matches existing scanner architecture. No binary dependencies. Supports password and key-based auth.
**Alternatives considered**:
- asyncssh: Async-native, but scanner engine is synchronous (ThreadPoolExecutor for parallelism). Adding asyncio would require refactoring the entire scan engine. Rejected for now; reconsider if engine goes async.

### TD-07: SNMP Library

**Decision**: pysnmp
**Rationale**: Pure Python, supports v1/v2c/v3 including v3 authentication and encryption. No native dependencies. Well-documented.
**Alternatives considered**:
- easysnmp: Wraps net-snmp C library. Faster but requires native library installation (complicates PyInstaller packaging for Windows agent). Rejected.

### TD-08: Agent Packaging

**Decision**: PyInstaller single EXE + WiX MSI wrapper
**Rationale**: PyInstaller creates self-contained EXE with all Python deps. WiX wraps into MSI for enterprise deployment (GPO, SCCM, Intune). Combined approach gives both standalone and managed deployment options.
**Alternatives considered**:
- cx_Freeze: Similar to PyInstaller but less actively maintained. Rejected.
- NSSM (Non-Sucking Service Manager): Service wrapper without needing pywin32. Kept as fallback for environments where pywin32 service registration fails.

### TD-09: Report Scheduling

**Decision**: APScheduler (in-process, backed by PostgreSQL job store)
**Rationale**: Lightweight, no additional infrastructure. Already Python-native. PostgreSQL job store survives restarts. Sufficient for the expected scale (hundreds of scheduled reports, not millions).
**Alternatives considered**:
- Celery + Redis/RabbitMQ: Production-grade task queue but requires Redis or RabbitMQ infrastructure. Overkill for report scheduling at current scale. Reconsider if scan orchestration needs distributed task queue.
- OS cron: Not portable, not manageable from portal UI. Rejected.

### TD-10: PHI Scanning at Scale

**Decision**: Python `re` module with compiled regex patterns, ThreadPoolExecutor for parallel file scanning
**Rationale**: The existing PHI detection checks already use Python regex (re module). Performance is sufficient because PHI scanning is I/O-bound (reading files over WinRM/SSH), not CPU-bound on regex matching. Compiling patterns once and reusing handles the hot path.
**Alternatives considered**:
- Hyperscan (Intel regex engine): 10x faster for large pattern sets, but requires C library and complicates packaging. Not needed at current file-scan volumes. Revisit if scanning > 10,000 files per host.

---

## 11. Security Architecture

### 11.1 Agent-to-Portal TLS Certificate Validation

- Agent receives portal CA certificate during enrollment (pinned in local config)
- Agent validates TLS certificate chain against pinned CA on every connection
- If validation fails, agent refuses to communicate (logs error locally)
- Portal uses a certificate from a public CA (Let's Encrypt or commercial) for initial enrollment
- Optional: internal CA for mTLS (see TD-03)

### 11.2 API Key Hashing

- API keys are generated as 64-byte random hex strings
- Only the first 8 characters (prefix) and an argon2id hash are stored in the database
- The full key is shown to the user exactly once at creation time
- Verification: hash the incoming key with argon2id and compare to stored hash
- Agent secrets use the same pattern (argon2id hash stored, plaintext shown once during enrollment)

### 11.3 PHI Data Handling

**Critical rule: the scanner NEVER stores PHI content. Only locations.**

- PHI detection checks scan for patterns (SSN, MRN, DOB, ICD-10 codes)
- When a match is found, the scanner records:
  - File path where PHI was found
  - Line number (approximate)
  - Pattern type that matched (e.g., "SSN", "MRN")
  - Count of matches
- The scanner does NOT record:
  - The actual PHI content (no SSN values, no patient names)
  - File contents
  - Surrounding context text
- This is enforced in the BaseCheck `_pass`/`_fail` helpers and in the Finding model serialization

### 11.4 Multi-Tenant Data Isolation

**Three-layer defense** (from prior architecture learning):

1. **Database layer**: `msp_id` column on all tables. PostgreSQL Row-Level Security (RLS) policies prevent cross-tenant queries even if application logic fails.
2. **Application layer**: FastAPI dependency injection adds `msp_id` filter to all queries. The `get_current_user` dependency extracts msp_id from JWT.
3. **API layer**: All endpoints validate that requested resources belong to the requesting user's msp_id. 404 returned (not 403) for cross-tenant requests to prevent enumeration.

```sql
-- Example RLS policy (add to all tenant-scoped tables)
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY scans_msp_isolation ON scans
    USING (msp_id = current_setting('app.current_msp_id')::uuid);
```

### 11.5 Secret Management for Per-Client WinRM Credentials

- WinRM/SSH/SNMP credentials are stored in the `agent_configs` table `config_data` JSONB field
- Credentials within config_data are encrypted at the application level using AES-256-GCM
- Encryption key is derived per-MSP from a master key stored in environment variable (`CREDENTIAL_ENCRYPTION_KEY`)
- Credentials are decrypted only by the agent after config pull (agent has the MSP-scoped decryption key established during enrollment)
- Database encryption at rest (PostgreSQL TDE or pgcrypto) provides defense-in-depth
- Credentials are NEVER logged, NEVER included in error messages, NEVER returned in API responses

### 11.6 Audit Logging Requirements

All of the following actions MUST be logged to the `audit_log` table:

| Action | Fields Logged |
|--------|---------------|
| User login (success/fail) | user_id, ip_address, success/fail, user_agent |
| User created/modified/deactivated | actor_id, target_user_id, changes |
| API key generated/revoked | actor_id, key_prefix, scopes |
| Agent enrolled/retired | actor_id, agent_id, client_id |
| Scan initiated/completed | actor_id or agent_id, scan_id, client_id |
| Finding status changed | actor_id, finding_id, old_status, new_status |
| Report generated/downloaded | actor_id, report_type, scan_id |
| Client created/modified | actor_id, client_id, changes |
| Config pushed to agent | actor_id, agent_id, config_version |
| Schedule created/modified/deleted | actor_id, schedule_id |
| Branding updated | actor_id, msp_id |

Audit log is append-only. No DELETE or UPDATE endpoints exist. Retention: 6 years minimum (per HIPAA documentation requirements at 45 CFR 164.316(b)(2)(i)).

---

## Appendix A: File Tree (New and Modified)

```
hipaa-scanner/
  backend/
    app/
      api/v1/
        auth.py              [MODIFY] Fix refresh endpoint
        scans.py             [MODIFY] Fix Host record creation, add WebSocket
        clients.py           [EXISTING]
        reports.py           [EXISTING]
        users.py             [NEW] User management CRUD
        api_keys.py          [NEW] API key management
        agents.py            [NEW] Agent enrollment, heartbeat, config
        msp.py               [NEW] MSP org management
        schedules.py         [NEW] Scan scheduling
        discovery.py         [NEW] Network discovery endpoints
        audit_log.py         [NEW] Audit log query endpoint
      auth/
        agent_auth.py        [NEW] HMAC authentication for agents
      middleware/
        audit.py             [NEW] Audit logging middleware
      models/
        agent.py             [NEW] Agent, AgentConfig, EnrollmentToken models
        api_key.py           [NEW] ApiKey model
        schedule.py          [NEW] ScanSchedule model
        discovery.py         [NEW] NetworkDiscoveryResult model
        branding.py          [NEW] MspBranding model
        audit.py             [NEW] AuditLog model
        scan.py              [MODIFY] Add agent_id, schedule_id columns
        user.py              [MODIFY] Add invited_at, mfa columns
      services/
        credential_encryption.py  [NEW] AES-256-GCM credential encryption
  scanner/
    hipaa_scanner/
      agent/                 [NEW DIRECTORY]
        __init__.py
        core.py              [NEW] AgentCore main loop
        enrollment.py        [NEW] Enrollment protocol
        config_manager.py    [NEW] Config storage/merge
        service_win.py       [NEW] Windows service wrapper
        service_linux.py     [NEW] systemd daemon wrapper
        updater.py           [NEW] Auto-update logic
      connectors/
        ssh_connector.py     [NEW] Paramiko SSH connector
        snmp_connector.py    [NEW] pysnmp SNMP connector
        http_connector.py    [NEW] httpx HTTP connector
      checks/
        backup.py            [NEW] BK-01..BK-05
        email_security.py    [NEW] EM-01..EM-05
        removable_media.py   [NEW] RM-01..RM-03
        browser_security.py  [NEW] BS-01..BS-04
        app_security.py      [NEW] AS-01..AS-03
        physical.py          [NEW] PS-01..PS-05
        policy_checks.py     [NEW] AD-01..AD-08
        network_devices.py   [NEW] ND-01..ND-06
        linux.py             [NEW] LX-01..LX-08
        access_controls.py   [MODIFY] Add AC-13..AC-19
        encryption.py        [MODIFY] Add EN-05..EN-11
        audit_controls.py    [MODIFY] Add AU-05..AU-08
        network_security.py  [MODIFY] Add NS-05..NS-12
      engine.py              [MODIFY] Add nmap discovery, connector factory
      scoring.py             [MODIFY] Apply category weights
  installer/                 [NEW DIRECTORY]
    windows/
      build.bat              [NEW] PyInstaller + WiX build script
      installer.wxs          [NEW] WiX MSI manifest
      pyinstaller.spec       [NEW] PyInstaller config
    linux/
      build.sh               [NEW] deb/rpm build script
      debian/                [NEW] Debian packaging files
  frontend/
    src/
      pages/
        SettingsPage.tsx     [NEW]
        AgentsPage.tsx       [NEW]
        DiscoveryPage.tsx    [NEW]
        ReportsPage.tsx      [NEW]
        HostsPage.tsx        [NEW]
        ScansPage.tsx        [MODIFY] Add scan initiation
        ScanDetailPage.tsx   [MODIFY] Add remediation workflow
      hooks/
        useWebSocket.ts      [NEW]
      components/
        agents/              [NEW] Agent management components
        settings/            [NEW] Settings tab components
        discovery/           [NEW] Network map components
        reports/             [NEW] Trend charts, export
```

---

**End of Architecture Specification**
