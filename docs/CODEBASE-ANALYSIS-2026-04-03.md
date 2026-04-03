# HIPAA Scanner Codebase Analysis — 2026-04-03

**Produced by:** Codebase Explorer Agent
**Purpose:** Gap analysis for architect planning session

---

## 1. BACKEND (backend/)

### 1.1 FastAPI Routes — Complete Endpoint Inventory

All routers mounted under `/api/v1`. Health check at `/api/health`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/api/health` | None | Health check, returns version |
| `POST` | `/api/v1/auth/login` | None | JWT login, sets refresh cookie |
| `POST` | `/api/v1/auth/refresh` | Cookie | **STUB — raises 501** |
| `POST` | `/api/v1/auth/logout` | None | Deletes refresh cookie |
| `GET` | `/api/v1/auth/me` | Bearer | Returns current user |
| `GET` | `/api/v1/clients/` | MSP user | List clients (enriched with latest score) |
| `POST` | `/api/v1/clients/` | MSP admin | Create client |
| `GET` | `/api/v1/clients/{id}` | MSP user | Get single client |
| `PATCH` | `/api/v1/clients/{id}` | MSP admin | Update client fields |
| `GET` | `/api/v1/clients/{id}/dashboard` | MSP user | Client dashboard with last 5 scans |
| `POST` | `/api/v1/scans/upload` | API key header | Scanner CLI uploads results |
| `GET` | `/api/v1/scans/` | Any user | List scans (filtered by MSP, optional client_id) |
| `GET` | `/api/v1/scans/{id}` | Any user | Get single scan |
| `GET` | `/api/v1/scans/{id}/findings` | Any user | List findings with filters |
| `PATCH` | `/api/v1/scans/{id}/findings/{fid}` | Any user | Update finding status/assignee/notes |
| `POST` | `/api/v1/reports/{scan_id}/generate` | Any user | Generate PDF (executive or technical) |

**Total: 16 endpoints (15 functional + 1 stub)**

### 1.2 Database Models

| Model | Table | Key Fields |
|-------|-------|------------|
| `MspOrganization` | `msp_organizations` | id, name, api_key, api_secret_hash, is_active |
| `User` | `users` | id, msp_id, client_id (nullable), email, hashed_password, role (msp_admin/msp_tech/client_admin), is_active |
| `Client` | `clients` | id, msp_id, name, contact_name/email/phone, industry, notes, is_active |
| `Scan` | `scans` | id, client_id, msp_id, scanner_version, profile, environment_type, status, overall_score, risk_level, hosts_scanned/failed, total_checks, checks_passed/failed, findings_critical/high/medium/low, started_at/completed_at |
| `Host` | `hosts` | id, scan_id, hostname, ip_address, os_version, os_build, role, scan_status |
| `Finding` | `findings` | id, scan_id, host_id (nullable), check_id, check_name, category, hipaa_reference, severity, status, result, details, remediation, remediation_script, evidence (JSON), points_deducted, assigned_to, notes |

### 1.3 Authentication/Authorization
- JWT (15-min access) + refresh tokens (7-day, httponly cookie)
- **Refresh endpoint is STUB — returns HTTP 501**
- Roles: `msp_admin`, `msp_tech`, `client_admin`
- Scanner CLI: `X-Scanner-API-Key` header auth

### 1.4 Multi-Tenancy Status
- Data model is fully multi-tenant (msp_id on all entities)
- Query filtering by msp_id is consistent
- **GAP:** No MSP org management API/UI (create/list/update orgs)
- **GAP:** No user management endpoints (create/invite users)
- **GAP:** No API key management (generate/rotate/revoke)
- **GAP:** Refresh token endpoint broken (501)
- **GAP:** No audit logging

### 1.5 Scan Upload Gap
Upload creates Scan + Finding records **but never creates Host records** — Host table exists but is never populated by the upload flow.

---

## 2. SCANNER ENGINE (scanner/) — 27 Checks Across 6 Categories

### Access Control (8 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| AC-01 | Password Min Length | CRITICAL | >= 12 chars via AD LDAP or `net accounts` |
| AC-02 | Password Complexity | HIGH | Complexity enabled |
| AC-03 | Password Max Age | MEDIUM | <= 90 days |
| AC-04 | Account Lockout | HIGH | Threshold <= 5 attempts |
| AC-07 | Screen Lock Timeout | HIGH | Screen saver <= 15 min |
| AC-09 | Inactive Accounts | HIGH | No accounts inactive > 90 days |
| AC-10 | Local Admin Audit | HIGH | <= 2 local admin members |
| AC-12 | RDP Session Timeout | MEDIUM | Idle timeout <= 15 min |

### Encryption (4 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| EN-01 | BitLocker | CRITICAL | All drives BitLocker-encrypted |
| EN-02 | TLS Protocol | HIGH | No SSL 2/3, TLS 1.0/1.1 |
| EN-03 | RDP Encryption | HIGH | Level >= 3 (High/FIPS) |
| EN-04 | SMB Encryption | HIGH | SMB signing + encryption enabled |

### Audit Controls (4 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| AU-01 | Audit Logon Events | HIGH | Logon auditing enabled |
| AU-02 | Audit Account Mgmt | HIGH | Account mgmt auditing enabled |
| AU-03 | Event Log Size | MEDIUM | Security log >= 200 MB |
| AU-04 | Log Retention | MEDIUM | Mode is Retain or AutoBackup |

### Patch Management (3 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| PM-01 | Windows Update | CRITICAL | No missing critical/important updates |
| PM-02 | Auto Update | HIGH | Auto updates not disabled |
| PM-03 | Pending Reboot | MEDIUM | No pending reboot |

### Network Security (4 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| NS-01 | RDP Port Open | CRITICAL | Port 3389 not exposed externally |
| NS-02 | Telnet Open | CRITICAL | Port 23 not open |
| NS-03 | FTP Open | HIGH | Port 21 not open |
| NS-04 | Windows Firewall | HIGH | Firewall enabled all profiles |

### Antivirus (3 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| AV-01 | AV Installed | CRITICAL | AV detected via WMI Security Center |
| AV-02 | AV Definitions | HIGH | Defender defs <= 3 days old |
| AV-03 | AV Real-Time | CRITICAL | Real-time protection on |

### PHI Discovery (2 checks)
| ID | Check | Severity | Tests |
|----|-------|----------|-------|
| PHI-01 | PHI on Desktop | CRITICAL | Regex scan for SSN, DOB, ICD-10, MRN on desktop |
| PHI-02 | PHI on Shares | CRITICAL | Regex scan for SSN, MRN on network shares |

### Connectors
- **WinRM** — Windows only, NTLM auth, HTTP(S) 5985/5986
- **LDAP** — Active Directory, NTLM auth
- **MISSING:** SSH (Linux/macOS), SNMP (network devices), VMware, cloud APIs

### Network Discovery
- AD mode: LDAP `(objectClass=computer)` query
- Workgroup mode: CIDR expansion (generates all IPs, does NOT ping-test before scanning)
- **No ping/ARP sweep**, **no port scanning** (nmap listed in deps but never used)
- **No Linux/macOS support**, **no network device support**

---

## 3. FRONTEND (frontend/)

### Pages/Routes (hash-based)
| Route | Page | Status |
|-------|------|--------|
| `#/dashboard` | Dashboard | ✅ KPI cards, client grid |
| `#/clients` | Clients | ✅ Table, search, create modal |
| `#/scans` | Scans | ✅ Table with CLI usage hint |
| `#/scans/{id}` | ScanDetail | ✅ Score, categories, findings, PDF download |
| Reports (nav item) | — | ❌ **No Reports page — shows Dashboard** |
| (no hash) | Login | ✅ |

### UI Gaps
1. **No scan initiation from UI** — CLI only
2. **No real-time scan progress** — no WebSocket/SSE
3. **No Reports page** — nav item is dead
4. **No Settings/Admin page** — no user, org, API key management
5. **No finding remediation workflow UI** — API exists, no UI
6. **No host inventory view** — Host model exists, no UI
7. **No historical trend charts** — Recharts imported but unused
8. **No agent management** — no collector agent UI
9. **Hash routing** — TanStack Router in package.json, unused

---

## 4. GAP ANALYSIS SUMMARY

### Network Scanning Gaps (Critical)
- No ping/ARP sweep — cannot discover live hosts
- No port scanning (nmap present in deps, never called)
- No service detection or OS fingerprinting
- No Linux/macOS scanning (no SSH connector)
- No network device scanning (no SNMP)
- No wireless network assessment
- CIDR mode tries all IPs blindly via WinRM

### Missing HIPAA Check Categories (Critical)
- **MFA/2FA verification** — entirely absent
- **Backup encryption/testing** — entirely absent
- **Email security** (DMARC, DKIM, SPF, TLS) — absent
- **USB/removable media policy** — absent
- **Service account password age** — absent
- **Shared/guest accounts** — absent
- **VPN configuration verification** — absent
- **Wireless security** (WPA2/WPA3) — absent
- **Certificate expiration** — absent
- **SIEM/centralized logging** — absent
- **Browser security** — absent
- **AppLocker/application whitelisting** — absent
- **Database encryption** — absent
- **All Administrative Safeguards** (164.308) — none implemented
- **All Physical Safeguards** (164.310) — none implemented

### Collector/Agent Infrastructure (Entirely Missing)
- No persistent daemon/service
- No agent-to-portal secure channel
- No enrollment/registration mechanism
- No agent authentication
- No auto-update
- No scheduled scanning from portal
- No heartbeat/online status
- No agent config management
- No installer package

### Multi-Tenancy Operational Gaps
- No MSP org management API or UI
- No user management (invite/create/role management)
- No API key management UI
- No per-client credential storage
- No white-label/branding per MSP
- Refresh token broken (501)

### Reporting Gaps
- No historical trend reports
- No remediation progress reports
- No scheduled/automated report delivery
- No email delivery
- No CSV/Excel export
- No HIPAA Risk Assessment document
- No compliance certificate

---

## 5. WHAT IS WELL-BUILT (PRESERVE)

1. **Check plugin architecture** — BaseCheck with class-level metadata, _pass/_fail/_error/_na helpers. Trivial to add new checks.
2. **All 27 existing checks** — Correct PowerShell, thresholds, remediation text, CFR refs, evidence collection.
3. **Data models** — SQLAlchemy + Pydantic models are comprehensive and correct.
4. **PDF report templates** — Professional WeasyPrint HTML templates.
5. **WinRM + LDAP connectors** — Clean implementations.
6. **Backend auth flow** — JWT + RBAC dependency injection pattern.
7. **Frontend component quality** — Loading states, error handling, clean Tailwind UI.
8. **Scoring engine** — Simple and effective (weights defined but not applied — easy fix).
9. **Deployment config** — nginx, PM2, server-setup.sh all production-ready.

---

## 6. PRIORITY IMPLEMENTATION ORDER

### Tier 1 — Critical Fixes (must do before anything else)
1. Fix refresh token endpoint (501 stub)
2. Fix scan upload to create Host records
3. Add ping sweep before WinRM scanning (nmap already in deps)
4. Fix scoring to use category weights
5. Add user management API endpoints
6. Add API key management endpoints

### Tier 2 — Core Feature Build
1. Collector agent skeleton (Windows service, enrollment, heartbeat)
2. SSH connector (Linux/macOS nodes)
3. SNMP connector (network devices)
4. 20+ new HIPAA checks (MFA, backup, email sec, USB, wireless, certs)
5. Agent management UI
6. Reports page + historical trends
7. Settings/Admin page
8. Finding remediation workflow UI
9. Real-time scan progress (WebSocket)

### Tier 3 — Full Product
1. Agent auto-update + config push
2. White-label/MSP branding
3. HIPAA Risk Assessment document generation
4. Compliance certificate generation
5. CSV/Excel export
6. Scheduled report delivery via email
7. MSI/deb installer for collector
8. Cloud scanning (AWS, Azure)
9. SSO/SAML
10. Audit logging
