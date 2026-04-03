"""
Database encryption and access control checks.
HIPAA reference: 164.312(a)(2)(iv) — Encryption/Decryption (Addressable)
NIST SP 800-66r2: Section 3.6 — Access Control, Encryption

EHR and clinical databases containing ePHI must be encrypted at rest.
SQL Server TDE and MySQL encryption are the standard controls.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class SqlServerTdeCheck(BaseCheck):
    """
    DB-01: Verify SQL Server databases containing ePHI have Transparent Data Encryption (TDE) enabled.
    TDE encrypts the database files at rest — protection if physical storage is stolen or improperly disposed.
    """
    check_id = "DB-01"
    check_name = "SQL Server Transparent Data Encryption (TDE)"
    category = "Database Security"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 12.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check if SQL Server is running
            sql_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'MSSQLSERVER','MSSQL$*' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Select-Object Name | ConvertTo-Json"
            )

            if sql_service.strip() in ("", "null", "[]"):
                return self._na(target, "SQL Server service not running on this host.")

            # Query TDE status for all user databases
            tde_status = context.winrm.run_ps(
                target.hostname,
                r"$query = \"SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4\"; "
                r"try { "
                r"  Invoke-Sqlcmd -Query $query -ServerInstance localhost -ErrorAction Stop | "
                r"  Select-Object name, is_encrypted | ConvertTo-Json "
                r"} catch { "
                r"  # Fallback: use sqlcmd.exe if Invoke-Sqlcmd not available "
                r"  $result = sqlcmd -S localhost -Q $query -h -1 -W 2>&1; "
                r"  $result "
                r"}"
            )

            # Check SQL Server audit (monitors who accesses the DB)
            sql_audit = context.winrm.run_ps(
                target.hostname,
                r"$query = \"SELECT name, status_desc FROM sys.server_audits\"; "
                r"try { Invoke-Sqlcmd -Query $query -ServerInstance localhost -EA Stop | ConvertTo-Json } "
                r"catch { 'not available' }"
            )

            import json as _json
            unencrypted_dbs = []
            encrypted_dbs = []

            if tde_status.strip() not in ("", "null", "[]", "not available"):
                try:
                    raw = _json.loads(tde_status)
                    db_list = raw if isinstance(raw, list) else [raw]
                    for db in db_list:
                        name = db.get("name", "unknown")
                        encrypted = db.get("is_encrypted", 0)
                        if encrypted:
                            encrypted_dbs.append(name)
                        else:
                            unencrypted_dbs.append(name)
                except Exception:
                    # Could not parse — report as warning
                    pass

            evidence = {
                "encrypted_databases": encrypted_dbs[:10],
                "unencrypted_databases": unencrypted_dbs[:10],
                "sql_audit_configured": "started" in sql_audit.lower(),
                "raw_tde_output": tde_status.strip()[:200] if not encrypted_dbs and not unencrypted_dbs else None,
            }

            if unencrypted_dbs:
                return self._fail(
                    target,
                    details=f"{len(unencrypted_dbs)} SQL Server database(s) without TDE: {', '.join(unencrypted_dbs[:5])}. ePHI stored in these databases is unencrypted on disk.",
                    remediation=(
                        "Enable TDE on all SQL Server databases containing ePHI: "
                        "1. Create master key: CREATE MASTER KEY ENCRYPTION BY PASSWORD = '...'; "
                        "2. Create certificate: CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate'; "
                        "3. Create DEK: USE [database]; "
                        "   CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 "
                        "   ENCRYPTION BY SERVER CERTIFICATE TDECert; "
                        "4. Enable: ALTER DATABASE [database] SET ENCRYPTION ON; "
                        "BACKUP the TDE certificate immediately — losing it = losing all data."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "-- Enable TDE on a SQL Server database:\n"
                        "USE master;\n"
                        "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!';\n"
                        "CREATE CERTIFICATE TDECert WITH SUBJECT = 'HIPAA TDE Certificate';\n"
                        "USE [YourDatabase];\n"
                        "CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256\n"
                        "  ENCRYPTION BY SERVER CERTIFICATE TDECert;\n"
                        "ALTER DATABASE [YourDatabase] SET ENCRYPTION ON;\n"
                        "-- Backup the certificate (CRITICAL):\n"
                        "BACKUP CERTIFICATE TDECert TO FILE = 'C:\\TDECert.cer'\n"
                        "  WITH PRIVATE KEY (FILE = 'C:\\TDECert.pvk', ENCRYPTION BY PASSWORD = 'BackupPwd!');"
                    ),
                )
            elif encrypted_dbs:
                return self._pass(
                    target,
                    details=f"TDE enabled on all detected databases: {', '.join(encrypted_dbs[:5])}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="SQL Server is running but TDE status could not be determined. Manual verification required.",
                    remediation=(
                        "Manually verify TDE status: "
                        "SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4; "
                        "Enable TDE on all databases containing ePHI."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class SqlServerAuthModeCheck(BaseCheck):
    """
    DB-02: Verify SQL Server uses Windows Authentication mode (not mixed mode with SQL logins).
    SQL authentication with weak passwords is a common attack vector against EHR databases.
    """
    check_id = "DB-02"
    check_name = "SQL Server Authentication Mode"
    category = "Database Security"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            sql_service = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'MSSQLSERVER','MSSQL$*' -ErrorAction SilentlyContinue | "
                r"Where-Object Status -eq 'Running' | Measure-Object | Select-Object -ExpandProperty Count"
            )

            if sql_service.strip() in ("", "0"):
                return self._na(target, "SQL Server service not running on this host.")

            # Check auth mode via registry (1=Windows Only, 2=Mixed)
            auth_mode = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*\MSSQLServer' "
                r"-Name LoginMode -ErrorAction SilentlyContinue).LoginMode | Select-Object -First 1"
            )

            # Check if SA account is enabled (high risk if mixed mode)
            sa_enabled = context.winrm.run_ps(
                target.hostname,
                r"try { "
                r"  Invoke-Sqlcmd -Query \"SELECT is_disabled FROM sys.sql_logins WHERE name = 'sa'\" "
                r"  -ServerInstance localhost -EA Stop | Select-Object -ExpandProperty is_disabled "
                r"} catch { 'unknown' }"
            )

            mode_val = int(auth_mode.strip()) if auth_mode.strip().isdigit() else None
            sa_is_disabled = sa_enabled.strip() == "1"

            evidence = {
                "auth_mode_registry": auth_mode.strip(),
                "auth_mode": "Windows Only" if mode_val == 1 else "Mixed Mode" if mode_val == 2 else "Unknown",
                "sa_account_disabled": sa_is_disabled,
            }

            if mode_val == 1:
                return self._pass(
                    target,
                    details="SQL Server configured for Windows Authentication only — no SQL logins accepted.",
                    evidence=evidence,
                )
            elif mode_val == 2:
                if not sa_is_disabled:
                    return self._fail(
                        target,
                        details="SQL Server uses Mixed Mode authentication AND the 'sa' account is enabled. This is the most dangerous configuration for EHR databases.",
                        remediation=(
                            "1. Switch to Windows Authentication only if possible: "
                            "   ALTER LOGIN sa DISABLE; then reconfigure to Windows Auth mode. "
                            "2. If mixed mode is required: immediately disable or rename 'sa' account, "
                            "   use strong passwords for all SQL logins, enable SQL audit for login failures. "
                            "3. Grant database access via Windows groups/AD accounts whenever possible."
                        ),
                        evidence=evidence,
                    )
                else:
                    return self._fail(
                        target,
                        details="SQL Server uses Mixed Mode authentication (sa account is disabled). Prefer Windows Authentication only to eliminate SQL login attack surface.",
                        remediation=(
                            "Switch SQL Server to Windows Authentication mode: "
                            "Server Properties > Security > Server authentication > Windows Authentication mode. "
                            "Requires SQL Server service restart. Audit all SQL logins first to avoid access disruption."
                        ),
                        evidence=evidence,
                    )
            else:
                return self._fail(
                    target,
                    details="SQL Server authentication mode could not be determined. Manual verification required.",
                    remediation="Run: SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') — result 1=Windows Only, 0=Mixed.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
