"""
Advanced Windows security configuration checks.
HIPAA reference: 164.312(a)(1) — Access Control, 164.312(b) — Audit Controls

These checks cover Windows-specific hardening that goes beyond basic configuration:
scheduled maintenance tasks, security policy enforcement, and service hardening.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class AutoRunAutoPlayCheck(BaseCheck):
    """
    WIN-01: Verify AutoRun and AutoPlay are disabled for all drive types.
    AutoRun enables malware on USB/CD media to execute automatically when inserted.
    This is a HIPAA physical safeguard control for media handling.
    """
    check_id = "WIN-01"
    check_name = "AutoRun and AutoPlay Disabled"
    category = "Device and Media Controls"
    hipaa_reference = "164.310(d)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check NoDriveTypeAutoRun (255 = all drives, 0xFF)
            no_autorun = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' "
                r"-Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
            )

            # Check AutoPlay for non-volume devices
            no_autoplay = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' "
                r"-Name NoAutorun -ErrorAction SilentlyContinue).NoAutorun"
            )

            # Check GPO version
            gpo_autorun = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' "
                r"-Name NoAutoplayfornonVolume -ErrorAction SilentlyContinue).NoAutoplayfornonVolume"
            )

            # Check user-level settings
            user_autorun = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' "
                r"-Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
            )

            try:
                val = int(no_autorun.strip())
                autorun_disabled = val >= 255 or val == 0xFF
            except (ValueError, AttributeError):
                autorun_disabled = False

            no_autorun_set = no_autoplay.strip() == "1"
            gpo_set = gpo_autorun.strip() == "1"

            try:
                user_val = int(user_autorun.strip())
                user_disabled = user_val >= 255
            except (ValueError, AttributeError):
                user_disabled = False

            fully_disabled = autorun_disabled or (no_autorun_set and gpo_set)

            evidence = {
                "NoDriveTypeAutoRun": no_autorun.strip() or "not set",
                "NoAutorun": no_autoplay.strip() or "not set",
                "GPO_NoAutoplayfornonVolume": gpo_autorun.strip() or "not set",
                "user_NoDriveTypeAutoRun": user_autorun.strip() or "not set",
            }

            if fully_disabled:
                return self._pass(
                    target,
                    details="AutoRun and AutoPlay are disabled for all drive types. Removable media will not auto-execute.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="AutoRun/AutoPlay not fully disabled. Malware on USB drives or optical media could execute automatically when inserted.",
                    remediation=(
                        "Disable AutoRun/AutoPlay via GPO: "
                        "Computer Config > Admin Templates > Windows Components > AutoPlay Policies > "
                        "1. 'Turn off AutoPlay' → Enabled, All Drives. "
                        "2. 'Set the default behavior for AutoRun' → Enabled, Do not execute any autorun commands. "
                        "3. 'Disallow AutoPlay for non-volume devices' → Enabled. "
                        "Registry equivalent: "
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                        "-Name NoDriveTypeAutoRun -Value 0xFF"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable AutoRun for all drive types (0xFF = all drives):\n"
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                        "-Name NoDriveTypeAutoRun -Value 255 -Type DWord -Force\n"
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                        "-Name NoAutorun -Value 1 -Type DWord -Force\n"
                        "# Verify:\n"
                        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' | "
                        "Select-Object NoDriveTypeAutoRun, NoAutorun"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class ScheduledTaskAuditCheck(BaseCheck):
    """
    WIN-02: Verify no suspicious scheduled tasks are running as SYSTEM or with
    elevated privileges from user-writable locations. Attackers use scheduled tasks
    for persistence after initial compromise.
    """
    check_id = "WIN-02"
    check_name = "Scheduled Task Security Audit"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Find scheduled tasks running as SYSTEM from user-writable paths
            suspicious_tasks = context.winrm.run_ps(
                target.hostname,
                r"$suspicious = Get-ScheduledTask -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.State -ne 'Disabled' } | "
                r"ForEach-Object { "
                r"  $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; "
                r"  $action = $_.Actions | Select-Object -First 1; "
                r"  [PSCustomObject]@{ "
                r"    Name = $_.TaskName; "
                r"    Principal = $_.Principal.UserId; "
                r"    Execute = $action.Execute; "
                r"    Path = $_.TaskPath "
                r"  } "
                r"} | Where-Object { "
                r"  $_.Execute -and ( "
                r"    $_.Execute -like '*\Users\*' -or "
                r"    $_.Execute -like '*\Temp\*' -or "
                r"    $_.Execute -like '*\AppData\*' -or "
                r"    $_.Execute -like '*\ProgramData\*' "
                r"  ) -and ( "
                r"    $_.Principal -like '*SYSTEM*' -or $_.Principal -like '*Administrator*' "
                r"  ) "
                r"} | Select-Object Name, Execute, Principal | ConvertTo-Json"
            )

            # Count total scheduled tasks (baseline)
            total_tasks = context.winrm.run_ps(
                target.hostname,
                r"(Get-ScheduledTask -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.State -ne 'Disabled' }).Count"
            )

            # Check for recently created tasks (last 30 days) — forensic indicator
            recent_tasks = context.winrm.run_ps(
                target.hostname,
                r"$cutoff = (Get-Date).AddDays(-30); "
                r"$recent = Get-ScheduledTask -ErrorAction SilentlyContinue | "
                r"Where-Object { "
                r"  $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; "
                r"  $info -and $info.LastRunTime -gt $cutoff "
                r"} | "
                r"Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | "
                r"Measure-Object; "
                r"$recent.Count"
            )

            import json as _json
            suspicious_list = []
            if suspicious_tasks.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(suspicious_tasks)
                    suspicious_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            try:
                total = int(total_tasks.strip())
            except (ValueError, AttributeError):
                total = 0

            try:
                recent = int(recent_tasks.strip())
            except (ValueError, AttributeError):
                recent = 0

            evidence = {
                "total_active_tasks": total,
                "suspicious_tasks_count": len(suspicious_list),
                "suspicious_task_names": [t.get("Name", "?") for t in suspicious_list[:5]],
                "non_microsoft_recent_tasks": recent,
            }

            if not suspicious_list:
                return self._pass(
                    target,
                    details=f"{total} active scheduled tasks. No tasks found running as SYSTEM from user-writable paths.",
                    evidence=evidence,
                )
            else:
                task_names = [t.get("Name", "?") for t in suspicious_list[:3]]
                return self._fail(
                    target,
                    details=f"{len(suspicious_list)} scheduled task(s) running as SYSTEM/Administrator from user-writable paths: {', '.join(task_names)}. These are potential persistence mechanisms.",
                    remediation=(
                        "Review and remediate suspicious scheduled tasks: "
                        "1. Get-ScheduledTask -TaskName '<name>' | Select-Object * — review full details. "
                        "2. Verify with application vendor if task is legitimate. "
                        "3. For legitimate software: move executable to %ProgramFiles% (not user-writable). "
                        "4. For unknown tasks: Disable-ScheduledTask -TaskName '<name>' then investigate. "
                        "5. Check task creation date and associated files for malware indicators. "
                        "Run Autoruns (Sysinternals) for comprehensive scheduled task audit."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class GuestAccountCheck(BaseCheck):
    """
    WIN-03: Verify the built-in Guest account is disabled and no other
    anonymous/guest-capable accounts exist. Guest accounts provide
    unauthenticated access to system resources.
    """
    check_id = "WIN-03"
    check_name = "Guest Account Disabled"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase1"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check local Guest account
            guest_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
            )

            # Check for other enabled local accounts that look like guest/anonymous
            other_guest = context.winrm.run_ps(
                target.hostname,
                r"Get-LocalUser -ErrorAction SilentlyContinue | "
                r"Where-Object { "
                r"  $_.Enabled -eq $true -and "
                r"  ($_.Name -like '*guest*' -or $_.Name -like '*anon*' -or $_.Name -eq 'DefaultAccount') "
                r"} | Select-Object Name, Enabled | ConvertTo-Json"
            )

            # Check SMB null session (anonymous share access)
            null_session = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "
                r"-Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous"
            )

            # Check anonymous LDAP access restriction
            anonymous_ldap = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "
                r"-Name EveryoneIncludesAnonymous -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous"
            )

            guest_disabled = guest_status.strip().lower() == "false"

            import json as _json
            guest_accounts = []
            if other_guest.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(other_guest)
                    guest_accounts = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            try:
                restrict_anon = int(null_session.strip())
            except (ValueError, AttributeError):
                restrict_anon = 0
            anon_restricted = restrict_anon >= 1

            try:
                everyone_anon = int(anonymous_ldap.strip())
            except (ValueError, AttributeError):
                everyone_anon = 1  # Default is 1 (insecure)
            everyone_restricted = everyone_anon == 0

            evidence = {
                "guest_account_enabled": not guest_disabled,
                "other_guest_accounts": [a.get("Name", "?") for a in guest_accounts],
                "restrict_anonymous_smb": restrict_anon,
                "everyone_includes_anonymous": everyone_anon,
            }

            issues = []
            if not guest_disabled:
                issues.append("Built-in Guest account is ENABLED")
            if guest_accounts:
                issues.append(f"Additional guest-like accounts enabled: {', '.join([a.get('Name','?') for a in guest_accounts])}")
            if not anon_restricted:
                issues.append("RestrictAnonymous=0 — anonymous SMB enumeration allowed")
            if not everyone_restricted:
                issues.append("EveryoneIncludesAnonymous=1 — anonymous access included in Everyone group")

            if not issues:
                return self._pass(
                    target,
                    details="Guest account disabled, no guest-like accounts found, anonymous access restricted.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Anonymous/guest access issues: {'; '.join(issues)}",
                    remediation=(
                        "Disable guest and anonymous access: "
                        "1. Disable Guest: Disable-LocalUser -Name Guest. "
                        "2. Restrict anonymous SMB: "
                        "   Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RestrictAnonymous 2. "
                        "3. Restrict Everyone group: "
                        "   Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' EveryoneIncludesAnonymous 0. "
                        "4. Via GPO: Computer Config > Security Settings > Local Policies > Security Options: "
                        "   'Network access: Do not allow anonymous enumeration of SAM accounts and shares' → Enabled."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable Guest account and restrict anonymous access:\n"
                        "Disable-LocalUser -Name 'Guest'\n"
                        "$lsa = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'\n"
                        "Set-ItemProperty $lsa -Name RestrictAnonymous -Value 2\n"
                        "Set-ItemProperty $lsa -Name RestrictAnonymousSAM -Value 1\n"
                        "Set-ItemProperty $lsa -Name EveryoneIncludesAnonymous -Value 0"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class TimeServerSyncCheck(BaseCheck):
    """
    WIN-04: Verify accurate time synchronization.
    HIPAA requires accurate and reliable timestamps for audit logs (164.312(b)).
    Timestamp skew > 5 minutes breaks Kerberos authentication. Audit logs with
    wrong timestamps are legally inadmissible and useless for incident response.
    """
    check_id = "WIN-04"
    check_name = "Time Synchronization (NTP)"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 4.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check W32tm service
            w32tm_status = context.winrm.run_ps(
                target.hostname,
                r"(Get-Service -Name W32Time -ErrorAction SilentlyContinue).Status"
            )

            # Check NTP source
            ntp_source = context.winrm.run_ps(
                target.hostname,
                r"w32tm /query /source 2>$null"
            )

            # Check time offset from domain/NTP source (in seconds)
            time_offset = context.winrm.run_ps(
                target.hostname,
                r"try { "
                r"  $status = w32tm /query /status 2>$null; "
                r"  ($status | Select-String 'Last Successful Sync Time').ToString() "
                r"} catch { 'error' }"
            )

            # Check if NTP is configured to external servers (DC should sync to external)
            ntp_peers = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' "
                r"-Name NtpServer -ErrorAction SilentlyContinue).NtpServer"
            )

            w32tm_running = w32tm_status.strip().lower() == "running"
            source = ntp_source.strip()
            # Good sources: domain hierarchy, time.windows.com, pool.ntp.org, etc.
            # Bad: "Local CMOS Clock" or "Free-running System Clock" = not syncing
            good_source = bool(source) and "local" not in source.lower() and "free-running" not in source.lower() and "cmos" not in source.lower()

            evidence = {
                "w32time_service": w32tm_status.strip() or "not found",
                "ntp_source": source[:100] if source else "unknown",
                "ntp_peers": ntp_peers.strip()[:200] if ntp_peers.strip() else "not configured",
                "last_sync": time_offset.strip()[:150] if time_offset.strip() else "unknown",
            }

            if w32tm_running and good_source:
                return self._pass(
                    target,
                    details=f"Time synchronization active. Source: {source[:80]}",
                    evidence=evidence,
                )
            else:
                issues = []
                if not w32tm_running:
                    issues.append(f"W32Time service is {w32tm_status.strip() or 'not running'}")
                if not good_source:
                    issues.append(f"NTP source appears to be local clock ({source[:50] or 'unknown'}) — not syncing to network time")

                return self._fail(
                    target,
                    details=f"Time synchronization issues: {'; '.join(issues)}. Audit log timestamps may be inaccurate.",
                    remediation=(
                        "Fix NTP synchronization: "
                        "1. Start W32Time: Start-Service W32Time. "
                        "2. Configure domain-joined machines: w32tm /config /syncfromflags:domhier /update. "
                        "3. For PDC Emulator (or standalone): "
                        "   w32tm /config /manualpeerlist:'time.windows.com pool.ntp.org' /syncfromflags:manual /reliable:YES /update. "
                        "4. Force sync: w32tm /resync /force. "
                        "5. Set W32Time to auto-start: Set-Service W32Time -StartupType Automatic. "
                        "Kerberos requires <5 min clock skew — time drift breaks AD authentication."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class WindowsScriptingHostCheck(BaseCheck):
    """
    WIN-05: Verify Windows Script Host (WSH) is disabled or restricted.
    WSH enables .vbs, .js, .wsf, .wsh script execution — a common malware
    delivery mechanism. Most business workstations don't need WSH.
    """
    check_id = "WIN-05"
    check_name = "Windows Script Host Restriction"
    category = "Endpoint Security"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.WORKSTATION]
    phase = "phase2"
    points = 4.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check WSH enabled status (machine level)
            wsh_machine = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' "
                r"-Name Enabled -ErrorAction SilentlyContinue).Enabled"
            )

            # Check WSH user level
            wsh_user = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings' "
                r"-Name Enabled -ErrorAction SilentlyContinue).Enabled"
            )

            # Check .vbs file association (alternative indicator)
            vbs_assoc = context.winrm.run_ps(
                target.hostname,
                r"cmd /c 'assoc .vbs' 2>$null"
            )

            # Check macro execution settings for Office
            macro_word = context.winrm.run_ps(
                target.hostname,
                r"(Get-ItemProperty "
                r"'HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security' "
                r"-Name VBAWarnings -ErrorAction SilentlyContinue).VBAWarnings"
            )

            # WSH disabled = value 0
            wsh_disabled = wsh_machine.strip() == "0"

            vbs_active = ".vbs" in vbs_assoc.strip().lower() and "wscript" in vbs_assoc.strip().lower()

            try:
                macro_level = int(macro_word.strip())
            except (ValueError, AttributeError):
                macro_level = -1
            # 2 = disable all with notification, 3 = disable all (recommended), 4 = enable all (bad)
            macros_controlled = macro_level in (2, 3)

            evidence = {
                "wsh_machine_enabled": wsh_machine.strip() or "not set (enabled by default)",
                "wsh_user_enabled": wsh_user.strip() or "not set",
                "vbs_file_association": vbs_assoc.strip()[:100],
                "office_macro_level": macro_level if macro_level >= 0 else "not configured",
            }

            issues = []
            if not wsh_disabled and (not wsh_machine.strip() or wsh_machine.strip() == "1"):
                issues.append("Windows Script Host is enabled — .vbs/.js/.wsf files can execute")
            if not macros_controlled and macro_level not in (-1,):
                issues.append(f"Office macros level={macro_level} (4=all enabled is dangerous)")

            if not issues:
                return self._pass(
                    target,
                    details="Windows Script Host is disabled. Script-based malware delivery (VBS/JS) is blocked.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Script execution concerns: {'; '.join(issues)}",
                    remediation=(
                        "Restrict scripting on workstations: "
                        "1. Disable WSH: "
                        "   New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' "
                        "   -Name Enabled -Value 0 -PropertyType DWord -Force. "
                        "2. Via GPO: User Config > Admin Templates > Windows Components > "
                        "   Windows Script Host > Disable Windows Script Host. "
                        "3. Office macros: Computer Config > Admin Templates > Microsoft Office > Security Settings > "
                        "   'VBA Macro Notification Settings' → Disable all macros with notification (2) or Disable all (3). "
                        "4. Consider AppLocker to restrict .vbs, .js, .wsf, .hta file execution."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LocalSecurityPolicyCheck(BaseCheck):
    """
    WIN-06: Verify local security policy audit settings match HIPAA requirements.
    Missing audit categories mean attacks go undetected. Logon, object access,
    and privilege use events are required for HIPAA audit trails.
    """
    check_id = "WIN-06"
    check_name = "Security Audit Policy Completeness"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase1"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Get all audit policy settings via auditpol
            audit_policy = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /category:* 2>$null | "
                r"Select-String 'Logon|Account Logon|Object Access|Privilege Use|Process Tracking|Policy Change|Account Management|System' | "
                r"Out-String"
            )

            # Check specific required categories
            logon_audit = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /subcategory:'Logon' 2>$null"
            )

            account_mgmt = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /subcategory:'User Account Management' 2>$null"
            )

            object_access = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /subcategory:'File System' 2>$null"
            )

            policy_change = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /subcategory:'Audit Policy Change' 2>$null"
            )

            priv_use = context.winrm.run_ps(
                target.hostname,
                r"auditpol /get /subcategory:'Sensitive Privilege Use' 2>$null"
            )

            def is_audited(auditpol_output: str) -> bool:
                """Returns True if Success or Failure auditing is enabled."""
                lower = auditpol_output.lower()
                return "success" in lower or "failure" in lower

            logon_ok = is_audited(logon_audit)
            account_ok = is_audited(account_mgmt)
            object_ok = is_audited(object_access)
            policy_ok = is_audited(policy_change)
            priv_ok = is_audited(priv_use)

            score = sum([logon_ok, account_ok, object_ok, policy_ok, priv_ok])

            evidence = {
                "logon_auditing": logon_ok,
                "account_management_auditing": account_ok,
                "object_access_auditing": object_ok,
                "policy_change_auditing": policy_ok,
                "privilege_use_auditing": priv_ok,
                "categories_configured": f"{score}/5 required categories",
            }

            if score >= 4:
                return self._pass(
                    target,
                    details=f"Audit policy covers {score}/5 required HIPAA categories. Security event trail is maintained.",
                    evidence=evidence,
                )
            else:
                missing = []
                if not logon_ok:
                    missing.append("Logon/Logoff")
                if not account_ok:
                    missing.append("Account Management")
                if not object_ok:
                    missing.append("Object Access (File System)")
                if not policy_ok:
                    missing.append("Policy Change")
                if not priv_ok:
                    missing.append("Privilege Use")

                return self._fail(
                    target,
                    details=f"Audit policy missing {len(missing)} required categories: {', '.join(missing)}. HIPAA compliance requires logging these events for access and activity monitoring.",
                    remediation=(
                        "Enable required audit categories via GPO: "
                        "Computer Config > Security Settings > Advanced Audit Policy Configuration. "
                        "HIPAA minimum requirements: "
                        "1. Logon/Logoff → Logon: Success and Failure. "
                        "2. Account Management → User Account Management: Success and Failure. "
                        "3. Object Access → File System: Success and Failure (for PHI directories). "
                        "4. Policy Change → Audit Policy Change: Success. "
                        "5. Privilege Use → Sensitive Privilege Use: Success and Failure. "
                        "PowerShell: auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable required HIPAA audit categories:\n"
                        "auditpol /set /subcategory:'Logon' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'Logoff' /success:enable\n"
                        "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'Computer Account Management' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'File System' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable\n"
                        "auditpol /set /subcategory:'Security System Extension' /success:enable /failure:enable\n"
                        "# Verify:\n"
                        "auditpol /get /category:*"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
