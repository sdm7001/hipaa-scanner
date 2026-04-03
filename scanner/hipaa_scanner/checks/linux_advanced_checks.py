"""
Advanced Linux/Unix security checks.
HIPAA reference: 164.312(a)(1), 164.312(b) — Access Control and Audit Controls

Healthcare increasingly runs Linux for EHR backends, databases, and PACS systems.
These checks extend the basic linux_checks.py with deeper hardening verification.
All checks use SSH connector (context.ssh).
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class LinuxSudoConfigCheck(BaseCheck):
    """
    LNX-06: Verify sudo configuration follows least-privilege principles.
    Unrestricted sudo access (ALL=(ALL:ALL) ALL without password) is equivalent
    to root access and violates HIPAA minimum necessary access controls.
    """
    check_id = "LNX-06"
    check_name = "Linux sudo Configuration (Least Privilege)"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        if not context.ssh:
            return self._na(target, "SSH connector required for Linux checks.")
        try:
            # Get sudoers config (safe - just reading)
            sudoers = context.ssh.run_command(target.hostname, "sudo cat /etc/sudoers 2>/dev/null || cat /etc/sudoers 2>/dev/null")

            # Check sudoers.d directory
            sudoers_d = context.ssh.run_command(target.hostname, "sudo ls /etc/sudoers.d/ 2>/dev/null")

            # Check for NOPASSWD entries (dangerous)
            nopasswd = context.ssh.run_command(
                target.hostname,
                "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'"
            )

            # Check for ALL=(ALL) ALL entries (unrestricted sudo)
            all_access = context.ssh.run_command(
                target.hostname,
                "grep -r 'ALL=(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | grep -v 'sudo\\|wheel\\|admin'"
            )

            # Users in sudo/wheel group
            sudo_users = context.ssh.run_command(
                target.hostname,
                "getent group sudo wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\\n' | sort -u"
            )

            nopasswd_lines = [l.strip() for l in nopasswd.splitlines() if l.strip() and not l.strip().startswith("#")]
            unrestricted_lines = [l.strip() for l in all_access.splitlines() if l.strip() and not l.strip().startswith("#")]
            sudo_user_list = [u.strip() for u in sudo_users.splitlines() if u.strip()]

            evidence = {
                "nopasswd_entries": len(nopasswd_lines),
                "nopasswd_samples": nopasswd_lines[:3],
                "unrestricted_sudo_entries": len(unrestricted_lines),
                "unrestricted_samples": unrestricted_lines[:3],
                "sudo_group_members": sudo_user_list[:10],
                "sudo_member_count": len(sudo_user_list),
            }

            issues = []
            if nopasswd_lines:
                issues.append(f"{len(nopasswd_lines)} NOPASSWD sudo entries (no password required for privilege escalation)")
            if unrestricted_lines:
                issues.append(f"{len(unrestricted_lines)} user entries with unrestricted ALL=(ALL) sudo (beyond sudo/wheel group)")
            if len(sudo_user_list) > 5:
                issues.append(f"{len(sudo_user_list)} users in sudo/wheel group — review for necessity")

            if not issues:
                return self._pass(
                    target,
                    details=f"sudo configuration appears appropriately restricted. {len(sudo_user_list)} users in sudo/wheel group, no NOPASSWD entries.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"sudo configuration issues: {'; '.join(issues)}",
                    remediation=(
                        "Restrict sudo access per least-privilege principle: "
                        "1. Remove NOPASSWD: Edit /etc/sudoers with 'sudo visudo' — remove NOPASSWD from entries. "
                        "2. Use specific command restrictions instead of ALL: "
                        "   username ALL=(ALL) /usr/bin/systemctl restart nginx, /usr/bin/apt. "
                        "3. Limit sudo group membership to necessary administrators only. "
                        "4. Enable sudo logging: Defaults log_input,log_output,iolog_dir=/var/log/sudo-io/. "
                        "5. Require re-authentication: Defaults timestamp_timeout=0 (always require password)."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxUnattendedUpgradesCheck(BaseCheck):
    """
    LNX-07: Verify automatic security updates are configured.
    Linux servers without automatic security patching accumulate known vulnerabilities.
    HIPAA requires timely patching; 2025 NPRM specifies 15-day critical patch timeline.
    """
    check_id = "LNX-07"
    check_name = "Linux Automatic Security Updates"
    category = "Patch Management"
    hipaa_reference = "164.308(a)(5)(ii)(B)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        if not context.ssh:
            return self._na(target, "SSH connector required for Linux checks.")
        try:
            # Check unattended-upgrades (Debian/Ubuntu)
            unattended = context.ssh.run_command(
                target.hostname,
                "systemctl is-active unattended-upgrades 2>/dev/null; "
                "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii' | head -1"
            )

            # Check dnf-automatic (RHEL/CentOS/Rocky/AlmaLinux)
            dnf_auto = context.ssh.run_command(
                target.hostname,
                "systemctl is-active dnf-automatic.timer 2>/dev/null; "
                "systemctl is-active yum-cron 2>/dev/null"
            )

            # Check if auto-updates are configured (Ubuntu-specific config)
            auto_upgrade_conf = context.ssh.run_command(
                target.hostname,
                "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | head -5"
            )

            # Check last package update
            last_update = context.ssh.run_command(
                target.hostname,
                "stat -c %y /var/lib/apt/lists/ 2>/dev/null | cut -d' ' -f1; "
                "stat -c %y /var/cache/yum/ 2>/dev/null | cut -d' ' -f1"
            )

            # Count available security updates
            pending_security = context.ssh.run_command(
                target.hostname,
                "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || "
                "yum check-update --security 2>/dev/null | grep -c 'updates' || echo 'unknown'"
            )

            unattended_active = "active" in unattended.lower() or "ii  unattended" in unattended.lower()
            dnf_active = "active" in dnf_auto.lower()
            auto_upgrade_ok = "1" in auto_upgrade_conf if auto_upgrade_conf.strip() else False

            auto_patching = unattended_active or dnf_active

            evidence = {
                "unattended_upgrades_status": "active" if unattended_active else "inactive/not installed",
                "dnf_automatic_status": "active" if dnf_active else "inactive/not installed",
                "auto_upgrade_config": auto_upgrade_conf.strip()[:200] if auto_upgrade_conf.strip() else "not found",
                "last_package_cache_update": last_update.strip()[:50] if last_update.strip() else "unknown",
                "pending_updates_estimate": pending_security.strip()[:50],
            }

            if auto_patching:
                return self._pass(
                    target,
                    details="Automatic security updates are configured and active. Security patches will be applied without manual intervention.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="Automatic security updates are not configured. Security patches require manual intervention and may be delayed.",
                    remediation=(
                        "Configure automatic security updates: "
                        "Debian/Ubuntu: "
                        "  apt install unattended-upgrades; "
                        "  dpkg-reconfigure --priority=low unattended-upgrades. "
                        "  Edit /etc/apt/apt.conf.d/50unattended-upgrades to enable Unattended-Upgrade::Automatic-Reboot. "
                        "RHEL/CentOS/Rocky: "
                        "  dnf install dnf-automatic; "
                        "  Edit /etc/dnf/automatic.conf: apply_updates = yes; "
                        "  systemctl enable --now dnf-automatic.timer. "
                        "2025 HIPAA NPRM requires critical vulnerability patching within 15 days."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxFilePermissionsCheck(BaseCheck):
    """
    LNX-08: Verify critical system file permissions are not world-writable
    and sensitive files are properly restricted. World-writable system files
    allow any user to modify system configuration or inject malicious code.
    """
    check_id = "LNX-08"
    check_name = "Linux Critical File Permissions"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        if not context.ssh:
            return self._na(target, "SSH connector required for Linux checks.")
        try:
            # Find world-writable files in system directories (excluding /tmp, /var/tmp)
            world_writable = context.ssh.run_command(
                target.hostname,
                "find /etc /usr/bin /usr/sbin /bin /sbin -perm -002 -type f 2>/dev/null | head -10"
            )

            # Check /etc/passwd permissions (should be 644)
            passwd_perms = context.ssh.run_command(
                target.hostname,
                "stat -c '%a %U' /etc/passwd 2>/dev/null"
            )

            # Check /etc/shadow permissions (should be 000 or 640)
            shadow_perms = context.ssh.run_command(
                target.hostname,
                "stat -c '%a %U' /etc/shadow 2>/dev/null"
            )

            # Check /etc/sudoers permissions (should be 440)
            sudoers_perms = context.ssh.run_command(
                target.hostname,
                "stat -c '%a %U' /etc/sudoers 2>/dev/null"
            )

            # Check for SUID/SGID files outside standard locations
            unusual_suid = context.ssh.run_command(
                target.hostname,
                "find / -perm /6000 -type f 2>/dev/null | "
                "grep -v '/bin/\\|/sbin/\\|/usr/bin/\\|/usr/sbin/\\|/usr/lib/\\|/lib/' | head -10"
            )

            ww_files = [l.strip() for l in world_writable.splitlines() if l.strip()]
            suid_files = [l.strip() for l in unusual_suid.splitlines() if l.strip()]

            # Check shadow permissions (should be 000 or 400 or 640, NOT 644 or 666)
            shadow_ok = True
            if shadow_perms.strip():
                try:
                    shadow_mode = int(shadow_perms.strip().split()[0])
                    shadow_ok = shadow_mode <= 640
                except (ValueError, IndexError):
                    shadow_ok = False

            # Check sudoers permissions (should be <= 440)
            sudoers_ok = True
            if sudoers_perms.strip():
                try:
                    sudoers_mode = int(sudoers_perms.strip().split()[0])
                    sudoers_ok = sudoers_mode <= 440
                except (ValueError, IndexError):
                    sudoers_ok = False

            evidence = {
                "world_writable_system_files": ww_files,
                "passwd_permissions": passwd_perms.strip(),
                "shadow_permissions": shadow_perms.strip(),
                "sudoers_permissions": sudoers_perms.strip(),
                "unusual_suid_files": suid_files[:5],
            }

            issues = []
            if ww_files:
                issues.append(f"{len(ww_files)} world-writable files in system directories: {', '.join(ww_files[:3])}")
            if not shadow_ok:
                issues.append(f"/etc/shadow permissions {shadow_perms.strip()} — should be 000/400/640 (password hashes exposed)")
            if not sudoers_ok:
                issues.append(f"/etc/sudoers permissions {sudoers_perms.strip()} — should be 440")
            if suid_files:
                issues.append(f"{len(suid_files)} unusual SUID/SGID files outside standard paths: {', '.join(suid_files[:2])}")

            if not issues:
                return self._pass(
                    target,
                    details="Critical system file permissions are correctly set. No world-writable system files or unusual SUID binaries detected.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"File permission issues: {'; '.join(issues)}",
                    remediation=(
                        "Fix critical file permissions: "
                        "1. Remove world-writable: chmod o-w <file> for each identified file. "
                        "2. Fix /etc/shadow: chmod 640 /etc/shadow; chown root:shadow /etc/shadow. "
                        "3. Fix /etc/sudoers: chmod 440 /etc/sudoers. "
                        "4. Review SUID files: ls -la <suid-file> — remove SUID if not needed: chmod u-s <file>. "
                        "5. Find all world-writable in system dirs: find /etc /usr/bin /usr/sbin -perm -002 -type f. "
                        "6. Periodic permission audit: aide --check (if AIDE is installed)."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxDiskEncryptionCheck(BaseCheck):
    """
    LNX-09: Verify Linux disk encryption (LUKS) is configured for data partitions.
    Unencrypted Linux disks on healthcare servers expose PHI in case of physical theft
    or disk disposal. HIPAA 164.312(a)(2)(iv) — encryption at rest required.
    """
    check_id = "LNX-09"
    check_name = "Linux Disk Encryption (LUKS)"
    category = "Encryption at Rest"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER, TargetRole.WORKSTATION]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        if not context.ssh:
            return self._na(target, "SSH connector required for Linux checks.")
        try:
            # Check for LUKS encrypted volumes
            luks_devices = context.ssh.run_command(
                target.hostname,
                "lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT 2>/dev/null | grep -i 'crypt\\|luks' | head -10"
            )

            # Check dmsetup for encrypted mappings
            dm_crypt = context.ssh.run_command(
                target.hostname,
                "dmsetup ls --target crypt 2>/dev/null | head -10"
            )

            # Check if root partition is encrypted
            root_encrypted = context.ssh.run_command(
                target.hostname,
                "lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep '/$' | head -3"
            )

            # Check for LUKS headers on block devices
            cryptsetup_check = context.ssh.run_command(
                target.hostname,
                "lsblk -d -o NAME 2>/dev/null | while read dev; do "
                "  cryptsetup isLuks /dev/$dev 2>/dev/null && echo \"$dev: LUKS\"; "
                "done 2>/dev/null | head -10"
            )

            # Check /etc/crypttab (persistent encrypted volume config)
            crypttab = context.ssh.run_command(
                target.hostname,
                "cat /etc/crypttab 2>/dev/null | grep -v '^#' | head -10"
            )

            luks_found = bool(luks_devices.strip()) or bool(dm_crypt.strip()) or bool(cryptsetup_check.strip())
            crypttab_configured = bool(crypttab.strip())

            # Check if root is on encrypted volume (best practice)
            root_on_crypt = "crypt" in root_encrypted.lower() or "luks" in root_encrypted.lower()

            evidence = {
                "luks_devices": luks_devices.strip()[:300] if luks_devices.strip() else "none detected",
                "dm_crypt_mappings": dm_crypt.strip()[:200] if dm_crypt.strip() else "none",
                "crypttab_entries": crypttab.strip()[:200] if crypttab.strip() else "not configured",
                "root_encrypted": root_on_crypt,
            }

            if luks_found or crypttab_configured:
                return self._pass(
                    target,
                    details=f"LUKS disk encryption detected. {'Root partition is encrypted.' if root_on_crypt else 'Verify PHI data partitions are included in encryption.'}",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No LUKS disk encryption detected on this Linux system. PHI stored on unencrypted disks is at risk if physical media is lost or improperly disposed.",
                    remediation=(
                        "Implement LUKS encryption: "
                        "NEW INSTALLS (preferred): "
                        "  Select 'Encrypt disk' during OS installation. "
                        "  Ubuntu Server: storage layout → select disk → Format → Set as ext4 → check 'Encrypt with LUKS'. "
                        "EXISTING SYSTEMS (disruptive - requires backup and reinstall): "
                        "  1. Back up all data. "
                        "  2. cryptsetup luksFormat /dev/sdX (destroys existing data). "
                        "  3. cryptsetup luksOpen /dev/sdX encrypted_data. "
                        "  4. mkfs.ext4 /dev/mapper/encrypted_data. "
                        "  5. Add to /etc/crypttab for auto-mount. "
                        "MINIMUM: Encrypt the data partition containing PHI (/var/lib, /data, database directories)."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxSyslogCheck(BaseCheck):
    """
    LNX-10: Verify system logging (syslog/journald) is properly configured
    and sending logs to a remote log server for HIPAA audit trail requirements.
    Local-only logs are at risk from deletion during a breach incident.
    """
    check_id = "LNX-10"
    check_name = "Linux System Logging and Remote Syslog"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        if not context.ssh:
            return self._na(target, "SSH connector required for Linux checks.")
        try:
            # Check rsyslog service
            rsyslog = context.ssh.run_command(
                target.hostname,
                "systemctl is-active rsyslog 2>/dev/null"
            )

            # Check syslog-ng
            syslog_ng = context.ssh.run_command(
                target.hostname,
                "systemctl is-active syslog-ng 2>/dev/null"
            )

            # Check journald remote forwarding
            journald_fwd = context.ssh.run_command(
                target.hostname,
                "cat /etc/systemd/journald.conf 2>/dev/null | grep -E 'ForwardToSyslog|Storage'"
            )

            # Check if rsyslog is configured to forward to remote server
            remote_syslog = context.ssh.run_command(
                target.hostname,
                "grep -E '^[^#].*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -5"
            )

            # Check for Splunk Universal Forwarder or Elastic Agent
            splunk_fwd = context.ssh.run_command(
                target.hostname,
                "systemctl is-active SplunkForwarder 2>/dev/null; "
                "systemctl is-active elastic-agent 2>/dev/null; "
                "systemctl is-active filebeat 2>/dev/null; "
                "systemctl is-active fluentd 2>/dev/null"
            )

            # Check log rotation
            logrotate = context.ssh.run_command(
                target.hostname,
                "cat /etc/logrotate.conf 2>/dev/null | grep -E 'rotate|compress' | head -5"
            )

            rsyslog_active = "active" in rsyslog.strip().lower()
            syslog_ng_active = "active" in syslog_ng.strip().lower()
            syslog_running = rsyslog_active or syslog_ng_active

            remote_configured = bool(remote_syslog.strip())
            siem_agent = any("active" in line.lower() for line in splunk_fwd.splitlines() if line.strip())

            log_forwarding = remote_configured or siem_agent

            evidence = {
                "rsyslog_status": rsyslog.strip() or "not installed",
                "syslog_ng_status": syslog_ng.strip() or "not installed",
                "remote_syslog_configured": remote_configured,
                "remote_config_sample": remote_syslog.strip()[:150] if remote_syslog.strip() else "not configured",
                "siem_agent_active": siem_agent,
            }

            if syslog_running and log_forwarding:
                return self._pass(
                    target,
                    details=f"System logging active ({'rsyslog' if rsyslog_active else 'syslog-ng'}) with remote log forwarding configured. Audit trail protected from local tampering.",
                    evidence=evidence,
                )
            elif syslog_running:
                return self._fail(
                    target,
                    details="System logging is active but logs are local only — no remote syslog or SIEM forwarding detected. Local logs can be tampered with during a breach.",
                    remediation=(
                        "Configure remote log forwarding: "
                        "rsyslog — add to /etc/rsyslog.conf: "
                        "  *.* @@siem-server.domain.com:514  (TCP, double @@). "
                        "  *.* @siem-server.domain.com:514   (UDP, single @). "
                        "Restart: systemctl restart rsyslog. "
                        "Or install Splunk UF: "
                        "  Download universal forwarder, configure outputs.conf with SIEM server. "
                        "HIPAA requires audit logs be protected from unauthorized modification — remote logging is essential."
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No system logging service (rsyslog/syslog-ng) is active. System events are not being recorded — HIPAA audit trail requirement is unmet.",
                    remediation=(
                        "Install and configure system logging: "
                        "Debian/Ubuntu: apt install rsyslog && systemctl enable --now rsyslog. "
                        "RHEL/Rocky: dnf install rsyslog && systemctl enable --now rsyslog. "
                        "After installing rsyslog, configure remote forwarding as described above."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
