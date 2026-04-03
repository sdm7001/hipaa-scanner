"""
Linux/Unix system compliance checks — executed via SSH connector.
HIPAA reference: Multiple — same requirements as Windows but Linux-specific implementation.
NIST SP 800-66r2: Applicable across all OS platforms.

Linux servers in healthcare: EHR backends, DICOM imaging servers, lab systems, VPN concentrators.
Uses SSHConnector (Paramiko) instead of WinRM.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class LinuxSshRootLoginCheck(BaseCheck):
    """
    LNX-01: Verify SSH root login is disabled on Linux servers.
    Root login via SSH means any SSH compromise = full system access and no audit trail per user.
    """
    check_id = "LNX-01"
    check_name = "SSH Root Login Disabled"
    category = "Access Control"
    hipaa_reference = "164.312(a)(1)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 10.0

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ssh:
                return self._na(target, "SSH connector required for Linux checks.")

            result = context.ssh.run_command(
                target.hostname,
                "grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | "
                "grep -v '^#' | tail -1"
            )

            # Also check for override in /etc/ssh/sshd_config.d/
            result_d = context.ssh.run_command(
                target.hostname,
                "grep -ri 'PermitRootLogin' /etc/ssh/sshd_config.d/ 2>/dev/null | "
                "grep -v '^#' | tail -1"
            )

            effective = (result_d.strip() or result.strip()).lower()

            evidence = {
                "sshd_config_value": result.strip(),
                "sshd_config_d_value": result_d.strip(),
                "effective_value": effective,
            }

            # "prohibit-password" or "forced-commands-only" = partially restricted (pass)
            # "no" = fully disabled (pass)
            # "yes" or empty (default) = root login allowed (fail)
            if not effective:
                # Default behavior in most modern distros is to allow root login
                return self._fail(
                    target,
                    details="PermitRootLogin not explicitly set in sshd_config — defaults to 'yes' on older systems. Root SSH access may be permitted.",
                    remediation=(
                        "Add 'PermitRootLogin no' to /etc/ssh/sshd_config and restart sshd. "
                        "Use sudo for administrative tasks. "
                        "systemctl restart sshd (RHEL/CentOS) or service ssh restart (Debian/Ubuntu)"
                    ),
                    evidence=evidence,
                )
            elif "no" in effective or "prohibit-password" in effective or "forced-commands-only" in effective:
                return self._pass(
                    target,
                    details=f"SSH root login restricted: {effective.split(':')[-1].strip()}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"SSH root login is permitted ({effective.split(':')[-1].strip()}). Direct root access eliminates individual user accountability.",
                    remediation=(
                        "Set PermitRootLogin no in /etc/ssh/sshd_config:\n"
                        "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                        "sudo systemctl restart sshd\n"
                        "Ensure at least one admin user has sudo access before applying this change."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Disable root SSH login:\n"
                        "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                        "echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config\n"
                        "sudo systemctl restart sshd"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxSshProtocolCheck(BaseCheck):
    """
    LNX-02: Verify SSH uses Protocol 2 only and strong ciphers.
    SSH Protocol 1 has known vulnerabilities. Weak ciphers (3DES, RC4) compromise ePHI in transit.
    """
    check_id = "LNX-02"
    check_name = "SSH Protocol Version and Cipher Strength"
    category = "Transmission Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    # Weak ciphers to flag
    WEAK_CIPHERS = {"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc"}

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ssh:
                return self._na(target, "SSH connector required for Linux checks.")

            # Check protocol version (Protocol 1 is deprecated/broken)
            proto_result = context.ssh.run_command(
                target.hostname,
                "grep -i 'Protocol' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
            )

            # Check configured ciphers
            cipher_result = context.ssh.run_command(
                target.hostname,
                "grep -i 'Ciphers' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
            )

            # Check MACs (message authentication codes)
            mac_result = context.ssh.run_command(
                target.hostname,
                "grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
            )

            # Check supported ciphers from running SSH server
            server_ciphers = context.ssh.run_command(
                target.hostname,
                "sshd -T 2>/dev/null | grep '^ciphers' | head -1"
            )

            proto_val = proto_result.strip()
            cipher_val = cipher_result.strip()

            has_proto1 = "1" in proto_val and "2" not in proto_val.replace("21", "")
            configured_ciphers = cipher_val.split()[-1].split(",") if cipher_val else []
            weak_found = [c for c in configured_ciphers if c.lower() in self.WEAK_CIPHERS]

            evidence = {
                "protocol_line": proto_val or "not configured (modern OpenSSH defaults to 2)",
                "cipher_line": cipher_val,
                "weak_ciphers_found": weak_found,
                "server_ciphers": server_ciphers.strip()[:200],
            }

            if has_proto1:
                return self._fail(
                    target,
                    details="SSH Protocol 1 is enabled or configured. Protocol 1 has fundamental cryptographic weaknesses.",
                    remediation=(
                        "Remove 'Protocol 1' from sshd_config. Modern OpenSSH (7.0+) disables Protocol 1 by default. "
                        "If using very old OpenSSH, upgrade immediately: the server may be running an EOL version."
                    ),
                    evidence=evidence,
                )
            elif weak_found:
                return self._fail(
                    target,
                    details=f"Weak SSH ciphers explicitly configured: {', '.join(weak_found)}. These can be exploited to decrypt ePHI in transit.",
                    remediation=(
                        "Replace weak ciphers in /etc/ssh/sshd_config with strong alternatives:\n"
                        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"
                        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
                        "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Harden SSH ciphers (add to /etc/ssh/sshd_config):\n"
                        "cat >> /etc/ssh/sshd_config << 'EOF'\n"
                        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr\n"
                        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
                        "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512\n"
                        "EOF\n"
                        "systemctl restart sshd"
                    ),
                )
            else:
                return self._pass(
                    target,
                    details="SSH Protocol 1 not configured; no weak ciphers explicitly enabled.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxFirewallCheck(BaseCheck):
    """
    LNX-03: Verify Linux firewall (iptables/nftables/ufw/firewalld) is enabled.
    Linux servers in healthcare often have no host-based firewall, relying solely on perimeter.
    """
    check_id = "LNX-03"
    check_name = "Linux Host Firewall"
    category = "Network Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ssh:
                return self._na(target, "SSH connector required for Linux checks.")

            # Check firewalld (RHEL/CentOS/Fedora)
            firewalld = context.ssh.run_command(
                target.hostname,
                "systemctl is-active firewalld 2>/dev/null || echo 'inactive'"
            )

            # Check ufw (Ubuntu/Debian)
            ufw = context.ssh.run_command(
                target.hostname,
                "ufw status 2>/dev/null | head -1 || echo 'not installed'"
            )

            # Check iptables rules count (at least INPUT chain rules)
            iptables = context.ssh.run_command(
                target.hostname,
                "iptables -L INPUT --line-numbers 2>/dev/null | grep -c '^[0-9]' || echo '0'"
            )

            # Check nftables
            nftables = context.ssh.run_command(
                target.hostname,
                "nft list ruleset 2>/dev/null | wc -l || echo '0'"
            )

            firewalld_active = "active" in firewalld.strip().lower()
            ufw_active = "active" in ufw.strip().lower()
            iptables_rules = int(iptables.strip()) if iptables.strip().isdigit() else 0
            nftables_rules = int(nftables.strip()) if nftables.strip().isdigit() else 0

            has_firewall = firewalld_active or ufw_active or iptables_rules > 0 or nftables_rules > 10

            evidence = {
                "firewalld": firewalld.strip(),
                "ufw": ufw.strip(),
                "iptables_input_rules": iptables_rules,
                "nftables_lines": nftables_rules,
            }

            if has_firewall:
                active_fw = (
                    "firewalld" if firewalld_active else
                    "ufw" if ufw_active else
                    f"iptables ({iptables_rules} rules)" if iptables_rules else
                    f"nftables ({nftables_rules} lines)"
                )
                return self._pass(
                    target,
                    details=f"Linux host firewall active: {active_fw}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No active host-based firewall detected on this Linux server. All network ports are potentially exposed.",
                    remediation=(
                        "Enable and configure host-based firewall:\n"
                        "Ubuntu/Debian: ufw enable && ufw default deny incoming && ufw allow ssh\n"
                        "RHEL/CentOS: systemctl enable --now firewalld && firewall-cmd --permanent --add-service=ssh && firewall-cmd --reload\n"
                        "Allow only required ports. Block all others by default."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable UFW (Ubuntu/Debian):\n"
                        "ufw default deny incoming\n"
                        "ufw default allow outgoing\n"
                        "ufw allow ssh\n"
                        "ufw --force enable\n"
                        "\n"
                        "# Enable firewalld (RHEL/CentOS):\n"
                        "# systemctl enable --now firewalld\n"
                        "# firewall-cmd --permanent --add-service=ssh --zone=public\n"
                        "# firewall-cmd --reload"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxAuditdCheck(BaseCheck):
    """
    LNX-04: Verify auditd (Linux Audit Framework) is enabled and running.
    auditd provides the Linux equivalent of Windows Security event log — mandatory for HIPAA 164.312(b).
    """
    check_id = "LNX-04"
    check_name = "Linux Audit Framework (auditd)"
    category = "Audit Controls"
    hipaa_reference = "164.312(b)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ssh:
                return self._na(target, "SSH connector required for Linux checks.")

            # Check auditd service
            auditd_status = context.ssh.run_command(
                target.hostname,
                "systemctl is-active auditd 2>/dev/null || echo 'inactive'"
            )

            # Check audit rules count
            audit_rules = context.ssh.run_command(
                target.hostname,
                "auditctl -l 2>/dev/null | grep -v '^No rules' | wc -l || echo '0'"
            )

            # Check if key HIPAA-relevant rules exist (file access, user auth, privileged commands)
            key_rules = context.ssh.run_command(
                target.hostname,
                "auditctl -l 2>/dev/null | grep -E 'identity|logins|session|perm_mod|access|privileged' | wc -l || echo '0'"
            )

            # Check audit log path and retention
            audit_log_path = context.ssh.run_command(
                target.hostname,
                "grep 'log_file' /etc/audit/auditd.conf 2>/dev/null | grep -v '#' | head -1"
            )

            # Check max log file count (retention indicator)
            max_log_files = context.ssh.run_command(
                target.hostname,
                "grep 'num_logs' /etc/audit/auditd.conf 2>/dev/null | grep -v '#' | head -1"
            )

            is_active = "active" in auditd_status.strip().lower()
            rule_count = int(audit_rules.strip()) if audit_rules.strip().isdigit() else 0
            key_rule_count = int(key_rules.strip()) if key_rules.strip().isdigit() else 0

            evidence = {
                "auditd_status": auditd_status.strip(),
                "total_audit_rules": rule_count,
                "hipaa_relevant_rules": key_rule_count,
                "log_path": audit_log_path.strip(),
                "log_retention": max_log_files.strip(),
            }

            if is_active and key_rule_count >= 3:
                return self._pass(
                    target,
                    details=f"auditd running with {rule_count} rules ({key_rule_count} HIPAA-relevant).",
                    evidence=evidence,
                )
            elif is_active and rule_count > 0:
                return self._fail(
                    target,
                    details=f"auditd running but only {key_rule_count} HIPAA-relevant rules configured. Key events (login, file access, privilege use) may not be captured.",
                    remediation=(
                        "Add HIPAA-required audit rules to /etc/audit/audit.rules:\n"
                        "Use the CIS Linux Benchmark auditd rule set or DISA STIG auditd profile. "
                        "Key rules: -w /etc/passwd -p wa -k identity, "
                        "-a always,exit -F arch=b64 -S execve -k privileged"
                    ),
                    evidence=evidence,
                )
            elif is_active:
                return self._fail(
                    target,
                    details="auditd is running but no audit rules are configured. The service is collecting nothing.",
                    remediation=(
                        "Configure audit rules. Install the CIS or STIG audit rules package:\n"
                        "RHEL: yum install audit-rules-oscap\n"
                        "Or manually add rules to /etc/audit/rules.d/hipaa.rules"
                    ),
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="auditd is not running. No audit trail exists for file access, authentication, or privilege escalation on this Linux server.",
                    remediation=(
                        "Enable and start auditd:\n"
                        "systemctl enable auditd && systemctl start auditd\n"
                        "Then configure rules per HIPAA 164.312(b) requirements."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Enable auditd with basic HIPAA rules:\n"
                        "systemctl enable auditd && systemctl start auditd\n"
                        "cat > /etc/audit/rules.d/hipaa.rules << 'EOF'\n"
                        "-w /etc/passwd -p wa -k identity\n"
                        "-w /etc/group -p wa -k identity\n"
                        "-w /etc/shadow -p wa -k identity\n"
                        "-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access\n"
                        "-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged\n"
                        "EOF\n"
                        "augenrules --load"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))


class LinuxPasswordPolicyCheck(BaseCheck):
    """
    LNX-05: Verify Linux password policy meets HIPAA requirements.
    Tests: /etc/login.defs minimum/maximum age, PAM password complexity, pwquality settings.
    """
    check_id = "LNX-05"
    check_name = "Linux Password Policy"
    category = "Access Control"
    hipaa_reference = "164.312(a)(2)(i)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 7.0

    MIN_LEN = 12
    MAX_DAYS = 90

    def run(self, target: Target, context) -> Finding:
        try:
            if not context.ssh:
                return self._na(target, "SSH connector required for Linux checks.")

            # /etc/login.defs
            pass_max_days = context.ssh.run_command(
                target.hostname,
                "grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'"
            )
            pass_min_len = context.ssh.run_command(
                target.hostname,
                "grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}'"
            )

            # PAM pwquality
            pwquality_minlen = context.ssh.run_command(
                target.hostname,
                "grep 'minlen' /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | awk -F= '{print $2}'"
            )
            pwquality_complexity = context.ssh.run_command(
                target.hostname,
                "grep -E 'dcredit|ucredit|lcredit|ocredit' /etc/security/pwquality.conf 2>/dev/null | "
                "grep -v '^#' | wc -l"
            )

            max_days = int(pass_max_days.strip()) if pass_max_days.strip().isdigit() else 99999
            min_len_login = int(pass_min_len.strip()) if pass_min_len.strip().isdigit() else 6
            min_len_pam = int(pwquality_minlen.strip()) if pwquality_minlen.strip().isdigit() else 0
            effective_min_len = max(min_len_login, min_len_pam)
            complexity_rules = int(pwquality_complexity.strip()) if pwquality_complexity.strip().isdigit() else 0

            evidence = {
                "pass_max_days": max_days,
                "pass_min_len_login_defs": min_len_login,
                "pass_min_len_pwquality": min_len_pam,
                "effective_min_len": effective_min_len,
                "complexity_rules_count": complexity_rules,
            }

            issues = []
            if effective_min_len < self.MIN_LEN:
                issues.append(f"minimum password length {effective_min_len} < required {self.MIN_LEN}")
            if max_days > self.MAX_DAYS:
                issues.append(f"password max age {max_days} days > recommended {self.MAX_DAYS}")
            if complexity_rules < 2:
                issues.append("insufficient password complexity rules in pwquality.conf")

            if not issues:
                return self._pass(
                    target,
                    details=f"Linux password policy meets requirements: min length {effective_min_len}, max age {max_days} days.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details=f"Linux password policy deficiencies: {'; '.join(issues)}.",
                    remediation=(
                        "Configure /etc/security/pwquality.conf:\n"
                        "minlen = 12\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n\n"
                        "Configure /etc/login.defs:\nPASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n\n"
                        "Apply to existing users: chage -M 90 <username>"
                    ),
                    evidence=evidence,
                    remediation_script=(
                        "# Set Linux password policy:\n"
                        "# Edit /etc/security/pwquality.conf:\n"
                        "sed -i 's/# minlen.*/minlen = 12/' /etc/security/pwquality.conf || "
                        "echo 'minlen = 12' >> /etc/security/pwquality.conf\n"
                        "# Edit /etc/login.defs:\n"
                        "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs\n"
                        "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs"
                    ),
                )
        except Exception as e:
            return self._error(target, str(e))
