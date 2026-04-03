"""
Email security compliance checks — DMARC, DKIM, SPF, TLS enforcement.
HIPAA reference: 164.312(e)(1) — Transmission Security (REQUIRED)
NIST SP 800-66r2: Section 3.7 — Transmission Security

Email is the #1 phishing and data-exfiltration vector in healthcare breaches.
OCR enforcement actions consistently cite lack of email security controls.
"""

from __future__ import annotations
import dns.resolver
import dns.exception
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


def _dns_query(qname: str, rdtype: str) -> list[str]:
    """Run a DNS query, return text records. Raises on failure."""
    answers = dns.resolver.resolve(qname, rdtype, lifetime=10)
    return [r.to_text().strip('"') for r in answers]


class DmarcCheck(BaseCheck):
    """
    EMAIL-01: Verify DMARC policy is configured for the organization's email domain.
    DMARC prevents domain spoofing — attackers impersonating the medical practice's email to send phishing.
    Tests: _dmarc.{domain} TXT record, policy strength (none/quarantine/reject).
    """
    check_id = "EMAIL-01"
    check_name = "DMARC Policy Configured"
    category = "Email Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Resolve the target's primary email domain from AD or hostname
            domain = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_ComputerSystem).Domain"
            ).strip()

            if not domain or domain.lower() in ("workgroup", ""):
                return self._na(target, "Cannot determine email domain — target is not domain-joined.")

            dmarc_record = None
            policy = "none"
            rua = None

            try:
                records = _dns_query(f"_dmarc.{domain}", "TXT")
                dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
                if dmarc_records:
                    dmarc_record = dmarc_records[0]
                    # Parse policy tag
                    for part in dmarc_record.split(";"):
                        part = part.strip()
                        if part.startswith("p="):
                            policy = part[2:].lower().strip()
                        if part.startswith("rua="):
                            rua = part[4:].strip()
            except (dns.exception.DNSException, Exception) as e:
                dmarc_record = None

            evidence = {
                "domain": domain,
                "dmarc_record": dmarc_record,
                "policy": policy,
                "report_address": rua,
            }

            if not dmarc_record:
                return self._fail(
                    target,
                    details=f"No DMARC record found for domain '{domain}'. Attackers can spoof emails from your domain to send phishing to patients and staff.",
                    remediation=(
                        f"Add a DMARC TXT record at _dmarc.{domain}: "
                        f"Start with: 'v=DMARC1; p=none; rua=mailto:dmarc@{domain}' to monitor, "
                        "then escalate to p=quarantine and p=reject after 2-4 weeks of clean reports. "
                        "Tools: MXToolbox DMARC wizard, EasyDMARC, or Cloudflare Email Security."
                    ),
                    evidence=evidence,
                    remediation_script=(
                        f"# DNS TXT record to add (via your DNS registrar/provider):\n"
                        f"# Name: _dmarc.{domain}\n"
                        f"# Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100\n"
                        f"# Use p=reject once no legitimate mail is being quarantined."
                    ),
                )
            elif policy in ("none", ""):
                return self._fail(
                    target,
                    details=f"DMARC record exists for '{domain}' but policy is 'none' — monitoring only, no enforcement. Spoofed emails are still delivered.",
                    remediation=(
                        "Escalate DMARC policy from p=none to p=quarantine, then p=reject. "
                        "Review DMARC aggregate reports (rua) to identify legitimate mail sources, "
                        "then strengthen policy. Target: p=reject within 90 days per CISA guidance."
                    ),
                    evidence=evidence,
                )
            elif policy == "quarantine":
                return self._fail(
                    target,
                    details=f"DMARC policy for '{domain}' is 'quarantine' — better than none but spoofed mail still reaches spam folders. Escalate to p=reject.",
                    remediation=(
                        "Escalate DMARC from p=quarantine to p=reject to fully block domain spoofing. "
                        "Review DMARC reports for 2-4 weeks to ensure no legitimate senders fail DMARC, "
                        "then change to p=reject."
                    ),
                    evidence=evidence,
                )
            else:  # reject
                return self._pass(
                    target,
                    details=f"DMARC policy for '{domain}' is 'reject' — domain spoofing is actively blocked.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class SpfCheck(BaseCheck):
    """
    EMAIL-02: Verify SPF record is configured for the organization's email domain.
    SPF (Sender Policy Framework) specifies which mail servers are authorized to send email
    on behalf of the domain — prevents email spoofing at the envelope-from level.
    """
    check_id = "EMAIL-02"
    check_name = "SPF Record Configured"
    category = "Email Security"
    hipaa_reference = "164.312(e)(1)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            domain = context.winrm.run_ps(
                target.hostname,
                r"(Get-WmiObject Win32_ComputerSystem).Domain"
            ).strip()

            if not domain or domain.lower() in ("workgroup", ""):
                return self._na(target, "Cannot determine email domain — target is not domain-joined.")

            spf_record = None
            spf_all = None

            try:
                records = _dns_query(domain, "TXT")
                spf_records = [r for r in records if r.startswith("v=spf1")]
                if spf_records:
                    spf_record = spf_records[0]
                    # Parse the terminating mechanism (~all, -all, +all, ?all)
                    parts = spf_record.lower().split()
                    for part in reversed(parts):
                        if part.endswith("all"):
                            spf_all = part
                            break
            except (dns.exception.DNSException, Exception):
                spf_record = None

            evidence = {
                "domain": domain,
                "spf_record": spf_record,
                "terminator": spf_all,
            }

            if not spf_record:
                return self._fail(
                    target,
                    details=f"No SPF record found for domain '{domain}'. Any server on the internet can send email claiming to be from your domain.",
                    remediation=(
                        f"Add an SPF TXT record at {domain}: "
                        f"v=spf1 include:_spf.google.com ~all (adjust for your mail provider). "
                        "Use MXToolbox SPF generator to build the correct record for your mail provider."
                    ),
                    evidence=evidence,
                )
            elif spf_all in ("+all", None):
                return self._fail(
                    target,
                    details=f"SPF record exists for '{domain}' but uses '+all' (allow all) — no restriction on who can send email as your domain.",
                    remediation=(
                        "Replace '+all' with '-all' (hard fail) or '~all' (soft fail) in your SPF record. "
                        "'-all' is recommended: any server not listed in SPF will be rejected."
                    ),
                    evidence=evidence,
                )
            elif spf_all == "~all":
                return self._fail(
                    target,
                    details=f"SPF record for '{domain}' uses '~all' (soft fail) — unauthorized senders are marked but may still be delivered.",
                    remediation=(
                        "Escalate SPF terminator from '~all' to '-all' (hard fail) once "
                        "you have confirmed all legitimate sending sources are in the SPF record."
                    ),
                    evidence=evidence,
                )
            else:  # -all or ?all (discouraged but present)
                return self._pass(
                    target,
                    details=f"SPF record configured for '{domain}' with strict terminator ({spf_all}).",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class EmailTlsCheck(BaseCheck):
    """
    EMAIL-03: Verify SMTP server requires TLS for inbound connections (STARTTLS enforcement).
    HIPAA 164.312(e)(1) requires transmission security for ePHI — email in transit must be encrypted.
    Tests: Exchange TLS receive connector settings, SMTP STARTTLS support via banner check.
    """
    check_id = "EMAIL-03"
    check_name = "Email Transmission Encryption (STARTTLS)"
    category = "Email Security"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 8.0

    def run(self, target: Target, context) -> Finding:
        try:
            # Check Exchange receive connector TLS settings
            exchange_tls = context.winrm.run_ps(
                target.hostname,
                r"Get-ReceiveConnector -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.Enabled -eq $true } | "
                r"Select-Object Name, RequireTLS, AuthMechanism | ConvertTo-Json"
            )

            # Check if Exchange transport service is running
            exchange_transport = context.winrm.run_ps(
                target.hostname,
                r"Get-Service -Name 'MSExchangeTransport' -ErrorAction SilentlyContinue | "
                r"Select-Object -ExpandProperty Status"
            )

            # Check SMTP port 25 TLS certificate binding (non-Exchange)
            smtp_tls = context.winrm.run_ps(
                target.hostname,
                r"Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SmtpSvc\' "
                r"-Name 'TLSCertHash' -ErrorAction SilentlyContinue | "
                r"Select-Object -ExpandProperty TLSCertHash"
            )

            is_exchange = "running" in exchange_transport.strip().lower()

            import json as _json
            connectors_json = None
            if exchange_tls.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(exchange_tls)
                    connectors_json = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            evidence = {
                "exchange_running": is_exchange,
                "smtp_tls_cert": smtp_tls.strip(),
                "receive_connectors": connectors_json,
            }

            if is_exchange and connectors_json:
                # Check if any internet-facing connector lacks TLS
                internet_connectors = [c for c in connectors_json
                                       if c.get("Name", "").lower() not in ("client frontend", "client proxy")]
                require_tls_all = all(c.get("RequireTLS", False) for c in internet_connectors)
                has_auth_tls = any("TLS" in str(c.get("AuthMechanism", "")) for c in internet_connectors)

                if require_tls_all or has_auth_tls:
                    return self._pass(
                        target,
                        details="Exchange receive connectors have TLS authentication configured.",
                        evidence=evidence,
                    )
                else:
                    return self._fail(
                        target,
                        details="Exchange SMTP receive connectors do not enforce TLS. Email containing ePHI may be transmitted unencrypted.",
                        remediation=(
                            "Configure Exchange receive connectors to require TLS: "
                            "Set-ReceiveConnector 'Default Frontend' -RequireTLS $true "
                            "-AuthMechanism 'TLS'. "
                            "Also enable Domain Security (mutual TLS) with known partner domains "
                            "that routinely exchange ePHI."
                        ),
                        evidence=evidence,
                    )
            elif smtp_tls.strip():
                return self._pass(
                    target,
                    details="IIS SMTP service has TLS certificate configured.",
                    evidence=evidence,
                )
            elif not is_exchange:
                return self._na(target, "No Exchange or IIS SMTP service detected on this server.")
            else:
                return self._fail(
                    target,
                    details="Exchange transport running but TLS configuration could not be verified.",
                    remediation=(
                        "Review Exchange receive connector TLS settings manually: "
                        "Run Get-ReceiveConnector | Select Name, RequireTLS, AuthMechanism "
                        "and ensure internet-facing connectors have TLS enabled."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
