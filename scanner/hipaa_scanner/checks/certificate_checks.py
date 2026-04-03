"""
Certificate expiration and PKI compliance checks.
HIPAA reference: 164.312(e)(2)(ii) — Encryption/Decryption (Addressable)
NIST SP 800-66r2: Section 3.7 — Transmission Security, certificate management

Expired certificates break encrypted connections, leaving ePHI transmitted in cleartext.
"""

from __future__ import annotations
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class CertificateExpirationCheck(BaseCheck):
    """
    CERT-01: Check for certificates expiring within 30 days or already expired.
    Tests LocalMachine certificate stores: My, WebHosting, Remote Desktop.
    """
    check_id = "CERT-01"
    check_name = "TLS Certificate Expiration"
    category = "Encryption in Transit"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    WARN_DAYS = 30
    CRITICAL_DAYS = 0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                f"""
$stores = @('My', 'WebHosting', 'Remote Desktop')
$threshold = (Get-Date).AddDays({self.WARN_DAYS})
$expired = @()
$warning = @()
foreach ($storeName in $stores) {{
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
    try {{
        $store.Open('ReadOnly')
        foreach ($cert in $store.Certificates) {{
            if ($cert.NotAfter -lt (Get-Date)) {{
                $expired += "$($cert.Subject) [EXPIRED: $($cert.NotAfter.ToString('yyyy-MM-dd'))]"
            }} elseif ($cert.NotAfter -lt $threshold) {{
                $days = [int]($cert.NotAfter - (Get-Date)).TotalDays
                $warning += "$($cert.Subject) [expires in $days days: $($cert.NotAfter.ToString('yyyy-MM-dd'))]"
            }}
        }}
        $store.Close()
    }} catch {{}}
}}
[PSCustomObject]@{{
    Expired = $expired -join ';'
    Warning = $warning -join ';'
    ExpiredCount = $expired.Count
    WarningCount = $warning.Count
}} | ConvertTo-Json
"""
            )

            import json
            data = json.loads(result)
            expired_count = data.get("ExpiredCount", 0)
            warning_count = data.get("WarningCount", 0)
            expired_list = [c for c in data.get("Expired", "").split(";") if c]
            warning_list = [c for c in data.get("Warning", "").split(";") if c]

            evidence = {
                "expired_count": expired_count,
                "warning_count": warning_count,
                "expired_certs": expired_list[:5],
                "warning_certs": warning_list[:5],
            }

            if expired_count > 0:
                return self._fail(
                    target,
                    details=f"{expired_count} EXPIRED certificate(s) found in LocalMachine stores. Encrypted connections using these certs are broken. Expired: {'; '.join(expired_list[:3])}",
                    remediation=(
                        "Renew expired certificates immediately. Expired TLS certificates break encrypted connections, "
                        "leaving ePHI potentially transmitted in cleartext or causing service outages. "
                        "Use Let's Encrypt (free), your CA, or Active Directory Certificate Services to renew. "
                        "Consider implementing certificate monitoring with alerts 60+ days before expiration."
                    ),
                    evidence=evidence,
                    remediation_script="# Run: certlm.msc → Personal → Certificates → right-click expired cert → All Tasks → Renew Certificate with Same Key",
                )
            elif warning_count > 0:
                return self._fail(
                    target,
                    details=f"{warning_count} certificate(s) expiring within {self.WARN_DAYS} days. Expiring: {'; '.join(warning_list[:3])}",
                    remediation=(
                        f"Renew certificates expiring within {self.WARN_DAYS} days before they expire and cause service interruptions. "
                        "Certificate expiration tracking should be automated — consider CertifyTheWeb, Certbot, or your CA's renewal notifications."
                    ),
                    evidence=evidence,
                )
            else:
                return self._pass(
                    target,
                    details=f"No expired or soon-expiring certificates found (checked within {self.WARN_DAYS} days).",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class SelfSignedCertificateCheck(BaseCheck):
    """
    CERT-02: Detect self-signed certificates on servers handling ePHI.
    Self-signed certs provide no PKI trust chain — clients cannot verify server identity.
    """
    check_id = "CERT-02"
    check_name = "Self-Signed Certificates"
    category = "Encryption in Transit"
    hipaa_reference = "164.312(e)(2)(ii)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.SERVER]
    phase = "phase2"
    points = 5.0

    def run(self, target: Target, context) -> Finding:
        try:
            result = context.winrm.run_ps(
                target.hostname,
                r"""
$selfSigned = @()
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
$store.Open('ReadOnly')
foreach ($cert in $store.Certificates) {
    if ($cert.Subject -eq $cert.Issuer -and $cert.NotAfter -gt (Get-Date)) {
        $selfSigned += "$($cert.Subject) [Expires: $($cert.NotAfter.ToString('yyyy-MM-dd'))]"
    }
}
$store.Close()
[PSCustomObject]@{
    SelfSignedCerts = $selfSigned -join ';'
    Count = $selfSigned.Count
} | ConvertTo-Json
"""
            )

            import json
            data = json.loads(result)
            count = data.get("Count", 0)
            certs = [c for c in data.get("SelfSignedCerts", "").split(";") if c]

            evidence = {"self_signed_count": count, "self_signed_certs": certs[:5]}

            if count > 0:
                return self._fail(
                    target,
                    details=f"{count} self-signed certificate(s) found: {'; '.join(certs[:3])}",
                    remediation=(
                        "Replace self-signed certificates with certificates issued by a trusted CA (Certificate Authority). "
                        "Self-signed certificates do not provide verifiable identity, allowing man-in-the-middle attacks "
                        "against ePHI transmissions. Options: Let's Encrypt (public CA, free), your organization's internal CA, "
                        "or a commercial CA (DigiCert, Sectigo). Use Active Directory Certificate Services for internal services."
                    ),
                    evidence=evidence,
                )
            else:
                return self._pass(
                    target,
                    details="No self-signed certificates found in Personal store.",
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
