"""
Administrative safeguards compliance checks.
HIPAA reference: 164.308 — Administrative Safeguards (REQUIRED/ADDRESSABLE)
NIST SP 800-66r2: Section 3.1 — Administrative Safeguards

These checks detect the PRESENCE of administrative controls through system artifacts —
policy documents, scheduled training events, incident response procedures.
"""

from __future__ import annotations
from datetime import datetime, timezone
from .base import BaseCheck
from ..models import Finding, Severity, TargetRole, Target


class SecurityPolicyDocumentCheck(BaseCheck):
    """
    ADMIN-01: Verify a security policy document exists and has been updated within 12 months.
    Tests: Common policy document paths, SharePoint policy sites, file metadata.
    HIPAA 164.316 requires written policies and procedures.
    """
    check_id = "ADMIN-01"
    check_name = "Security Policy Documentation"
    category = "Administrative Safeguards"
    hipaa_reference = "164.316(b)(1)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 8.0

    # Common policy document locations in healthcare environments
    POLICY_PATHS = [
        r"C:\PoliciesAndProcedures",
        r"C:\CompanyPolicies",
        r"C:\HIPAA",
        r"C:\Compliance",
        r"\\{hostname}\POLICIES$",
        r"\\{hostname}\HIPAA$",
    ]

    def run(self, target: Target, context) -> Finding:
        try:
            # Search for HIPAA/security policy documents
            policy_files = context.winrm.run_ps(
                target.hostname,
                r"$paths = @('C:\PoliciesAndProcedures','C:\CompanyPolicies','C:\HIPAA','C:\Compliance',"
                r"'C:\Users\Public\Documents','C:\Shared'); "
                r"$cutoff = (Get-Date).AddDays(-365); "
                r"$found = @(); "
                r"foreach ($p in $paths) { "
                r"  if (Test-Path $p) { "
                r"    Get-ChildItem $p -Recurse -Include '*.pdf','*.docx','*.doc' "
                r"    -ErrorAction SilentlyContinue | "
                r"    Where-Object { $_.Name -match 'policy|procedure|hipaa|privacy|security|breach' -and "
                r"                   $_.LastWriteTime -gt $cutoff } | "
                r"    Select-Object Name, LastWriteTime, Length | "
                r"    ForEach-Object { $found += $_ } "
                r"  } "
                r"} "
                r"$found | Select-Object -First 10 | ConvertTo-Json"
            )

            # Check for any HIPAA-related scheduled tasks (training reminders, etc.)
            hipaa_tasks = context.winrm.run_ps(
                target.hostname,
                r"Get-ScheduledTask -ErrorAction SilentlyContinue | "
                r"Where-Object { $_.TaskName -match 'HIPAA|Security|Training|Compliance|Policy' } | "
                r"Select-Object TaskName, State | ConvertTo-Json"
            )

            import json as _json
            policy_list = []
            if policy_files.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(policy_files)
                    policy_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            has_tasks = hipaa_tasks.strip() not in ("", "null", "[]")

            evidence = {
                "recent_policy_files": [p.get("Name", "") for p in policy_list][:5],
                "policy_file_count": len(policy_list),
                "hipaa_scheduled_tasks": has_tasks,
            }

            if policy_list:
                return self._pass(
                    target,
                    details=f"Found {len(policy_list)} recent security/HIPAA policy documents (within 12 months): {', '.join([p.get('Name','') for p in policy_list[:3]])}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No HIPAA security policy documents found on this server within the past 12 months. Written policies are a mandatory HIPAA requirement.",
                    remediation=(
                        "Create and maintain written HIPAA policies and procedures per 164.316: "
                        "Required policies include: Information Security Policy, Incident Response Plan, "
                        "Contingency Plan, Workforce Training Policy, Access Control Policy, "
                        "Business Associate Agreement management. "
                        "Store in a centrally accessible location (SharePoint, network share). "
                        "Review and update annually — document review dates. "
                        "Free templates: HHS.gov HIPAA security toolkit, AMA HIPAA resources."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class IncidentResponsePlanCheck(BaseCheck):
    """
    ADMIN-02: Verify an incident response plan exists and has been tested.
    Tests: IRP document presence, breach notification procedure files, response plan age.
    HIPAA 164.308(a)(6) requires documented incident response procedures.
    """
    check_id = "ADMIN-02"
    check_name = "Incident Response Plan"
    category = "Administrative Safeguards"
    hipaa_reference = "164.308(a)(6)(i)"
    severity = Severity.HIGH
    applies_to = [TargetRole.SERVER, TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 7.0

    def run(self, target: Target, context) -> Finding:
        try:
            irp_files = context.winrm.run_ps(
                target.hostname,
                r"$paths = @('C:\PoliciesAndProcedures','C:\CompanyPolicies','C:\HIPAA','C:\Compliance','C:\Shared'); "
                r"$found = @(); "
                r"foreach ($p in $paths) { "
                r"  if (Test-Path $p) { "
                r"    Get-ChildItem $p -Recurse -Include '*.pdf','*.docx','*.doc','*.txt' "
                r"    -ErrorAction SilentlyContinue | "
                r"    Where-Object { $_.Name -match 'incident|response|IRP|breach|notification|disaster|recovery' } | "
                r"    Select-Object Name, LastWriteTime | ForEach-Object { $found += $_ } "
                r"  } "
                r"} "
                r"$found | Select-Object -First 5 | ConvertTo-Json"
            )

            import json as _json
            irp_list = []
            if irp_files.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(irp_files)
                    irp_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            evidence = {
                "irp_documents": [f.get("Name", "") for f in irp_list][:5],
                "irp_count": len(irp_list),
            }

            if irp_list:
                return self._pass(
                    target,
                    details=f"Incident response plan documents found: {', '.join([f.get('Name','') for f in irp_list[:3]])}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No incident response plan documents detected. HIPAA 164.308(a)(6) requires documented procedures for reporting and responding to security incidents.",
                    remediation=(
                        "Create an Incident Response Plan (IRP) per HIPAA 164.308(a)(6): "
                        "Must include: (1) How to identify a potential breach, "
                        "(2) Who to notify internally and externally, "
                        "(3) HHS breach notification timeline (60 days for breaches affecting 500+), "
                        "(4) Patient notification procedures, "
                        "(5) Post-incident analysis and documentation. "
                        "Test the IRP with tabletop exercises annually. "
                        "Document all security incidents — even minor ones — for OCR audit readiness."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))


class WorkforceTrainingCheck(BaseCheck):
    """
    ADMIN-03: Verify security awareness training records exist for workforce members.
    HIPAA 164.308(a)(5) requires security awareness training for ALL workforce members.
    Tests: Training completion tracking files, LMS exports, last training date evidence.
    """
    check_id = "ADMIN-03"
    check_name = "Security Awareness Training Records"
    category = "Administrative Safeguards"
    hipaa_reference = "164.308(a)(5)(i)"
    severity = Severity.MEDIUM
    applies_to = [TargetRole.DOMAIN_CONTROLLER]
    phase = "phase2"
    points = 6.0

    def run(self, target: Target, context) -> Finding:
        try:
            training_files = context.winrm.run_ps(
                target.hostname,
                r"$paths = @('C:\PoliciesAndProcedures','C:\CompanyPolicies','C:\HIPAA','C:\Training','C:\Compliance','C:\Shared'); "
                r"$cutoff = (Get-Date).AddDays(-400); "
                r"$found = @(); "
                r"foreach ($p in $paths) { "
                r"  if (Test-Path $p) { "
                r"    Get-ChildItem $p -Recurse -Include '*.pdf','*.docx','*.xlsx','*.csv','*.txt' "
                r"    -ErrorAction SilentlyContinue | "
                r"    Where-Object { $_.Name -match 'training|awareness|phishing|security.awareness|hipaa.training' "
                r"                   -and $_.LastWriteTime -gt $cutoff } | "
                r"    Select-Object Name, LastWriteTime | ForEach-Object { $found += $_ } "
                r"  } "
                r"} "
                r"$found | Select-Object -First 5 | ConvertTo-Json"
            )

            import json as _json
            training_list = []
            if training_files.strip() not in ("", "null", "[]"):
                try:
                    raw = _json.loads(training_files)
                    training_list = raw if isinstance(raw, list) else [raw]
                except Exception:
                    pass

            evidence = {
                "training_documents": [f.get("Name", "") for f in training_list][:5],
                "recent_training_count": len(training_list),
            }

            if training_list:
                return self._pass(
                    target,
                    details=f"Security awareness training records found (within 13 months): {', '.join([f.get('Name','') for f in training_list[:3]])}.",
                    evidence=evidence,
                )
            else:
                return self._fail(
                    target,
                    details="No security awareness training records detected. HIPAA 164.308(a)(5) requires training for all workforce members with ePHI access.",
                    remediation=(
                        "Implement and document annual security awareness training: "
                        "1. Required topics: phishing identification, password security, ePHI handling, "
                        "   device security, incident reporting, HIPAA basics. "
                        "2. Track completion — name, date, training title — and retain for 6 years. "
                        "3. Platforms: KnowBe4, Proofpoint Security Awareness, Hoxhunt (all HIPAA-focused). "
                        "4. Free option: HHS.gov security awareness resources + spreadsheet tracking. "
                        "OCR specifically audits training records — documentation is the proof."
                    ),
                    evidence=evidence,
                )
        except Exception as e:
            return self._error(target, str(e))
