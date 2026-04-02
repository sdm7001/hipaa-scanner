"""Base class for all HIPAA compliance check plugins."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import ClassVar
from ..models import Finding, CheckResult, Severity, Target, TargetRole


class BaseCheck(ABC):
    """
    Every compliance check is a plugin that subclasses BaseCheck.
    Register checks by placing them in the checks/ package.
    """

    check_id: ClassVar[str]           # e.g. "AC-01"
    check_name: ClassVar[str]         # Human-readable name
    category: ClassVar[str]           # e.g. "Access Control"
    hipaa_reference: ClassVar[str]    # e.g. "164.312(a)(1)"
    severity: ClassVar[Severity]      # Default severity if failing
    applies_to: ClassVar[list[TargetRole]]  # Which target types this runs on
    phase: ClassVar[str] = "mvp"      # "mvp" or "phase2"

    # Points deducted from 100 when this check fails
    points: ClassVar[float] = 0.0

    @abstractmethod
    def run(self, target: Target, context: "ScanContext") -> Finding:
        """Execute the check against the target. Must return a Finding."""
        ...

    def _pass(self, target: Target, details: str = "Check passed.", evidence: dict = None) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            hipaa_reference=self.hipaa_reference,
            severity=self.severity,
            result=CheckResult.PASS,
            target=target.hostname,
            details=details,
            remediation="No action required.",
            evidence=evidence or {},
            points_deducted=0.0,
        )

    def _fail(self, target: Target, details: str, remediation: str,
              evidence: dict = None, remediation_script: str = None) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            hipaa_reference=self.hipaa_reference,
            severity=self.severity,
            result=CheckResult.FAIL,
            target=target.hostname,
            details=details,
            remediation=remediation,
            remediation_script=remediation_script,
            evidence=evidence or {},
            points_deducted=self.points,
        )

    def _error(self, target: Target, error: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            hipaa_reference=self.hipaa_reference,
            severity=self.severity,
            result=CheckResult.ERROR,
            target=target.hostname,
            details=f"Check failed to execute: {error}",
            remediation="Verify scanner has required permissions.",
            points_deducted=0.0,
        )

    def _na(self, target: Target, reason: str = "Not applicable to this target type.") -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            hipaa_reference=self.hipaa_reference,
            severity=self.severity,
            result=CheckResult.NOT_APPLICABLE,
            target=target.hostname,
            details=reason,
            remediation="No action required.",
            points_deducted=0.0,
        )
