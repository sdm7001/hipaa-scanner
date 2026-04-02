"""
HIPAA compliance scoring engine.
NIST-aligned: Likelihood × Impact = Risk (1-25 scale).
Overall score: 0-100 (higher = more compliant).
"""

from __future__ import annotations
from .models import Finding, CheckResult, Severity

# Category weights (must sum to 1.0)
CATEGORY_WEIGHTS = {
    "Access Control": 0.20,
    "Encryption at Rest": 0.15,
    "Encryption in Transit": 0.10,
    "Audit Controls": 0.12,
    "Patch Management": 0.12,
    "Antivirus/EDR": 0.10,
    "Network Security": 0.10,
    "PHI Discovery": 0.11,
}

DEFAULT_WEIGHT = 0.10  # For any category not in the map

# Severity → point deduction if not specified by check
SEVERITY_POINTS = {
    Severity.CRITICAL: 12.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 3.5,
    Severity.LOW: 1.5,
    Severity.INFO: 0.5,
}

# Risk level thresholds (score → risk label)
RISK_THRESHOLDS = [
    (90, "MINIMAL"),
    (80, "LOW"),
    (65, "MODERATE"),
    (50, "ELEVATED"),
    (0, "HIGH"),
]


def calculate_score(findings: list[Finding]) -> float:
    """
    Calculate overall HIPAA compliance score (0-100).

    Algorithm:
    1. Start at 100.
    2. For each FAIL finding, deduct points (from check's `points` field).
    3. Critical findings are never capped — they can drive score very low.
    4. Clamp result to [0, 100].
    """
    score = 100.0
    for finding in findings:
        if finding.result == CheckResult.FAIL:
            deduction = finding.points_deducted
            if deduction == 0.0:
                # Fall back to severity-based deduction
                deduction = SEVERITY_POINTS.get(finding.severity, 2.0)
            score -= deduction
    return round(max(0.0, min(100.0, score)), 1)


def calculate_risk_level(score: float) -> str:
    """Convert numeric score to NIST-aligned risk label."""
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "HIGH"


def calculate_category_score(findings: list[Finding]) -> float:
    """Score for a single category (0-100 based on pass rate)."""
    applicable = [f for f in findings if f.result != CheckResult.NOT_APPLICABLE]
    if not applicable:
        return 100.0
    passed = sum(1 for f in applicable if f.result == CheckResult.PASS)
    return round((passed / len(applicable)) * 100, 1)
