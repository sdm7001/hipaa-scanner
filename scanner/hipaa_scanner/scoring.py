"""
HIPAA compliance scoring engine.
NIST-aligned: Likelihood × Impact = Risk (1-25 scale).
Overall score: 0-100 (higher = more compliant).
"""

from __future__ import annotations
from .models import Finding, CheckResult, Severity

# Category weights — normalized automatically in calculate_score()
# Higher weight = more impact on overall score when failing
CATEGORY_WEIGHTS = {
    # Tier 1: REQUIRED safeguards with direct ePHI risk (highest weight)
    "Access Control": 0.15,
    "Multi-Factor Authentication": 0.10,
    "Encryption at Rest": 0.10,
    "Transmission Security": 0.08,
    "Encryption in Transit": 0.08,
    "Audit Controls": 0.08,
    # Tier 2: Critical operational controls
    "Patch Management": 0.07,
    "Antivirus/EDR": 0.06,
    "Network Security": 0.06,
    "Database Security": 0.05,
    "Contingency Plan": 0.05,
    # Tier 3: Important but less directly ePHI-linked
    "PHI Discovery": 0.04,
    "Email Security": 0.04,
    "Device and Media Controls": 0.03,
    "Endpoint Security": 0.03,
    "Administrative Safeguards": 0.03,
    "Physical Safeguards": 0.02,
    # Tier 4: Supporting controls
    "Certificate Management": 0.02,
    "Encryption": 0.02,
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
    Calculate overall HIPAA compliance score (0-100) using weighted category scores.

    Algorithm:
    1. Group findings by category.
    2. Score each category 0-100 based on pass rate (applicable checks only).
    3. Apply severity penalty: critical failures reduce category score further.
    4. Weight each category by CATEGORY_WEIGHTS and sum.
    5. Any unknown category uses DEFAULT_WEIGHT, normalized so total always sums to 1.0.
    """
    from collections import defaultdict

    by_category: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    if not by_category:
        return 100.0

    # Calculate per-category score
    cat_scores: dict[str, float] = {}
    for cat, cat_findings in by_category.items():
        applicable = [f for f in cat_findings if f.result != CheckResult.NOT_APPLICABLE]
        if not applicable:
            cat_scores[cat] = 100.0
            continue
        passed = sum(1 for f in applicable if f.result == CheckResult.PASS)
        base = (passed / len(applicable)) * 100.0
        # Additional penalty for critical failures (they should sink the score harder)
        critical_fails = sum(1 for f in applicable if f.result == CheckResult.FAIL and f.severity == Severity.CRITICAL)
        penalty = min(critical_fails * 5.0, 25.0)  # cap extra penalty at 25 pts
        cat_scores[cat] = max(0.0, base - penalty)

    # Assign weights (known categories use table; unknown use DEFAULT_WEIGHT)
    total_weight = 0.0
    weighted_sum = 0.0
    for cat, s in cat_scores.items():
        w = CATEGORY_WEIGHTS.get(cat, DEFAULT_WEIGHT)
        weighted_sum += w * s
        total_weight += w

    if total_weight == 0:
        return 100.0

    # Normalize so weights always sum to 1.0 (handles unknown categories gracefully)
    score = weighted_sum / total_weight
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
