"""
HIPAA Scanner Engine — orchestrates target discovery and parallel check execution.
"""

from __future__ import annotations
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
import socket

from .models import (
    ScanReport, Finding, CategoryScore, ScanSummary,
    Target, TargetRole, EnvironmentType, CheckResult, Severity
)
from .credentials import ScanCredentials
from .connectors.winrm_connector import WinRMConnector
from .connectors.ldap_connector import LdapConnector
from .checks import MVP_CHECKS, BaseCheck
from .scoring import calculate_score, calculate_risk_level

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

SCANNER_VERSION = "1.0.0"
MAX_WORKERS = 10


class ScanContext:
    """Runtime context passed to every check plugin."""

    def __init__(self, winrm: WinRMConnector, ldap: Optional[LdapConnector],
                 environment_type: EnvironmentType):
        self.winrm = winrm
        self.ldap = ldap
        self.environment_type = environment_type.value


class HipaaScanner:
    """
    Main scanner engine.
    Usage:
        scanner = HipaaScanner(creds, env_type="active_directory", dc_hostname="dc01.example.com")
        report = scanner.run(targets=["192.168.1.0/24"])
    """

    def __init__(
        self,
        credentials: ScanCredentials,
        environment_type: EnvironmentType = EnvironmentType.WORKGROUP,
        dc_hostname: Optional[str] = None,
        checks: list[type[BaseCheck]] = None,
        max_workers: int = MAX_WORKERS,
        msp_api_key: Optional[str] = None,
        client_id: Optional[str] = None,
    ):
        self.credentials = credentials
        self.environment_type = environment_type
        self.dc_hostname = dc_hostname
        self.checks = checks or MVP_CHECKS
        self.max_workers = max_workers
        self.msp_api_key = msp_api_key
        self.client_id = client_id

    def run(self, target_hosts: list[str]) -> ScanReport:
        """
        Main entry point. Takes a list of hostnames/IPs, runs all checks, returns a ScanReport.
        """
        started_at = datetime.now(timezone.utc)

        report = ScanReport(
            scanner_version=SCANNER_VERSION,
            msp_api_key=self.msp_api_key,
            client_id=self.client_id,
            started_at=started_at,
            environment_type=self.environment_type,
        )

        # Initialize connectors
        winrm = WinRMConnector(
            username=self.credentials.username,
            password=self.credentials.password,
            domain=self.credentials.domain,
        )

        ldap = None
        if self.environment_type == EnvironmentType.ACTIVE_DIRECTORY and self.dc_hostname:
            ldap = LdapConnector(
                domain_controller=self.dc_hostname,
                username=f"{self.credentials.domain}\\{self.credentials.username}" if self.credentials.domain else self.credentials.username,
                password=self.credentials.password,
            )
            try:
                ldap.connect()
                console.print(f"[green]✓[/green] Connected to Active Directory: {self.dc_hostname}")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] AD connection failed: {e} — domain checks will be skipped")
                ldap = None

        context = ScanContext(winrm=winrm, ldap=ldap, environment_type=self.environment_type)

        # Resolve targets
        targets = self._resolve_targets(target_hosts, ldap)
        console.print(f"[blue]Scanning {len(targets)} target(s) with {len(self.checks)} checks each...[/blue]")

        # Run scans in parallel
        all_findings: list[Finding] = []
        failed_targets = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning targets...", total=len(targets))

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_target = {
                    executor.submit(self._scan_target, target, context): target
                    for target in targets
                }
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        report.targets_scanned += 1
                    except Exception as e:
                        console.print(f"[red]✗[/red] Failed to scan {target.hostname}: {e}")
                        failed_targets += 1
                    progress.advance(task)

        report.targets_failed = failed_targets
        report.findings = all_findings
        report.completed_at = datetime.now(timezone.utc)

        # Calculate scores
        report.overall_score = calculate_score(all_findings)
        report.risk_level = calculate_risk_level(report.overall_score)
        report.category_scores = _build_category_scores(all_findings)
        report.summary = _build_summary(all_findings)

        if ldap:
            ldap.disconnect()

        return report

    def _resolve_targets(self, host_list: list[str], ldap: Optional[LdapConnector]) -> list[Target]:
        """Convert hostnames/IPs/CIDR ranges to Target objects."""
        targets = []

        if self.environment_type == EnvironmentType.ACTIVE_DIRECTORY and ldap:
            # Discover all domain computers from AD
            try:
                computers = ldap.get_computers()
                domain_controllers = ldap.get_computers()  # TODO: filter by role

                for comp in computers:
                    hostname = comp.get("cn", [""])[0] or comp.get("dNSHostName", [""])[0]
                    if not hostname:
                        continue
                    try:
                        ip = socket.gethostbyname(hostname)
                    except socket.gaierror:
                        ip = hostname

                    targets.append(Target(
                        hostname=hostname,
                        ip_address=ip,
                        role=TargetRole.WORKSTATION,
                        os_version=comp.get("operatingSystem", [""])[0] or None,
                    ))
                console.print(f"[green]✓[/green] Discovered {len(targets)} computers from Active Directory")
                return targets
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] AD computer discovery failed: {e} — using provided host list")

        # Workgroup / manual mode: resolve provided hostnames
        for host in host_list:
            if "/" in host:
                # CIDR range — expand
                import ipaddress
                for ip in ipaddress.ip_network(host, strict=False).hosts():
                    targets.append(Target(hostname=str(ip), ip_address=str(ip)))
            else:
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror:
                    ip = host
                targets.append(Target(hostname=host, ip_address=ip))

        return targets

    def _scan_target(self, target: Target, context: ScanContext) -> list[Finding]:
        """Run all applicable checks against a single target."""
        findings = []

        # Test connectivity first
        if not context.winrm.test_connection(target.hostname):
            console.print(f"[yellow]⚠[/yellow] {target.hostname}: WinRM unreachable — skipping")
            raise ConnectionError(f"Cannot connect to {target.hostname} via WinRM")

        applicable = [c for c in self.checks if target.role in c.applies_to]

        for check_cls in applicable:
            try:
                check = check_cls()
                finding = check.run(target, context)
                findings.append(finding)
            except Exception as e:
                findings.append(Finding(
                    check_id=check_cls.check_id,
                    check_name=check_cls.check_name,
                    category=check_cls.category,
                    hipaa_reference=check_cls.hipaa_reference,
                    severity=check_cls.severity,
                    result=CheckResult.ERROR,
                    target=target.hostname,
                    details=f"Check execution error: {e}",
                    remediation="Verify scanner permissions and target accessibility.",
                    points_deducted=0.0,
                ))

        return findings


def _build_category_scores(findings: list[Finding]) -> list[CategoryScore]:
    from collections import defaultdict
    categories: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        categories[f.category].append(f)

    scores = []
    for cat, cat_findings in categories.items():
        passed = sum(1 for f in cat_findings if f.result == CheckResult.PASS)
        total = sum(1 for f in cat_findings if f.result != CheckResult.NOT_APPLICABLE)
        score = (passed / total * 100) if total > 0 else 100.0
        scores.append(CategoryScore(
            category=cat,
            score=round(score, 1),
            weight=1.0,
            findings_critical=sum(1 for f in cat_findings if f.severity == Severity.CRITICAL and f.result == CheckResult.FAIL),
            findings_high=sum(1 for f in cat_findings if f.severity == Severity.HIGH and f.result == CheckResult.FAIL),
            findings_medium=sum(1 for f in cat_findings if f.severity == Severity.MEDIUM and f.result == CheckResult.FAIL),
            findings_low=sum(1 for f in cat_findings if f.severity == Severity.LOW and f.result == CheckResult.FAIL),
            findings_pass=passed,
        ))
    return scores


def _build_summary(findings: list[Finding]) -> ScanSummary:
    from collections import defaultdict
    by_severity: dict[str, int] = defaultdict(int)
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: {"passed": 0, "failed": 0})

    passed = failed = errors = na = 0
    for f in findings:
        if f.result == CheckResult.PASS:
            passed += 1
            by_category[f.category]["passed"] += 1
        elif f.result == CheckResult.FAIL:
            failed += 1
            by_severity[f.severity.value] += 1
            by_category[f.category]["failed"] += 1
        elif f.result == CheckResult.ERROR:
            errors += 1
        elif f.result == CheckResult.NOT_APPLICABLE:
            na += 1

    return ScanSummary(
        total_checks=len(findings),
        passed=passed,
        failed=failed,
        errors=errors,
        not_applicable=na,
        by_severity=dict(by_severity),
        by_category=dict(by_category),
    )
