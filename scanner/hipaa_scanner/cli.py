"""
CLI entry point for the HIPAA Scanner.
Usage: hipaa-scan [OPTIONS] TARGETS...
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .credentials import ScanCredentials
from .engine import HipaaScanner
from .models import EnvironmentType, CheckResult, Severity
from .uploader import ScanUploader

console = Console()


@click.command()
@click.argument("targets", nargs=-1)
@click.option("--mode", type=click.Choice(["workgroup", "domain"]), default="workgroup",
              help="Environment type: workgroup (P2P) or domain (Active Directory)")
@click.option("--dc", default=None, help="Domain controller hostname (domain mode only)")
@click.option("--api-url", envvar="HIPAA_API_URL", default=None,
              help="Platform API URL (e.g. https://hipaa.yourdomain.com). Omit to save locally.")
@click.option("--api-key", envvar="HIPAA_API_KEY", default=None,
              help="MSP API key for the platform.")
@click.option("--client-id", envvar="HIPAA_CLIENT_ID", default=None,
              help="Client UUID in the platform.")
@click.option("--output", "-o", default="scan-results.json",
              help="Local output file for scan results JSON.")
@click.option("--cred-store", default=None,
              help="OS credential store label (Windows Credential Manager). If omitted, prompts interactively.")
def main(targets, mode, dc, api_url, api_key, client_id, output, cred_store):
    """
    HIPAA Compliance Scanner — MSP Edition

    TARGETS: List of hostnames, IP addresses, or CIDR ranges to scan.
             In domain mode, leave empty to auto-discover from Active Directory.

    Examples:\n
        hipaa-scan 192.168.1.0/24 --mode workgroup\n
        hipaa-scan --mode domain --dc dc01.corp.local
    """
    console.print(Panel.fit(
        "[bold blue]HIPAA Compliance Scanner[/bold blue]\n[dim]MSP Edition v1.0.0[/dim]",
        border_style="blue"
    ))

    # Load credentials
    if cred_store:
        creds = ScanCredentials.from_credential_store(cred_store)
        console.print(f"[green]✓[/green] Credentials loaded from OS store: {creds}")
    else:
        creds = ScanCredentials.from_prompt()

    env_type = EnvironmentType.ACTIVE_DIRECTORY if mode == "domain" else EnvironmentType.WORKGROUP

    if mode == "domain" and not dc:
        # Try to detect DC from environment
        import subprocess
        try:
            result = subprocess.run(["nltest", "/dsgetdc:"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "DC:" in line:
                    dc = line.split("DC:")[1].strip().lstrip("\\")
                    console.print(f"[green]✓[/green] Auto-detected DC: {dc}")
                    break
        except Exception:
            pass

    if mode == "domain" and not dc:
        console.print("[red]Error: --dc is required for domain mode (could not auto-detect).[/red]")
        raise click.Abort()

    scanner = HipaaScanner(
        credentials=creds,
        environment_type=env_type,
        dc_hostname=dc,
        msp_api_key=api_key,
        client_id=client_id,
    )

    target_list = list(targets)
    console.print(f"\n[bold]Starting scan...[/bold]")
    if target_list:
        console.print(f"Targets: {', '.join(target_list[:5])}{'...' if len(target_list) > 5 else ''}")
    elif mode == "domain":
        console.print("Targets: Auto-discovery from Active Directory")

    report = scanner.run(target_list)

    # Print results summary
    _print_summary(report)

    # Save locally
    output_path = Path(output)
    ScanUploader("", "").save_local(report, output_path)
    console.print(f"\n[green]✓[/green] Results saved to: {output_path.absolute()}")

    # Upload to platform if configured
    if api_url and api_key:
        console.print(f"Uploading to platform: {api_url}...")
        try:
            uploader = ScanUploader(api_url, api_key)
            resp = uploader.upload(report)
            console.print(f"[green]✓[/green] Upload successful. Scan ID: {resp.get('scan_id', 'unknown')}")
        except Exception as e:
            console.print(f"[red]✗[/red] Upload failed: {e}")
            console.print("Results are saved locally for manual upload.")

    creds.wipe()


def _print_summary(report):
    """Print a formatted scan summary to the console."""
    score = report.overall_score
    risk = report.risk_level
    risk_color = {"MINIMAL": "green", "LOW": "green", "MODERATE": "yellow",
                  "ELEVATED": "red", "HIGH": "red"}.get(risk, "white")

    console.print(f"\n[bold]── Scan Complete ──────────────────────────────────[/bold]")
    console.print(f"  Targets scanned:  {report.targets_scanned}")
    console.print(f"  Targets failed:   {report.targets_failed}")
    console.print(f"  Compliance score: [bold]{score:.1f}/100[/bold]")
    console.print(f"  Risk level:       [{risk_color}]{risk}[/{risk_color}]")

    if report.summary:
        s = report.summary
        console.print(f"\n  Checks passed:   {s.passed}")
        console.print(f"  Checks failed:   {s.failed}")
        if s.by_severity:
            critical = s.by_severity.get("critical", 0)
            high = s.by_severity.get("high", 0)
            if critical:
                console.print(f"  [bold red]Critical findings: {critical}[/bold red]")
            if high:
                console.print(f"  [red]High findings:     {high}[/red]")

    # Top failing checks
    critical_fails = [f for f in report.findings
                     if f.result == CheckResult.FAIL and f.severity == Severity.CRITICAL]
    if critical_fails:
        console.print(f"\n[bold red]Critical Issues Requiring Immediate Attention:[/bold red]")
        for f in critical_fails[:5]:
            console.print(f"  ✗ [{f.target}] {f.check_name}")

    console.print()
