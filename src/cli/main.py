"""
main.py - CLI entry point, using the team's REAL modules
(src/aws, src/graph, src/automation) instead of the old standalone
AeroDrift/app/ (or its duplicate, src/app/) structure.
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.aws.mock_data import MOCK_AWS_STATE
from src.graph.graph_engine import build_graph, diagnose_drift
from src.automation.topology_adapter import to_dashboard_topology
from src.automation.adapter import convert_all
from src.automation.generator import RemediationGenerator
from src.automation.sandbox import RemediationSandbox
from src.cli.database import AeroDriftDB

from src.cli.dashboard import (
    console,
    show_banner,
    show_cloud_summary,
    show_topology,
    show_topology_tree,
    show_drift_findings,
    show_remediation_scripts,
    show_remediation_results,
    show_persistence_summary,
    show_scan_complete,
)
from src.cli.report import ReportGenerator


def load_and_analyze():
    """Shared logic: build the graph and detect drift from real AWS data."""
    raw_graph = build_graph(MOCK_AWS_STATE)
    topology = to_dashboard_topology(raw_graph)
    raw_findings = diagnose_drift(raw_graph)
    findings = convert_all(raw_findings)
    return topology, findings


@click.group()
@click.version_option(version="1.0.0", prog_name="AeroDrift")
def cli():
    """AeroDrift - Cloud Topology & Remediation Graph"""
    pass


@cli.command()
def scan():
    """Ingest state, build topology, and detect drift."""
    show_banner()
    with console.status("[bold cyan]Loading cloud state...[/bold cyan]"):
        topology, findings = load_and_analyze()
    console.print("[green]Cloud state loaded successfully.[/green]")
    show_cloud_summary(topology)
    show_topology_tree(topology)
    show_drift_findings(findings)
    show_scan_complete()


@cli.command()
def dashboard():
    """Display the full cloud dashboard with topology tree."""
    show_banner()
    topology, findings = load_and_analyze()
    show_cloud_summary(topology)
    console.print()
    show_topology_tree(topology)
    console.print()
    show_topology(topology)


@cli.command()
def detect():
    """Run drift detection and display findings."""
    show_banner()
    _, findings = load_and_analyze()
    show_drift_findings(findings)


@cli.command()
@click.option("--execute/--dry-run", default=True, help="Execute remediation or just generate scripts.")
@click.option("--save/--no-save", default=True, help="Save results to the database.")
def remediate(execute, save):
    """Detect drift, generate and execute remediation scripts."""
    show_banner()
    with console.status("[bold cyan]Detecting drift...[/bold cyan]"):
        topology, findings = load_and_analyze()

    show_drift_findings(findings)

    if not findings:
        console.print("[green]Nothing to remediate.[/green]")
        return

    with console.status("[bold yellow]Generating remediation scripts...[/bold yellow]"):
        generator = RemediationGenerator()
        scripts = generator.generate_all(findings)

    show_remediation_scripts(scripts)

    sandbox = RemediationSandbox(dry_run=not execute)
    mode = "live" if execute else "dry-run"
    console.print(f"\n[bold]Executing scripts ({mode})...[/bold]\n")

    results = sandbox.execute_all(scripts)
    show_remediation_results(results)

    if save:
        db = AeroDriftDB()
        db.connect()
        scan_id = db.save_scan(topology, findings, "MOCK_AWS_STATE (src/aws/mock_data.py)")
        show_persistence_summary(scan_id, len(findings))
        db.close()

    summary = sandbox.summary()
    console.print(
        Panel(
            f"Total: {summary['total']} | Succeeded: {summary['succeeded']} | Failed: {summary['failed']}",
            title="Remediation Summary",
            border_style="yellow",
        )
    )


@cli.command()
@click.option("--output", type=click.Path(), default=None, help="Custom output path for the PDF report.")
def report(output):
    """Generate a PDF incident report for the current scan."""
    show_banner()
    with console.status("[bold cyan]Detecting drift...[/bold cyan]"):
        topology, findings = load_and_analyze()

    show_drift_findings(findings)

    with console.status("[bold yellow]Generating remediation scripts...[/bold yellow]"):
        generator = RemediationGenerator()
        scripts = generator.generate_all(findings)

    sandbox = RemediationSandbox(dry_run=True)
    results = sandbox.execute_all(scripts)

    report_gen = ReportGenerator()
    if output:
        report_gen.output_dir = Path(output).parent

    filepath = report_gen.generate(findings=findings, topology=topology, remediation_results=results)

    console.print(
        Panel(
            f"[bold green]PDF report saved to:[/bold green]\n[cyan]{filepath}[/cyan]",
            title="AeroDrift Report",
            border_style="green",
        )
    )


@cli.command()
def history():
    """Show previous scan history from the database."""
    db = AeroDriftDB()
    db.connect()
    scans = db.list_scans()
    db.close()

    if not scans:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    from rich.table import Table
    table = Table(title="Scan History")
    table.add_column("Scan ID", style="bold")
    table.add_column("Timestamp")
    table.add_column("State File")
    table.add_column("Nodes")
    table.add_column("Edges")
    table.add_column("Findings")

    for scan in scans:
        table.add_row(
            str(scan["id"]), scan["timestamp"], scan["state_file"] or "-",
            str(scan["node_count"]), str(scan["edge_count"]), str(scan["finding_count"]),
        )

    console.print(table)


if __name__ == "__main__":
    cli()