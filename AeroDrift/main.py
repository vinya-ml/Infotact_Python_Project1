import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector
from app.remediation.generator import RemediationGenerator
from app.remediation.sandbox import RemediationSandbox
from app.persistence.database import AeroDriftDB
from app.cli.dashboard import (
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
from app.cli.report import ReportGenerator


DEFAULT_STATE = (
    Path(__file__).resolve().parent / "data" / "mock_aws_state.json"
)


@click.group()
@click.version_option(version="1.0.0", prog_name="AeroDrift")
def cli():
    """AeroDrift - Cloud Topology & Remediation Graph"""
    pass


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
def scan(state_file):
    """Ingest state, build topology, and detect drift."""

    show_banner()

    with console.status(
        "[bold cyan]Loading cloud state...[/bold cyan]"
    ):
        loader = CloudStateLoader(state_file)
        state = loader.load()

    console.print(
        "[green]Cloud state loaded successfully.[/green]"
    )

    with console.status(
        "[bold cyan]Building topology graph...[/bold cyan]"
    ):
        topology = CloudTopology()
        topology.build_from_state(state)

    show_cloud_summary(topology)
    show_topology_tree(topology)

    with console.status(
        "[bold cyan]Running drift detection...[/bold cyan]"
    ):
        detector = DriftDetector(topology)
        findings = detector.detect_public_database_exposure()

    show_drift_findings(findings)
    show_scan_complete()


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
def dashboard(state_file):
    """Display the full cloud dashboard with topology tree."""

    show_banner()

    loader = CloudStateLoader(state_file)
    state = loader.load()

    topology = CloudTopology()
    topology.build_from_state(state)

    show_cloud_summary(topology)

    console.print()
    show_topology_tree(topology)

    console.print()
    show_topology(topology)


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
def detect(state_file):
    """Run drift detection and display findings."""

    show_banner()

    loader = CloudStateLoader(state_file)
    state = loader.load()

    topology = CloudTopology()
    topology.build_from_state(state)

    detector = DriftDetector(topology)
    findings = detector.detect_public_database_exposure()

    show_drift_findings(findings)


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
@click.option(
    "--execute/--dry-run",
    default=True,
    help="Execute remediation or just generate scripts.",
)
@click.option(
    "--save/--no-save",
    default=True,
    help="Save results to the database.",
)
def remediate(state_file, execute, save):
    """Detect drift, generate and execute remediation scripts."""

    show_banner()

    with console.status("[bold cyan]Loading state...[/bold cyan]"):
        loader = CloudStateLoader(state_file)
        state = loader.load()

    topology = CloudTopology()
    topology.build_from_state(state)

    with console.status("[bold cyan]Detecting drift...[/bold cyan]"):
        detector = DriftDetector(topology)
        findings = detector.detect_public_database_exposure()

    show_drift_findings(findings)

    if not findings:
        console.print(
            "[green]Nothing to remediate.[/green]"
        )
        return

    with console.status(
        "[bold yellow]Generating remediation scripts...[/bold yellow]"
    ):
        generator = RemediationGenerator()
        scripts = generator.generate_all(findings)

    show_remediation_scripts(scripts)

    sandbox = RemediationSandbox(dry_run=not execute)
    mode = "live" if execute else "dry-run"
    console.print(
        f"\n[bold]Executing scripts ({mode})...[/bold]\n"
    )

    results = sandbox.execute_all(scripts)
    show_remediation_results(results)

    if save:
        db = AeroDriftDB()
        db.connect()
        scan_id = db.save_scan(topology, findings, state_file)
        show_persistence_summary(scan_id, len(findings))
        db.close()

    summary = sandbox.summary()
    console.print(
        Panel(
            f"Total: {summary['total']} | "
            f"Succeeded: {summary['succeeded']} | "
            f"Failed: {summary['failed']}",
            title="Remediation Summary",
            border_style="yellow",
        )
    )


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Custom output path for the PDF report.",
)
def report(state_file, output):
    """Generate a PDF incident report for the current scan."""

    show_banner()

    with console.status("[bold cyan]Loading state...[/bold cyan]"):
        loader = CloudStateLoader(state_file)
        state = loader.load()

    topology = CloudTopology()
    topology.build_from_state(state)

    with console.status("[bold cyan]Detecting drift...[/bold cyan]"):
        detector = DriftDetector(topology)
        findings = detector.detect_public_database_exposure()

    show_drift_findings(findings)

    with console.status(
        "[bold yellow]Generating remediation scripts...[/bold yellow]"
    ):
        generator = RemediationGenerator()
        scripts = generator.generate_all(findings)

    sandbox = RemediationSandbox(dry_run=True)
    results = sandbox.execute_all(scripts)

    report_gen = ReportGenerator()
    if output:
        report_gen.output_dir = Path(output).parent

    filepath = report_gen.generate(
        findings=findings,
        topology=topology,
        remediation_results=results,
    )

    console.print(
        Panel(
            f"[bold green]PDF report saved to:[/bold green]\n"
            f"[cyan]{filepath}[/cyan]",
            title="AeroDrift Report",
            border_style="green",
        )
    )


@cli.command()
@click.option(
    "--state-file",
    type=click.Path(exists=True),
    default=str(DEFAULT_STATE),
    help="Path to the cloud state JSON file.",
)
def full_scan(state_file):
    """Run the complete pipeline: ingest, detect, remediate,
    persist, and generate PDF report."""

    show_banner()

    with console.status("[bold cyan]Step 1/5: Loading state...[/bold cyan]"):
        loader = CloudStateLoader(state_file)
        state = loader.load()
        topology = CloudTopology()
        topology.build_from_state(state)

    show_cloud_summary(topology)
    show_topology_tree(topology)

    with console.status(
        "[bold cyan]Step 2/5: Detecting drift...[/bold cyan]"
    ):
        detector = DriftDetector(topology)
        findings = detector.detect_public_database_exposure()

    show_drift_findings(findings)

    with console.status(
        "[bold yellow]Step 3/5: Generating remediation...[/bold yellow]"
    ):
        generator = RemediationGenerator()
        scripts = generator.generate_all(findings)
        show_remediation_scripts(scripts)

    with console.status(
        "[bold yellow]Step 4/5: Executing sandbox...[/bold yellow]"
    ):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all(scripts)
        show_remediation_results(results)

    with console.status(
        "[bold green]Step 5/5: Saving & reporting...[/bold green]"
    ):
        db = AeroDriftDB()
        db.connect()
        scan_id = db.save_scan(topology, findings, state_file)
        show_persistence_summary(scan_id, len(findings))
        db.close()

        report_gen = ReportGenerator()
        report_path = report_gen.generate(
            findings=findings,
            topology=topology,
            remediation_results=results,
            scan_id=scan_id,
        )

    console.print(
        Panel(
            f"[bold green]Full scan complete![/bold green]\n\n"
            f"Scan ID:        {scan_id}\n"
            f"Findings:       {len(findings)}\n"
            f"Scripts:        {len(scripts)}\n"
            f"PDF Report:     {report_path}",
            title="AeroDrift Pipeline Summary",
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
            str(scan["id"]),
            scan["timestamp"],
            scan["state_file"] or "-",
            str(scan["node_count"]),
            str(scan["edge_count"]),
            str(scan["finding_count"]),
        )

    console.print(table)


if __name__ == "__main__":
    cli()
