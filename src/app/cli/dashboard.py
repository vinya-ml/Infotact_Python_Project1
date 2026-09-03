import sys
import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.columns import Columns
from rich import box


if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

console = Console(force_terminal=True)


def show_banner():
    """Display the AeroDrift ASCII banner."""

    banner = Text()
    banner.append(
        "  ___    __    ____  _  _  ____  ____  ____ \n",
        style="bold cyan",
    )
    banner.append(
        " / __)  /__\\  (  _ \\( \\/ )(_  _)(  _ \\( ___)\n",
        style="bold cyan",
    )
    banner.append(
        "( (_-. /(__)\\  ) _ < )  /   )(   ) _ < )__) \n",
        style="bold cyan",
    )
    banner.append(
        " \\___/(__)(__)(____/(_/_)  (__) (____/(____)\n",
        style="bold cyan",
    )
    banner.append(
        "        Cloud Topology & Remediation Graph",
        style="dim white",
    )

    console.print(
        Panel(banner, border_style="cyan", padding=(0, 1))
    )


def show_cloud_summary(topology):
    """Display the number of cloud resources."""

    table = Table(
        title="Cloud Resources",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("Resource Type", style="bold")
    table.add_column("Count", justify="right", style="green")

    counts = {}
    for _, attributes in topology.graph.nodes(data=True):
        resource_type = attributes.get(
            "resource_type", "Unknown"
        )
        counts[resource_type] = counts.get(resource_type, 0) + 1

    for resource_type, count in counts.items():
        table.add_row(resource_type, str(count))

    console.print(table)


def show_topology_tree(topology):
    """Render the cloud topology as an interactive text tree."""

    tree = Tree(
        "[bold cyan]Cloud Topology[/bold cyan]",
        guide_style="bold bright_blue",
    )

    internet_nodes = [
        n for n, d in topology.graph.nodes(data=True)
        if d.get("resource_type") == "Internet"
    ]

    vpc_nodes = [
        (n, d) for n, d in topology.graph.nodes(data=True)
        if d.get("resource_type") == "VPC"
    ]

    sg_nodes = [
        (n, d) for n, d in topology.graph.nodes(data=True)
        if d.get("resource_type") == "SecurityGroup"
    ]

    subnet_nodes = [
        (n, d) for n, d in topology.graph.nodes(data=True)
        if d.get("resource_type") == "Subnet"
    ]

    ec2_nodes = [
        (n, d) for n, d in topology.graph.nodes(data=True)
        if d.get("resource_type") == "EC2"
    ]

    for inet in internet_nodes:
        inet_branch = tree.add(
            f"[bold red]Internet[/bold red]"
        )

        for sg_id, sg_attrs in sg_nodes:
            has_edge = topology.graph.has_edge(inet, sg_id)
            if has_edge:
                edge_data = topology.graph.edges[inet, sg_id]
                port = edge_data.get("port", "?")
                proto = edge_data.get("protocol", "?")
                sg_branch = inet_branch.add(
                    f"[red]{sg_id}[/red] "
                    f"[dim]({sg_attrs.get('name', '')})[/dim]"
                )
                sg_branch.add(
                    f"[yellow]Ingress: {proto}/{port} "
                    f"from 0.0.0.0/0[/yellow]"
                )

                for ec2_id, ec2_attrs in ec2_nodes:
                    if ec2_attrs.get("security_group_id") == sg_id:
                        sg_branch.add(
                            f"[bold red]{ec2_id}[/bold red] "
                            f"[dim]({ec2_attrs.get('name', '')})[/dim]"
                        )

    for vpc_id, vpc_attrs in vpc_nodes:
        vpc_branch = tree.add(
            f"[bold blue]{vpc_id}[/bold blue] "
            f"[dim]({vpc_attrs.get('name', '')})[/dim]"
        )

        for sub_id, sub_attrs in subnet_nodes:
            if sub_attrs.get("vpc_id") == vpc_id:
                pub = "public" if sub_attrs.get("public") else "private"
                color = "green" if sub_attrs.get("public") else "yellow"
                sub_branch = vpc_branch.add(
                    f"[{color}]{sub_id}[/{color}] "
                    f"[dim]({sub_attrs.get('name', '')} "
                    f"- {pub})[/dim]"
                )

                for ec2_id, ec2_attrs in ec2_nodes:
                    if ec2_attrs.get("subnet_id") == sub_id:
                        sub_branch.add(
                            f"{ec2_id} "
                            f"[dim]({ec2_attrs.get('name', '')})[/dim]"
                        )

    console.print(tree)


def show_topology(topology):
    """Display the cloud topology connections as a table."""

    table = Table(
        title="Cloud Topology Edges",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("Source", style="bold")
    table.add_column("", justify="center", style="dim")
    table.add_column("Target", style="bold")
    table.add_column("Relationship", style="dim")

    for source, target, attributes in topology.graph.edges(data=True):
        relationship = attributes.get("relationship", "connected")
        table.add_row(source, "->", target, relationship)

    console.print(table)


def show_drift_findings(findings):
    """Display detected security drift with red highlighting."""

    if not findings:
        console.print(
            Panel(
                "[bold green]No security drift detected[/bold green]",
                title="AeroDrift Security Status",
                border_style="green",
            )
        )
        return

    console.print(
        Panel(
            f"[bold red]WARNING: {len(findings)} "
            f"security drift finding(s) detected![/bold red]",
            title="AeroDrift Security Status",
            border_style="red",
        )
    )

    table = Table(
        title="Detected Drift",
        box=box.HEAVY_EDGE,
        border_style="red",
    )

    table.add_column("Target", style="bold red")
    table.add_column("Security Group", style="red")
    table.add_column("Source", style="bold red")
    table.add_column("Protocol", style="yellow")
    table.add_column("Port", style="yellow")
    table.add_column("Attack Path", style="dim")

    for finding in findings:
        path_str = " -> ".join(finding.path)
        table.add_row(
            finding.target,
            finding.security_group,
            finding.source,
            finding.protocol,
            str(finding.port),
            path_str,
        )

    console.print(table)


def show_remediation_results(results):
    """Display the results of sandbox remediation execution."""

    table = Table(
        title="Remediation Execution Results",
        box=box.ROUNDED,
        border_style="yellow",
    )

    table.add_column("Script", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Output")

    for result in results:
        status = (
            "[green]SUCCESS[/green]"
            if result.success
            else "[red]FAILED[/red]"
        )
        output = result.output[:80] + "..." if len(result.output) > 80 else result.output
        if result.error:
            output = result.error[:80] + "..."

        table.add_row(
            str(result.script_path),
            status,
            output,
        )

    console.print(table)


def show_remediation_scripts(scripts):
    """Display the list of generated remediation scripts."""

    if not scripts:
        console.print(
            "[yellow]No remediation scripts generated.[/yellow]"
        )
        return

    console.print(
        Panel(
            f"[bold yellow]{len(scripts)} remediation script(s) "
            f"generated[/bold yellow]",
            title="Remediation Scripts",
            border_style="yellow",
        )
    )

    table = Table(box=box.SIMPLE, border_style="yellow")
    table.add_column("#", style="dim")
    table.add_column("Script Path", style="bold cyan")

    for i, script in enumerate(scripts, 1):
        table.add_row(str(i), str(script))

    console.print(table)


def show_persistence_summary(scan_id, finding_count):
    """Display persistence storage confirmation."""

    console.print(
        Panel(
            f"[bold green]Scan #{scan_id} saved to database "
            f"({finding_count} findings)[/bold green]",
            title="Persistence",
            border_style="green",
        )
    )


def show_scan_complete():
    """Display scan completion message."""

    console.print(
        Panel(
            "[bold green]Scan complete. All checks finished.[/bold green]",
            title="AeroDrift",
            border_style="green",
        )
    )
