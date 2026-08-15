"""
graph_engine.py - Member 2's module (NetworkX / Topology Engine)

Public API (this is what Members 3 and 4 will import from you):
    build_graph(resources)         -> nx.DiGraph
    diagnose_drift(graph)          -> list[dict]

Run this file directly (`python graph_engine.py`) to see it work against
the shared fake dataset.
"""

import networkx as nx

INTERNET_CIDR = "0.0.0.0/0"


def build_graph(resources: list[dict]) -> nx.DiGraph:
    """
    Turn a list of AWS-shaped resource dicts into a directed graph.

    Nodes: every resource (including the special "internet" node).
    Edges: internet -> security_group -> instance, only when the
           security group's allows_from includes the open internet CIDR.
    """
    graph = nx.DiGraph()

    # First pass: add every resource as a node, keeping its data on the node
    for r in resources:
        graph.add_node(r["id"], **r)

    # Second pass: add edges based on security group rules
    for r in resources:
        if r["type"] != "security_group":
            continue

        attached_to = r.get("attached_to")
        allows_from = r.get("allows_from", [])

        if INTERNET_CIDR in allows_from:
            graph.add_edge("internet", r["id"], port=r.get("port"))

        if attached_to:
            graph.add_edge(r["id"], attached_to, port=r.get("port"))

    return graph


def diagnose_drift(graph: nx.DiGraph) -> list[dict]:
    """
    Look for any instance reachable from the internet that shouldn't be -
    specifically, flag any 'database' role instance with a path from internet.

    Returns a list of dicts in the shape Member 4 (automation) expects:
        {
            "drift_type": "open_ingress",
            "resource_id": <security group id>,
            "bad_rule": {"port": int, "cidr": str},
            "path": [list of node ids from internet to the exposed instance],
        }
    """
    if graph is None:
        raise ValueError("diagnose_drift() called with no graph - build_graph() first.")

    findings = []

    if "internet" not in graph:
        return findings

    for node, data in graph.nodes(data=True):
        if data.get("type") != "instance":
            continue
        if data.get("role") != "database":
            continue  # for now we only treat "database" as sensitive

        if nx.has_path(graph, "internet", node):
            path = nx.shortest_path(graph, "internet", node)
            # the security group is always the second node in the path (internet -> sg -> instance)
            sg_id = path[1] if len(path) > 1 else None
            sg_data = graph.nodes[sg_id] if sg_id else {}

            findings.append({
                "drift_type": "open_ingress",
                "resource_id": sg_id,
                "bad_rule": {"port": sg_data.get("port"), "cidr": INTERNET_CIDR},
                "path": path,
            })

    return findings


def save_snapshot(graph: nx.DiGraph) -> dict:
    """Serialize a graph to a plain dict (JSON-friendly) for SQLite storage later."""
    return nx.node_link_data(graph)


def load_snapshot(data: dict) -> nx.DiGraph:
    """Reverse of save_snapshot()."""
    return nx.node_link_graph(data)


if __name__ == "__main__":
    from tests.sample_data import SAMPLE_RESOURCES

    graph = build_graph(SAMPLE_RESOURCES)

    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print("Nodes:", list(graph.nodes))
    print("Edges:", list(graph.edges))
    print()

    findings = diagnose_drift(graph)
    if findings:
        print(f"DRIFT DETECTED ({len(findings)} issue(s)):")
        for f in findings:
            print(f"  - {f['drift_type']} via {f['resource_id']}: "
                  f"port {f['bad_rule']['port']} open to {f['bad_rule']['cidr']}")
            print(f"    path: {' -> '.join(f['path'])}")
    else:
        print("No drift detected.")