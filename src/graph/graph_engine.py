"""
graph_engine.py - Member 2's module (NetworkX / Topology Engine)

Updated to read Member 1's actual MOCK_AWS_STATE shape:
    {
        "ec2_instances": [{"id", "name", "subnet_id", "security_group_ids", "state"}],
        "subnets": [{"id", "name", "vpc_id"}],
        "security_groups": [{"id", "name", "vpc_id", "ingress_rules": [{"port", "cidr"}]}],
    }

NOTE: "ingress_rules" doesn't exist in Member 1's data yet as of writing this.
Until it's added, build_graph() still works (nodes + subnet/instance edges),
but diagnose_drift() has nothing to flag, since there's no rule data yet.
The code below is written to pick it up automatically the moment it's added
- no changes needed here when that happens.

Public API:
    build_graph(aws_state)   -> nx.DiGraph
    diagnose_drift(graph)    -> list[dict]
"""

import networkx as nx

INTERNET_CIDR = "0.0.0.0/0"


def build_graph(aws_state: dict) -> nx.DiGraph:
    """
    Turn Member 1's AWS state dict into a directed graph.

    Nodes: internet, every subnet, every security group, every instance.
    Edges:
        internet -> security_group      (if ingress_rules allows 0.0.0.0/0)
        security_group -> instance      (via instance's security_group_ids)
        subnet -> instance               (structural, not security-relevant)
    """
    graph = nx.DiGraph()
    graph.add_node("internet", type="internet")

    for subnet in aws_state.get("subnets", []):
        graph.add_node(subnet["id"], type="subnet", **subnet)

    for sg in aws_state.get("security_groups", []):
        graph.add_node(sg["id"], type="security_group", **sg)

        # Only creates this edge once ingress_rules actually exists in the data.
        for rule in sg.get("ingress_rules", []):
            if rule.get("cidr") == INTERNET_CIDR:
                graph.add_edge("internet", sg["id"], port=rule.get("port"))

    for instance in aws_state.get("ec2_instances", []):
        graph.add_node(instance["id"], type="instance", **instance)

        subnet_id = instance.get("subnet_id")
        if subnet_id:
            graph.add_edge(subnet_id, instance["id"])

        for sg_id in instance.get("security_group_ids", []):
            graph.add_edge(sg_id, instance["id"])

    return graph


def diagnose_drift(graph: nx.DiGraph) -> list[dict]:
    """
    Find any instance reachable from the internet.

    Returns a list of dicts, e.g.:
        {
            "drift_type": "open_ingress",
            "resource_id": <security group id>,
            "bad_rule": {"port": int, "cidr": str},
            "path": [node ids from internet to the exposed instance],
        }

    Will correctly return an EMPTY list if there's no ingress_rules data
    yet - that's expected, not a bug, until Member 1 adds that field.
    """
    if graph is None:
        raise ValueError("diagnose_drift() called with no graph - build_graph() first.")

    findings = []
    if "internet" not in graph:
        return findings

    for node, data in graph.nodes(data=True):
        if data.get("type") != "instance":
            continue

        if nx.has_path(graph, "internet", node):
            path = nx.shortest_path(graph, "internet", node)
            sg_id = path[1] if len(path) > 1 else None
            sg_data = graph.nodes[sg_id] if sg_id else {}

            # Find the specific rule that caused this exposure
            bad_rule = next(
                (r for r in sg_data.get("ingress_rules", []) if r.get("cidr") == INTERNET_CIDR),
                {}
            )

            findings.append({
                "drift_type": "open_ingress",
                "resource_id": sg_id,
                "bad_rule": bad_rule,
                "path": path,
            })

    return findings


if __name__ == "__main__":
    from src.aws.mock_data import MOCK_AWS_STATE  # Member 1's real data

    graph = build_graph(MOCK_AWS_STATE)

    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print("Nodes:", list(graph.nodes))
    print("Edges:", list(graph.edges))
    print()

    findings = diagnose_drift(graph)
    if findings:
        print(f"DRIFT DETECTED ({len(findings)} issue(s)):")
        for f in findings:
            print(f"  - {f['drift_type']} via {f['resource_id']}: {f['bad_rule']}")
            print(f"    path: {' -> '.join(f['path'])}")
    else:
        print("No drift detected.")