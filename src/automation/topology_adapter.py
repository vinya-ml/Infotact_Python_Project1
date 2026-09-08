"""
topology_adapter.py - Converts graph_engine.py's raw NetworkX graph into
the shape src/cli/dashboard.py expects for display.

dashboard.py expects:
    - an object with a `.graph` attribute holding the NetworkX graph
    - node attribute "resource_type" (values: "Internet", "VPC", "Subnet",
      "SecurityGroup", "EC2") - graph_engine.py uses "type" instead
    - node attribute "name" - already present in the real AWS data
    - EC2 nodes need "security_group_id" (singular) and "subnet_id"
    - Subnet nodes need "vpc_id" and "public"
    - Edges from internet -> security_group need "port" and "protocol"

This adapter builds a NEW graph with the translated attributes, so
neither graph_engine.py nor dashboard.py need to be changed.
"""

import networkx as nx


TYPE_MAP = {
    "internet": "Internet",
    "vpc": "VPC",
    "subnet": "Subnet",
    "security_group": "SecurityGroup",
    "instance": "EC2",
}

DEFAULT_PROTOCOL = "tcp"


class TopologyView:
    """Thin wrapper so dashboard.py's `topology.graph` access, and
    report.py's `topology.summary()` call, both work correctly."""
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def summary(self) -> dict:
        """Used by report.py to show node/edge counts in the PDF report."""
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
        }


def to_dashboard_topology(source_graph: nx.DiGraph) -> TopologyView:
    """
    Convert a graph_engine.py-built graph into a TopologyView that
    dashboard.py can render correctly.
    """
    display_graph = nx.DiGraph()

    for node, data in source_graph.nodes(data=True):
        new_attrs = dict(data)
        new_attrs["resource_type"] = TYPE_MAP.get(data.get("type"), "Unknown")

        if data.get("type") == "instance":
            sg_ids = data.get("security_group_ids", [])
            new_attrs["security_group_id"] = sg_ids[0] if sg_ids else None

        if data.get("type") == "subnet":
            new_attrs.setdefault("public", False)

        display_graph.add_node(node, **new_attrs)

    for source, target, data in source_graph.edges(data=True):
        new_attrs = dict(data)
        new_attrs.setdefault("protocol", DEFAULT_PROTOCOL)
        new_attrs.setdefault("relationship", "connected")
        display_graph.add_edge(source, target, **new_attrs)

    return TopologyView(display_graph)