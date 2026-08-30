"""
test_missing_fields.py - Edge case test: what happens when data is incomplete?

Real AWS data is messy. This test checks that build_graph() and
diagnose_drift() don't crash when a resource is missing fields they'd
normally expect - they should just skip gracefully.

Run this directly: python test_missing_fields.py
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


# An instance with NO security_group_ids at all (empty list) - a resource
# that isn't protected by anything, which is unusual but real.
# Also: a security group with no ingress_rules key at all (not even empty).
MESSY_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-002",
            "name": "isolated-server",
            "subnet_id": "subnet-001",
            "security_group_ids": [],  # <-- no security groups attached
            "state": "running"
        }
    ],
    "subnets": [
        {
            "id": "subnet-001",
            "name": "private-subnet",
            "vpc_id": "vpc-001"
        }
    ],
    "security_groups": [
        {
            "id": "sg-002",
            "name": "unused-sg",
            "vpc_id": "vpc-001"
            # <-- no "ingress_rules" key at all, not even an empty list
        }
    ]
}


if __name__ == "__main__":
    try:
        graph = build_graph(MESSY_AWS_STATE)
        findings = diagnose_drift(graph)

        print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
        print(f"Findings: {findings}")
        print()
        print("PASS: No crash. Code handled missing/empty fields gracefully.")

    except Exception as e:
        print(f"FAIL: Code crashed on messy data!")
        print(f"Error: {type(e).__name__}: {e}")
