"""
test_missing_fields.py - Edge case test: what happens when data is incomplete?

Real AWS data is messy. This test checks that build_graph() and
diagnose_drift() don't crash when a resource is missing fields they'd
normally expect - they should just skip gracefully.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


MESSY_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-002",
            "name": "isolated-server",
            "subnet_id": "subnet-001",
            "security_group_ids": [],  # <-- no security groups attached
            "state": "running",
            "role": "database"
        }
    ],
    "subnets": [
        {"id": "subnet-001", "name": "private-subnet", "vpc_id": "vpc-001"}
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


def test_no_crash_on_missing_ingress_rules_and_empty_sg_list():
    graph = build_graph(MESSY_AWS_STATE)  # should not raise
    findings = diagnose_drift(graph)      # should not raise
    assert findings == [], "No path to internet exists, so there should be no findings"


def test_graph_still_builds_with_messy_data():
    graph = build_graph(MESSY_AWS_STATE)
    assert graph.number_of_nodes() == 4