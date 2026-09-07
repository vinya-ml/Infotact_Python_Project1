"""
test_zero_drift.py - Edge case test: what happens when NOTHING is exposed?

A correct diagnose_drift() should return an EMPTY list here - not crash,
and not falsely report a problem that doesn't exist.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


SAFE_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-001",
            "name": "aerodrift-server",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-001"],
            "state": "running",
            "role": "database"
        }
    ],
    "subnets": [
        {"id": "subnet-001", "name": "private-subnet", "vpc_id": "vpc-001"}
    ],
    "security_groups": [
        {
            "id": "sg-001",
            "name": "aerodrift-sg",
            "vpc_id": "vpc-001",
            "ingress_rules": [
                {"port": 22, "cidr": "10.0.0.0/16"}  # private range, NOT the internet
            ]
        }
    ]
}


def test_no_drift_when_ingress_is_private_only():
    graph = build_graph(SAFE_AWS_STATE)
    findings = diagnose_drift(graph)
    assert findings == [], "Expected no drift when ingress only allows a private CIDR range"


def test_graph_builds_correctly_even_when_safe():
    graph = build_graph(SAFE_AWS_STATE)
    assert graph.number_of_nodes() == 4
    assert graph.number_of_edges() == 2