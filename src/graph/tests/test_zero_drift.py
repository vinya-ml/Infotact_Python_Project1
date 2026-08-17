"""
test_zero_drift.py - Edge case test: what happens when NOTHING is exposed?

A correct diagnose_drift() should return an EMPTY list here - not crash,
and not falsely report a problem that doesn't exist.

Run this directly: python test_zero_drift.py
"""

import sys
import os

# Let this file find graph_engine.py, which sits one folder up (in graph/)
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


# A safe setup: the security group only allows traffic from inside the
# private network (10.0.0.0/16), never from the open internet (0.0.0.0/0).
SAFE_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-001",
            "name": "aerodrift-server",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-001"],
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
            "id": "sg-001",
            "name": "aerodrift-sg",
            "vpc_id": "vpc-001",
            "ingress_rules": [
                {"port": 22, "cidr": "10.0.0.0/16"}  # private range, NOT the internet
            ]
        }
    ]
}


if __name__ == "__main__":
    graph = build_graph(SAFE_AWS_STATE)
    findings = diagnose_drift(graph)

    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print(f"Findings: {findings}")
    print()

    if findings == []:
        print("PASS: No drift found, as expected. Correctly recognized a safe setup.")
    else:
        print("FAIL: Something was incorrectly flagged as drift when nothing was wrong!")
        print("This means diagnose_drift() has a bug - it's too aggressive.")