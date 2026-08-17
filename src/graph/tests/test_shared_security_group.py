"""
test_shared_security_group.py - Edge case test: one security group,
multiple instances.

If a security group protecting TWO instances gets exposed to the internet,
both instances should be flagged - not just the first one found.

Run this directly: python test_shared_security_group.py
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


# Two instances, both attached to the SAME exposed security group.
SHARED_SG_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-010",
            "name": "server-one",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-shared"],
            "state": "running"
        },
        {
            "id": "i-011",
            "name": "server-two",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-shared"],  # <-- same security group
            "state": "running"
        }
    ],
    "subnets": [
        {"id": "subnet-001", "name": "private-subnet", "vpc_id": "vpc-001"}
    ],
    "security_groups": [
        {
            "id": "sg-shared",
            "name": "shared-sg",
            "vpc_id": "vpc-001",
            "ingress_rules": [
                {"port": 22, "cidr": "0.0.0.0/0"}  # exposed to the internet
            ]
        }
    ]
}


if __name__ == "__main__":
    graph = build_graph(SHARED_SG_AWS_STATE)
    findings = diagnose_drift(graph)

    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    print(f"Findings: {findings}")
    print()

    flagged_instances = {f["path"][-1] for f in findings}
    expected_instances = {"i-010", "i-011"}

    if flagged_instances == expected_instances:
        print(f"PASS: Both instances correctly flagged: {flagged_instances}")
    else:
        print(f"FAIL: Expected both {expected_instances} flagged, but got {flagged_instances}")