"""
test_shared_security_group.py - Edge case test: one security group,
multiple instances.

If a security group protecting TWO instances gets exposed to the internet,
both instances should be flagged - not just the first one found.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from graph_engine import build_graph, diagnose_drift


SHARED_SG_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-010",
            "name": "server-one",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-shared"],
            "state": "running",
            "role": "database"
        },
        {
            "id": "i-011",
            "name": "server-two",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-shared"],
            "state": "running",
            "role": "database"
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
                {"port": 22, "cidr": "0.0.0.0/0"}
            ]
        }
    ]
}


def test_both_instances_flagged_when_sharing_exposed_sg():
    graph = build_graph(SHARED_SG_AWS_STATE)
    findings = diagnose_drift(graph)

    flagged_instances = {f["path"][-1] for f in findings}
    assert flagged_instances == {"i-010", "i-011"}


def test_correct_number_of_findings_for_shared_sg():
    graph = build_graph(SHARED_SG_AWS_STATE)
    findings = diagnose_drift(graph)
    assert len(findings) == 2