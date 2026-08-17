# Graph Engine (NetworkX Topology & Drift Detection)

## What this module does

Takes AWS resource data (instances, subnets, security groups) and builds
a directed graph representing the network topology. Then checks that
graph to answer the core question this project exists for:

**"Is anything reachable from the public internet that shouldn't be?"**

## Files

- `graph_engine.py` — the main module. Two public functions:
  - `build_graph(aws_state)` — turns AWS-shaped data into a NetworkX graph.
  - `diagnose_drift(graph)` — finds any instance reachable from the internet.
- `tests/test_zero_drift.py` — confirms no false positives on a safe setup.
- `tests/test_missing_fields.py` — confirms no crash on incomplete data.
- `tests/test_shared_security_group.py` — confirms multiple instances behind
  one exposed security group are all correctly flagged.

## How to run it

```
cd src/graph
python graph_engine.py
```

Requires `src/aws/mock_data.py` to exist (Member 1's AWS ingestion module).

## How to run the tests

```
cd src/graph/tests
python test_zero_drift.py
python test_missing_fields.py
python test_shared_security_group.py
```

Each prints PASS or FAIL with an explanation.

## Data shape this module expects

```python
{
    "ec2_instances": [
        {"id": str, "name": str, "subnet_id": str, "security_group_ids": list[str], "state": str}
    ],
    "subnets": [
        {"id": str, "name": str, "vpc_id": str}
    ],
    "security_groups": [
        {
            "id": str, "name": str, "vpc_id": str,
            "ingress_rules": [{"port": int, "cidr": str}]  # optional, may be missing
        }
    ]
}
```

## Known limitation (as of this writing)

Member 1's current mock data doesn't yet include `ingress_rules` on
security groups. Until that's added, `diagnose_drift()` will correctly
return an empty list (no false positives) — but won't detect real drift
either, since there's no rule data to check yet.