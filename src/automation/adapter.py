"""
adapter.py - Converts graph_engine.py's diagnose_drift() output into the
DriftFinding shape that generator.py and sandbox.py expect.

This is the "glue" between the Graph module and the Automation module,
which were built independently and originally used different data shapes.

diagnose_drift() produces dicts shaped like:
    {
        "drift_type": "open_ingress",
        "resource_id": "sg-001",
        "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"},
        "path": ["internet", "sg-001", "i-001"],
    }

generator.py expects objects with these attributes:
    finding.target           -> the exposed resource
    finding.security_group   -> the security group id
    finding.protocol         -> e.g. "tcp"
    finding.port             -> e.g. 22
    finding.source           -> the exposed CIDR
    finding.path             -> list of node ids
"""

from types import SimpleNamespace


# graph_engine.py's data doesn't include a protocol field (tcp/udp) yet.
# Defaulting to "tcp" is a reasonable assumption for now, since that's the
# most common case for the kind of rules being detected (e.g. SSH on port 22).
# Worth revisiting if the AWS ingestion module adds a real protocol field later.
DEFAULT_PROTOCOL = "tcp"


def convert_finding(drift_finding: dict) -> SimpleNamespace:
    """
    Convert a single diagnose_drift() dict into a DriftFinding-shaped object.

    Raises KeyError if the input dict is missing an expected field - this
    is intentional, so a malformed finding fails loudly here rather than
    causing a confusing error later inside generator.py.
    """
    bad_rule = drift_finding["bad_rule"]
    path = drift_finding["path"]

    return SimpleNamespace(
        target=path[-1] if path else drift_finding.get("resource_id"),
        security_group=drift_finding["resource_id"],
        protocol=bad_rule.get("protocol", DEFAULT_PROTOCOL),
        port=bad_rule.get("port"),
        source=bad_rule.get("cidr"),
        path=path,
    )


def convert_all(drift_findings: list[dict]) -> list[SimpleNamespace]:
    """Convert a whole list of diagnose_drift() findings at once."""
    return [convert_finding(f) for f in drift_findings]


if __name__ == "__main__":
    # Quick manual check, using a realistic example finding
    example = {
        "drift_type": "open_ingress",
        "resource_id": "sg-001",
        "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"},
        "path": ["internet", "sg-001", "i-001"],
    }

    converted = convert_finding(example)
    print("Converted finding:")
    print(f"  target:         {converted.target}")
    print(f"  security_group: {converted.security_group}")
    print(f"  protocol:       {converted.protocol}")
    print(f"  port:           {converted.port}")
    print(f"  source:         {converted.source}")
    print(f"  path:           {converted.path}")