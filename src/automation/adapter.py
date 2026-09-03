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

# Fields every diagnose_drift() finding must have for conversion to work.
REQUIRED_FIELDS = ["resource_id", "bad_rule", "path"]

# Fields that must exist inside "bad_rule" specifically.
REQUIRED_BAD_RULE_FIELDS = ["port", "cidr"]


class InvalidFindingError(ValueError):
    """
    Raised when a diagnose_drift() finding is missing required data.

    Using a specific, named exception (instead of a generic KeyError)
    makes it immediately clear WHERE the problem is - a malformed finding
    from the Graph module - rather than looking like a bug inside the
    Automation module itself.
    """
    pass


def _validate_finding(drift_finding: dict) -> None:
    """
    Checks that a drift_finding dict has everything convert_finding() needs.
    Raises InvalidFindingError with a specific, human-readable message if
    anything is missing - instead of failing later with a confusing KeyError.
    """
    if not isinstance(drift_finding, dict):
        raise InvalidFindingError(
            f"Expected a dict, got {type(drift_finding).__name__} instead: {drift_finding!r}"
        )

    missing_top_level = [f for f in REQUIRED_FIELDS if f not in drift_finding]
    if missing_top_level:
        raise InvalidFindingError(
            f"Finding is missing required field(s): {missing_top_level}. "
            f"Received keys: {list(drift_finding.keys())}"
        )

    bad_rule = drift_finding["bad_rule"]
    if not isinstance(bad_rule, dict):
        raise InvalidFindingError(
            f"'bad_rule' must be a dict, got {type(bad_rule).__name__} instead: {bad_rule!r}"
        )

    missing_rule_fields = [f for f in REQUIRED_BAD_RULE_FIELDS if f not in bad_rule]
    if missing_rule_fields:
        raise InvalidFindingError(
            f"'bad_rule' is missing required field(s): {missing_rule_fields}. "
            f"Received keys: {list(bad_rule.keys())}"
        )

    path = drift_finding["path"]
    if not isinstance(path, list) or len(path) == 0:
        raise InvalidFindingError(
            f"'path' must be a non-empty list, got: {path!r}"
        )


def convert_finding(drift_finding: dict) -> SimpleNamespace:
    """
    Convert a single diagnose_drift() dict into a DriftFinding-shaped object.

    Raises InvalidFindingError with a specific, clear message if the input
    is missing required fields - so a malformed finding fails loudly and
    understandably here, rather than causing a confusing error later
    inside generator.py.
    """
    _validate_finding(drift_finding)

    bad_rule = drift_finding["bad_rule"]
    path = drift_finding["path"]

    return SimpleNamespace(
        target=path[-1],
        security_group=drift_finding["resource_id"],
        protocol=bad_rule.get("protocol", DEFAULT_PROTOCOL),
        port=bad_rule.get("port"),
        source=bad_rule.get("cidr"),
        path=path,
    )


def convert_all(drift_findings: list[dict]) -> list[SimpleNamespace]:
    """
    Convert a whole list of diagnose_drift() findings at once.

    If any single finding is invalid, raises InvalidFindingError
    immediately, naming which finding (by index) caused the problem -
    rather than silently skipping it or converting a partial list.
    """
    converted = []
    for i, finding in enumerate(drift_findings):
        try:
            converted.append(convert_finding(finding))
        except InvalidFindingError as e:
            raise InvalidFindingError(f"Finding at index {i} is invalid: {e}") from e
    return converted


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

    print()
    print("Testing validation with a malformed finding...")
    try:
        convert_finding({"resource_id": "sg-002"})  # missing bad_rule, path
    except InvalidFindingError as e:
        print(f"  Correctly caught: {e}")