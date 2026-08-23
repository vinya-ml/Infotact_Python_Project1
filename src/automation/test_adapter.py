from src.automation.adapter import convert_finding, convert_all

def test_convert_finding():
    finding = {
        "drift_type": "open_ingress",
        "resource_id": "sg-001",
        "bad_rule": {
            "port": 22,
            "cidr": "0.0.0.0/0"
        },
        "path": ["internet", "sg-001", "i-001"]
    }

    result = convert_finding(finding)

    assert result.target == "i-001"
    assert result.security_group == "sg-001"
    assert result.protocol == "tcp"
    assert result.port == 22
    assert result.source == "0.0.0.0/0"
    assert result.path == ["internet", "sg-001", "i-001"]


def test_convert_all():
    findings = [
        {
            "drift_type": "open_ingress",
            "resource_id": "sg-001",
            "bad_rule": {
                "port": 22,
                "cidr": "0.0.0.0/0"
            },
            "path": ["internet", "sg-001", "i-001"]
        }
    ]

    results = convert_all(findings)

    assert len(results) == 1
    assert results[0].security_group == "sg-001"
    assert results[0].port == 22
