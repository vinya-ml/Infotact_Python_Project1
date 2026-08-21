from pathlib import Path
from types import SimpleNamespace

from src.cli.generator import RemediationGenerator


def make_finding():
    return SimpleNamespace(
        source="0.0.0.0/0",
        protocol="tcp",
        port=22,
        security_group="sg-001",
        target="i-001",
        path=["internet", "sg-001", "i-001"],
    )


def test_generate_revoke_ingress():
    generator = RemediationGenerator()

    finding = make_finding()

    module = generator.generate_revoke_ingress(finding)

    assert module is not None
    assert len(module.body) == 4


def test_render_code():
    generator = RemediationGenerator()

    finding = make_finding()

    code = generator.render_code(finding)

    assert "import boto3" in code
    assert "revoke_security_group_ingress" in code
    assert "sg-001" in code
    assert "0.0.0.0/0" in code
    assert "22" in code


def test_save_script(tmp_path):
    generator = RemediationGenerator(output_dir=tmp_path)

    finding = make_finding()

    filepath = generator.save_script(finding)

    assert filepath.exists()
    assert filepath.suffix == ".py"
    assert "sg-001" in filepath.name

    content = filepath.read_text(encoding="utf-8")

    assert "AeroDrift Auto-Generated Remediation Script" in content
    assert "sg-001" in content


def test_generate_all(tmp_path):
    generator = RemediationGenerator(output_dir=tmp_path)

    findings = [
        make_finding(),
        SimpleNamespace(
            source="10.0.0.0/8",
            protocol="tcp",
            port=80,
            security_group="sg-002",
            target="i-002",
            path=["internet", "sg-002", "i-002"],
        ),
    ]

    scripts = generator.generate_all(findings)

    assert len(scripts) == 2

    for script in scripts:
        assert Path(script).exists()
