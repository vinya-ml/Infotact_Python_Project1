"""
test_multiple_findings.py - Confirms generate_all() correctly handles
MULTIPLE drift findings at once, creating a separate, correct script for
each one - with no data mixing between them.

This matters because a bug here could silently cause one finding's fix
to overwrite another's, or apply the wrong port/security-group to the
wrong script - a subtle, dangerous kind of bug that a single-finding
test would never catch.
"""

from types import SimpleNamespace

from generator import RemediationGenerator


def make_finding(security_group, port, target):
    return SimpleNamespace(
        target=target,
        security_group=security_group,
        protocol="tcp",
        port=port,
        source="0.0.0.0/0",
        path=["internet", security_group, target],
    )


class TestMultipleFindings:

    def setup_method(self):
        self.generator = RemediationGenerator(output_dir="/tmp/test_remediation_multi")
        self.findings = [
            make_finding("sg-001", 22, "i-001"),
            make_finding("sg-002", 3389, "i-002"),
            make_finding("sg-003", 5432, "i-003"),
        ]
        self.scripts = self.generator.generate_all(self.findings)

    def test_generate_all_returns_correct_count(self):
        assert len(self.scripts) == 3, f"Expected 3 scripts, got {len(self.scripts)}"

    def test_generate_all_creates_distinct_files(self):
        # Every path should be unique - no two findings should overwrite
        # the same file.
        paths = [str(s) for s in self.scripts]
        assert len(set(paths)) == 3, f"Expected 3 distinct file paths, got: {paths}"

    def test_each_script_has_correct_security_group(self):
        # This is the important one: confirm sg-001's script actually
        # references sg-001, NOT sg-002 or sg-003's data leaking in.
        expected_groups = ["sg-001", "sg-002", "sg-003"]
        for script_path, expected_group in zip(self.scripts, expected_groups):
            content = script_path.read_text()
            assert expected_group in content, (
                f"Expected '{expected_group}' in {script_path.name}, but it wasn't found"
            )

    def test_each_script_has_correct_port(self):
        expected_ports = [22, 3389, 5432]
        for script_path, expected_port in zip(self.scripts, expected_ports):
            content = script_path.read_text()
            assert f"'FromPort': {expected_port}" in content, (
                f"Expected port {expected_port} in {script_path.name}, but it wasn't found"
            )

    def test_no_cross_contamination_between_scripts(self):
        # The strongest check: sg-001's script should NOT contain sg-002
        # or sg-003's identifiers anywhere.
        sg001_content = self.scripts[0].read_text()
        assert "sg-002" not in sg001_content
        assert "sg-003" not in sg001_content

    def test_generate_all_with_single_finding_still_works(self):
        # Make sure the multi-finding logic didn't break the original
        # single-finding case.
        single_result = self.generator.generate_all([self.findings[0]])
        assert len(single_result) == 1

    def test_generate_all_with_empty_list_returns_empty(self):
        # An empty list of findings is a normal, valid case - should
        # return an empty list of scripts, not crash.
        empty_result = self.generator.generate_all([])
        assert empty_result == []


if __name__ == "__main__":
    test = TestMultipleFindings()
    test.setup_method()

    print(f"Generated {len(test.scripts)} scripts:")
    for s in test.scripts:
        print(f"  {s}")
    print()

    test.test_generate_all_returns_correct_count()
    print("PASS: correct count returned")

    test.test_generate_all_creates_distinct_files()
    print("PASS: all files are distinct")

    test.test_each_script_has_correct_security_group()
    print("PASS: each script has its own correct security group")

    test.test_each_script_has_correct_port()
    print("PASS: each script has its own correct port")

    test.test_no_cross_contamination_between_scripts()
    print("PASS: no data mixing between scripts")

    test.test_generate_all_with_single_finding_still_works()
    print("PASS: single-finding case still works")

    test.test_generate_all_with_empty_list_returns_empty()
    print("PASS: empty list handled correctly")