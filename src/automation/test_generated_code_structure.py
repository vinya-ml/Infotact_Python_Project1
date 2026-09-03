"""
test_generated_code_structure.py - Verifies the CODE ITSELF that
generator.py produces is structurally correct, not just that it happens
to run without errors.

This matters because a test that only checks "did it run" could pass
even if the generated code accidentally called the WRONG function, or
passed the WRONG arguments, as long as it didn't crash. Parsing the
generated code with Python's own `ast` module and walking the tree lets
us confirm the actual function call and its arguments are correct.
"""

import ast
from types import SimpleNamespace

from generator import RemediationGenerator


def make_finding():
    return SimpleNamespace(
        target="i-001",
        security_group="sg-001",
        protocol="tcp",
        port=22,
        source="0.0.0.0/0",
        path=["internet", "sg-001", "i-001"],
    )


def find_call_nodes(tree, function_name):
    """Walk an AST and return every function call matching the given name."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == function_name:
                calls.append(node)
    return calls


def get_keyword_value(call_node, keyword_name):
    """Extract the literal value of a specific keyword argument from a Call node."""
    for kw in call_node.keywords:
        if kw.arg == keyword_name:
            if isinstance(kw.value, ast.Constant):
                return kw.value.value
    return None


class TestGeneratedCodeStructure:

    def setup_method(self):
        self.generator = RemediationGenerator(output_dir="/tmp/test_remediation_structure")
        self.finding = make_finding()
        self.code = self.generator.render_code(self.finding)
        self.tree = ast.parse(self.code)

    def test_generated_code_is_valid_python(self):
        assert self.tree is not None

    def test_code_imports_boto3(self):
        import_found = any(
            isinstance(node, ast.Import) and any(alias.name == "boto3" for alias in node.names)
            for node in ast.walk(self.tree)
        )
        assert import_found, "Generated code does not import boto3"

    def test_code_calls_revoke_security_group_ingress(self):
        calls = find_call_nodes(self.tree, "revoke_security_group_ingress")
        assert len(calls) == 1, (
            f"Expected exactly 1 call to revoke_security_group_ingress, found {len(calls)}"
        )

    def test_revoke_call_has_correct_group_id(self):
        calls = find_call_nodes(self.tree, "revoke_security_group_ingress")
        group_id = get_keyword_value(calls[0], "GroupId")
        assert group_id == "sg-001", f"Expected GroupId 'sg-001', got {group_id!r}"

    def test_revoke_call_ip_permissions_has_correct_port(self):
        calls = find_call_nodes(self.tree, "revoke_security_group_ingress")
        ip_permissions_node = None
        for kw in calls[0].keywords:
            if kw.arg == "IpPermissions":
                ip_permissions_node = kw.value
        assert ip_permissions_node is not None, "No IpPermissions argument found"

        first_dict = ip_permissions_node.elts[0]
        from_port = None
        for key_node, value_node in zip(first_dict.keys, first_dict.values):
            if isinstance(key_node, ast.Constant) and key_node.value == "FromPort":
                from_port = value_node.value
        assert from_port == 22, f"Expected FromPort 22, got {from_port!r}"

    def test_no_hardcoded_credentials_in_generated_code(self):
        suspicious_terms = ["aws_secret_access_key", "aws_access_key_id", "password"]
        for term in suspicious_terms:
            assert term not in self.code.lower(), f"Found suspicious term '{term}' in generated code"


if __name__ == "__main__":
    test = TestGeneratedCodeStructure()
    test.setup_method()

    print("Generated code:")
    print(test.code)
    print()

    test.test_generated_code_is_valid_python()
    print("PASS: valid Python syntax")

    test.test_code_imports_boto3()
    print("PASS: imports boto3")

    test.test_code_calls_revoke_security_group_ingress()
    print("PASS: calls revoke_security_group_ingress exactly once")

    test.test_revoke_call_has_correct_group_id()
    print("PASS: GroupId is correct")

    test.test_revoke_call_ip_permissions_has_correct_port()
    print("PASS: FromPort is correct")

    test.test_no_hardcoded_credentials_in_generated_code()
    print("PASS: no hardcoded credentials found")