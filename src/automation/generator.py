"""
generator.py - AST-based Remediation Script Generator

Generates boto3 remediation scripts from drift findings using Python's
ast module. Each finding produces a script that calls
ec2.revoke_security_group_ingress() to close the offending rule.

Accepts findings as dicts from graph_engine.diagnose_drift():
    {
        "drift_type": "open_ingress",
        "resource_id": "sg-001",
        "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"},
        "path": ["internet", "sg-001", "i-001"],
    }

Public API:
    RemediationGenerator(output_dir=None)
        .generate_revoke_ingress(finding)  -> ast.Module
        .render_code(finding)              -> str
        .save_script(finding)              -> Path
        .generate_all(findings)            -> list[Path]
"""

import ast
import textwrap
from pathlib import Path


class RemediationGenerator:
    """Generates Python remediation code from drift findings using ast."""

    def __init__(self, output_dir=None):
        if output_dir is None:
            output_dir = (
                Path(__file__).resolve().parents[2] / "generated_remediation"
            )
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _extract(self, finding):
        """Extract normalized fields from a finding dict."""
        bad_rule = finding.get("bad_rule", {})
        path = finding.get("path", [])
        return {
            "sg_id": finding.get("resource_id", "unknown-sg"),
            "port": bad_rule.get("port", 0),
            "cidr": bad_rule.get("cidr", "0.0.0.0/0"),
            "protocol": "tcp",
            "target": path[-1] if path else "unknown",
            "path": path,
        }

    def generate_revoke_ingress(self, finding):
        """Build an AST for a boto3 revoke_security_group_ingress call."""
        f = self._extract(finding)

        import_node = ast.Import(names=[ast.alias(name="boto3")])

        client_call = ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="boto3", ctx=ast.Load()),
                attr="client",
                ctx=ast.Load(),
            ),
            args=[ast.Constant(value="ec2")],
            keywords=[],
        )

        client_assign = ast.Assign(
            targets=[ast.Name(id="ec2", ctx=ast.Store())],
            value=client_call,
        )

        ip_range_dict = ast.Dict(
            keys=[ast.Constant(value="CidrIp")],
            values=[ast.Constant(value=f["cidr"])],
        )

        ip_permissions_dict = ast.Dict(
            keys=[
                ast.Constant(value="IpProtocol"),
                ast.Constant(value="FromPort"),
                ast.Constant(value="ToPort"),
                ast.Constant(value="IpRanges"),
            ],
            values=[
                ast.Constant(value=f["protocol"]),
                ast.Constant(value=f["port"]),
                ast.Constant(value=f["port"]),
                ast.List(elts=[ip_range_dict], ctx=ast.Load()),
            ],
        )

        revoke_call = ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="ec2", ctx=ast.Load()),
                attr="revoke_security_group_ingress",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(
                    arg="GroupId",
                    value=ast.Constant(value=f["sg_id"]),
                ),
                ast.keyword(
                    arg="IpPermissions",
                    value=ast.List(
                        elts=[ip_permissions_dict], ctx=ast.Load()
                    ),
                ),
            ],
        )

        revoke_assign = ast.Assign(
            targets=[ast.Name(id="response", ctx=ast.Store())],
            value=revoke_call,
        )

        print_call = ast.Expr(
            value=ast.Call(
                func=ast.Name(id="print", ctx=ast.Load()),
                args=[
                    ast.Constant(
                        value=(
                            f"Revoked {f['protocol']}/{f['port']} from "
                            f"{f['cidr']} on {f['sg_id']}"
                        )
                    )
                ],
                keywords=[],
            )
        )

        module = ast.Module(
            body=[import_node, client_assign, revoke_assign, print_call],
            type_ignores=[],
        )

        ast.fix_missing_locations(module)
        return module

    def render_code(self, finding):
        """Return the generated Python source code as a string."""
        module = self.generate_revoke_ingress(finding)
        lines = [ast.unparse(node) for node in module.body]
        return "\n\n".join(lines) + "\n"

    def save_script(self, finding):
        """Write the remediation script to disk and return the path."""
        f = self._extract(finding)
        code = self.render_code(finding)

        safe_name = f["sg_id"].replace("/", "_")
        filename = f"remediate_{safe_name}_{f['port']}.py"
        filepath = self.output_dir / filename

        header = textwrap.dedent(
            f"""\
            # AeroDrift Auto-Generated Remediation Script
            # Target:  {f['target']}
            # SG:      {f['sg_id']}
            # Rule:    {f['protocol']}/{f['port']} from {f['cidr']}
            # Path:    {" -> ".join(f['path'])}

            """
        )

        filepath.write_text(header + code, encoding="utf-8")
        return filepath

    def generate_all(self, findings):
        """Generate and save remediation scripts for all findings."""
        return [self.save_script(f) for f in findings]
