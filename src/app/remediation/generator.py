import ast
import textwrap
from pathlib import Path


class RemediationGenerator:
    """Generates Python remediation code from DriftFinding objects using ast."""

    def __init__(self, output_dir=None):
        if output_dir is None:
            output_dir = (
                Path(__file__).resolve().parents[2]
                / "generated_remediation"
            )
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_revoke_ingress(self, finding):
        """Build an AST for a boto3 revoke_security_group_ingress call."""

        import_node = ast.Import(
            names=[ast.alias(name="boto3")]
        )

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
            values=[ast.Constant(value=finding.source)],
        )

        ip_permissions_dict = ast.Dict(
            keys=[
                ast.Constant(value="IpProtocol"),
                ast.Constant(value="FromPort"),
                ast.Constant(value="ToPort"),
                ast.Constant(value="IpRanges"),
            ],
            values=[
                ast.Constant(value=finding.protocol),
                ast.Constant(value=finding.port),
                ast.Constant(value=finding.port),
                ast.List(
                    elts=[ip_range_dict],
                    ctx=ast.Load(),
                ),
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
                    value=ast.Constant(value=finding.security_group),
                ),
                ast.keyword(
                    arg="IpPermissions",
                    value=ast.List(
                        elts=[ip_permissions_dict],
                        ctx=ast.Load(),
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
                            f"Revoked {finding.protocol}/"
                            f"{finding.port} from "
                            f"{finding.source} on "
                            f"{finding.security_group}"
                        )
                    )
                ],
                keywords=[],
            )
        )

        module = ast.Module(
            body=[
                import_node,
                client_assign,
                revoke_assign,
                print_call,
            ],
            type_ignores=[],
        )

        ast.fix_missing_locations(module)
        return module

    def render_code(self, finding):
        """Return the generated Python source code as a string."""

        module = self.generate_revoke_ingress(finding)

        lines = []
        for node in module.body:
            lines.append(ast.unparse(node))

        return "\n\n".join(lines) + "\n"

    def save_script(self, finding):
        """Write the remediation script to disk and return the path."""

        code = self.render_code(finding)

        safe_name = finding.security_group.replace("/", "_")
        filename = f"remediate_{safe_name}_{finding.port}.py"
        filepath = self.output_dir / filename

        header = textwrap.dedent(
            f"""\
            # AeroDrift Auto-Generated Remediation Script
            # Target:  {finding.target}
            # SG:      {finding.security_group}
            # Rule:    {finding.protocol}/{finding.port} from {finding.source}
            # Path:    {" -> ".join(finding.path)}

            """
        )

        filepath.write_text(header + code, encoding="utf-8")

        return filepath

    def generate_all(self, findings):
        """Generate and save remediation scripts for all findings."""

        scripts = []

        for finding in findings:
            path = self.save_script(finding)
            scripts.append(path)

        return scripts
