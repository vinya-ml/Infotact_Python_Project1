class DriftFinding:
    """Represents one detected cloud security drift."""

    def __init__(
        self,
        target,
        security_group,
        protocol,
        port,
        source,
        path
    ):
        self.target = target
        self.security_group = security_group
        self.protocol = protocol
        self.port = port
        self.source = source
        self.path = path


class DriftDetector:
    """Detects security configuration drift."""

    def __init__(self, topology):
        self.topology = topology

    def detect_public_database_exposure(self):
        """
        Detect private EC2 resources that are reachable
        from the public Internet.
        """

        findings = []

        # Examine every resource in the topology
        for node, attributes in self.topology.graph.nodes(
            data=True
        ):

            # We currently detect exposure of EC2 resources
            if attributes.get("resource_type") != "EC2":
                continue

            # --------------------------------------------------
            # Check subnet
            # --------------------------------------------------

            subnet_id = attributes.get(
                "subnet_id"
            )

            if not subnet_id:
                continue

            if subnet_id not in self.topology.graph:
                continue

            subnet = self.topology.graph.nodes[
                subnet_id
            ]

            # We are interested in private resources
            if subnet.get(
                "public",
                False
            ):
                continue

            # --------------------------------------------------
            # Check Internet reachability
            # --------------------------------------------------

            if not self.topology.has_path(
                "internet",
                node
            ):
                continue

            path = self.topology.get_path(
                "internet",
                node
            )

            # --------------------------------------------------
            # Identify security group
            # --------------------------------------------------

            security_group = attributes.get(
                "security_group_id"
            )

            if not security_group:
                continue

            # --------------------------------------------------
            # Find Internet → Security Group edge
            # --------------------------------------------------

            edge = self.topology.graph.get_edge_data(
                "internet",
                security_group
            )

            if not edge:
                continue

            # --------------------------------------------------
            # Create drift finding
            # --------------------------------------------------

            finding = DriftFinding(
                target=attributes.get(
                    "name",
                    node
                ),
                security_group=security_group,
                protocol=edge.get(
                    "protocol",
                    "unknown"
                ),
                port=edge.get(
                    "port",
                    0
                ),
                source=edge.get(
                    "source_cidr",
                    "unknown"
                ),
                path=path
            )

            findings.append(
                finding
            )

        return findings