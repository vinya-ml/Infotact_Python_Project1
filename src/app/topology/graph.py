import networkx as nx


class CloudTopology:
    """Builds a directed graph representing the cloud infrastructure."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_resource(self, resource_id, resource_type, **attributes):
        """Add a cloud resource as a graph node."""
        self.graph.add_node(
            resource_id,
            resource_type=resource_type,
            **attributes
        )

    def add_connection(self, source, target, **attributes):
        """Add a connection between two cloud resources."""
        if source in self.graph and target in self.graph:
            self.graph.add_edge(
                source,
                target,
                **attributes
            )

    def build_from_state(self, state):
        """Build the topology from the ingested AWS state.

        Expects the team's mock schema:

            {
                "ec2_instances": [...],
                "subnets":       [...],
                "security_groups": [{"ingress_rules": [{"port", "cidr"}]}]
            }
        """

        self.graph.clear()

        # --------------------------------------------------
        # Internet
        # --------------------------------------------------

        self.add_resource(
            "internet",
            "Internet"
        )

        # --------------------------------------------------
        # Subnets
        # --------------------------------------------------

        for subnet in state.get("subnets", []):

            subnet_id = subnet["id"]

            self.add_resource(
                subnet_id,
                "Subnet",
                name=subnet.get("name"),
                vpc_id=subnet.get("vpc_id"),
                public=subnet.get("public", False)
            )

        # --------------------------------------------------
        # Security Groups
        # --------------------------------------------------

        for sg in state.get("security_groups", []):

            sg_id = sg["id"]

            self.add_resource(
                sg_id,
                "SecurityGroup",
                name=sg.get("name")
            )

            for rule in sg.get("ingress_rules", []):

                source_cidr = rule.get("cidr")

                if source_cidr == "0.0.0.0/0":

                    self.add_connection(
                        "internet",
                        sg_id,
                        relationship="ingress",
                        protocol=rule.get("protocol", "tcp"),
                        port=rule.get("port"),
                        source_cidr=source_cidr
                    )

        # --------------------------------------------------
        # EC2 Instances
        # --------------------------------------------------

        for instance in state.get("ec2_instances", []):

            instance_id = instance["id"]

            subnet_id = instance.get(
                "subnet_id"
            )

            security_group_ids = instance.get(
                "security_group_ids", []
            )

            self.add_resource(
                instance_id,
                "EC2",
                name=instance.get("name"),
                subnet_id=subnet_id,
                security_group_id=security_group_ids[0] if security_group_ids else None,
                security_group_ids=security_group_ids
            )

            # Subnet -> EC2
            if subnet_id:

                self.add_connection(
                    subnet_id,
                    instance_id,
                    relationship="contains"
                )

            # Security Group -> EC2
            for sg_id in security_group_ids:

                self.add_connection(
                    sg_id,
                    instance_id,
                    relationship="protects"
                )

        return self

    def has_path(self, source, target):
        """Check whether a path exists between two resources."""

        if source not in self.graph:
            return False

        if target not in self.graph:
            return False

        return nx.has_path(
            self.graph,
            source,
            target
        )

    def get_path(self, source, target):
        """Return the shortest path between two resources."""

        if not self.has_path(
            source,
            target
        ):
            return None

        return nx.shortest_path(
            self.graph,
            source,
            target
        )

    def resources(self):
        """Return all resources in the topology."""

        return list(
            self.graph.nodes(
                data=True
            )
        )

    def connections(self):
        """Return all connections in the topology."""

        return list(
            self.graph.edges(
                data=True
            )
        )

    def summary(self):
        """Return basic graph statistics."""

        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges()
        }
