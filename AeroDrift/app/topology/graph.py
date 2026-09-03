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
        self.graph.add_edge(
            source,
            target,
            **attributes
        )

    def build_from_state(self, state):
        """Build the cloud topology from the ingested AWS state."""

        self.graph.clear()

        # --------------------------------------------------
        # Internet
        # --------------------------------------------------

        self.add_resource(
            "internet",
            "Internet"
        )

        # --------------------------------------------------
        # VPCs
        # --------------------------------------------------

        for vpc in state.get("vpcs", []):

            self.add_resource(
                vpc["id"],
                "VPC",
                name=vpc.get("name")
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

            vpc_id = subnet.get("vpc_id")

            if vpc_id:
                self.add_connection(
                    vpc_id,
                    subnet_id,
                    relationship="contains"
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

            for ingress in sg.get("ingress", []):

                source_cidr = ingress.get("source")

                # Public Internet ingress
                if source_cidr == "0.0.0.0/0":

                    self.add_connection(
                        "internet",
                        sg_id,
                        relationship="ingress",
                        protocol=ingress.get("protocol"),
                        port=ingress.get("port"),
                        source_cidr=source_cidr
                    )

        # --------------------------------------------------
        # EC2 Instances
        # --------------------------------------------------

        for instance in state.get("instances", []):

            instance_id = instance["id"]

            subnet_id = instance.get(
                "subnet_id"
            )

            security_group_id = instance.get(
                "security_group_id"
            )

            self.add_resource(
                instance_id,
                "EC2",
                name=instance.get("name"),
                subnet_id=subnet_id,
                security_group_id=security_group_id
            )

            # Subnet → EC2
            if subnet_id:

                self.add_connection(
                    subnet_id,
                    instance_id,
                    relationship="contains"
                )

            # Security Group → EC2
            if security_group_id:

                self.add_connection(
                    security_group_id,
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