import json
from pathlib import Path

import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def topology():
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topo = CloudTopology()
    topo.build_from_state(state)
    return topo


class TestCloudTopology:

    def test_graph_has_nodes(self, topology):
        assert topology.graph.number_of_nodes() > 0

    def test_graph_has_edges(self, topology):
        assert topology.graph.number_of_edges() > 0

    def test_internet_node_exists(self, topology):
        assert "internet" in topology.graph

    def test_vpc_node_exists(self, topology):
        assert "vpc-prod" in topology.graph

    def test_subnet_node_exists(self, topology):
        assert "subnet-private" in topology.graph

    def test_ec2_node_exists(self, topology):
        assert "ec2-database" in topology.graph

    def test_sg_node_exists(self, topology):
        assert "sg-database" in topology.graph

    def test_internet_to_sg_edge(self, topology):
        assert topology.graph.has_edge("internet", "sg-database")

    def test_sg_to_ec2_edge(self, topology):
        assert topology.graph.has_edge("sg-database", "ec2-database")

    def test_subnet_to_ec2_edge(self, topology):
        assert topology.graph.has_edge("subnet-private", "ec2-database")

    def test_vpc_to_subnet_edge(self, topology):
        assert topology.graph.has_edge("vpc-prod", "subnet-private")

    def test_has_path_internet_to_ec2(self, topology):
        assert topology.has_path("internet", "ec2-database")

    def test_get_path_returns_list(self, topology):
        path = topology.get_path("internet", "ec2-database")
        assert isinstance(path, list)
        assert path[0] == "internet"
        assert path[-1] == "ec2-database"

    def test_summary_node_count(self, topology):
        summary = topology.summary()
        assert summary["nodes"] == 5

    def test_summary_edge_count(self, topology):
        summary = topology.summary()
        assert summary["edges"] == 4

    def test_resources_returns_list(self, topology):
        resources = topology.resources()
        assert isinstance(resources, list)
        assert len(resources) == 5

    def test_connections_returns_list(self, topology):
        connections = topology.connections()
        assert isinstance(connections, list)
        assert len(connections) == 4

    def test_no_path_nonexistent_node(self, topology):
        assert not topology.has_path("internet", "nonexistent")
