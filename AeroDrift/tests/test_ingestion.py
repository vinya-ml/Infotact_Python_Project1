import json
from pathlib import Path

import pytest

from app.ingestion.aws_ingestion import CloudStateLoader


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


class TestCloudStateLoader:

    def test_load_returns_dict(self):
        loader = CloudStateLoader(STATE_FILE)
        state = loader.load()
        assert isinstance(state, dict)

    def test_load_contains_expected_keys(self):
        loader = CloudStateLoader(STATE_FILE)
        state = loader.load()
        assert "vpcs" in state
        assert "subnets" in state
        assert "security_groups" in state
        assert "instances" in state

    def test_load_vpc_count(self):
        loader = CloudStateLoader(STATE_FILE)
        state = loader.load()
        assert len(state["vpcs"]) == 1

    def test_load_instance_count(self):
        loader = CloudStateLoader(STATE_FILE)
        state = loader.load()
        assert len(state["instances"]) == 1

    def test_summary_returns_counts(self):
        loader = CloudStateLoader(STATE_FILE)
        summary = loader.summary()
        assert summary["vpcs"] == 1
        assert summary["subnets"] == 1
        assert summary["security_groups"] == 1
        assert summary["instances"] == 1

    def test_missing_file_raises(self):
        loader = CloudStateLoader("/nonexistent/path.json")
        with pytest.raises(FileNotFoundError):
            loader.load()
