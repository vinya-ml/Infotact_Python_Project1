import json
from pathlib import Path


class CloudStateLoader:
    """Loads cloud infrastructure state from a JSON file."""

    def __init__(self, state_file):
        self.state_file = Path(state_file)

    def load(self):
        """Load and return the cloud state."""
        if not self.state_file.exists():
            raise FileNotFoundError(
                f"Cloud state file not found: {self.state_file}"
            )

        with self.state_file.open("r", encoding="utf-8") as file:
            return json.load(file)

    def summary(self):
        """Return a simple summary of the cloud environment."""
        state = self.load()

        return {
            "vpcs": len(state.get("vpcs", [])),
            "subnets": len(state.get("subnets", [])),
            "security_groups": len(state.get("security_groups", [])),
            "instances": len(state.get("instances", []))
        }


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[2]
    state_file = project_root / "data" / "mock_aws_state.json"

    loader = CloudStateLoader(state_file)

    print("AeroDrift Cloud State")
    print("---------------------")

    summary = loader.summary()

    for resource_type, count in summary.items():
        print(f"{resource_type}: {count}")