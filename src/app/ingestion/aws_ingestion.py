import json
from pathlib import Path


class CloudStateLoader:
    """Loads a cloud state JSON file from disk."""

    def __init__(self, state_file):
        self.state_file = Path(state_file)

    def load(self):
        """Load and return the cloud state."""
        if not self.state_file.exists():
            raise FileNotFoundError(
                f"Cloud state file not found: {self.state_file}"
            )

        with open(self.state_file, "r", encoding="utf-8") as handle:
            return json.load(handle)
