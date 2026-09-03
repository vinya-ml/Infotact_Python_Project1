import json
from pathlib import Path


class StateManager:
    """Manages saving and loading AWS resource states."""

    def __init__(self, state_file=None):
        if state_file is None:
            state_file = (
                Path(__file__).resolve().parents[2]
                / "data"
                / "aws_state.json"
            )

        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def save_state(self, state):
        """Save AWS state to a JSON file."""
        with open(self.state_file, "w", encoding="utf-8") as file:
            json.dump(state, file, indent=4)

    def load_state(self):
        """Load AWS state from a JSON file."""
        if not self.state_file.exists():
            return None

        with open(self.state_file, "r", encoding="utf-8") as file:
            return json.load(file)
