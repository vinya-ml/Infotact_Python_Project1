from .mock_data import MOCK_AWS_STATE
from .state_manager import StateManager


def get_mock_aws_state():
    """Return mock AWS infrastructure state for development."""
    return MOCK_AWS_STATE


def ingest_and_save_state():
    """Get AWS state and save it to the state file."""
    state = get_mock_aws_state()

    state_manager = StateManager()
    state_manager.save_state(state)

    return state


if __name__ == "__main__":
    state = ingest_and_save_state()

    print("AWS State:")
    print(state)

    print("\nState saved successfully.")
