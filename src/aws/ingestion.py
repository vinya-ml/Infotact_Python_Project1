from .mock_data import MOCK_AWS_STATE


def get_mock_aws_state():
    """Return mock AWS infrastructure state for development."""
    return MOCK_AWS_STATE


if __name__ == "__main__":
    state = get_mock_aws_state()

    print("AWS State:")
    print(state)

