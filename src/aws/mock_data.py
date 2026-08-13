MOCK_AWS_STATE = {
    "ec2_instances": [
        {
            "id": "i-001",
            "name": "aerodrift-server",
            "subnet_id": "subnet-001",
            "security_group_ids": ["sg-001"],
            "state": "running"
        }
    ],
    "subnets": [
        {
            "id": "subnet-001",
            "name": "private-subnet",
            "vpc_id": "vpc-001"
        }
    ],
    "security_groups": [
        {
            "id": "sg-001",
            "name": "aerodrift-sg",
            "vpc_id": "vpc-001"
        }
    ]
}
