"""
Shared fake AWS resource data for the AeroDrift project.

Everyone on the team should import from this file instead of writing their
own fake data - that's what keeps everyone's code compatible on merge day.

Shape agreed by the team:
{
    "id": str,                     # unique resource id
    "type": str,                   # "internet" | "vpc" | "security_group" | "instance"
    "allows_from": list[str],      # only on security_group - list of CIDR strings
    "port": int,                   # only on security_group
    "attached_to": str,            # only on security_group - id of the resource it protects
    "role": str,                   # only on instance - e.g. "database", "web", "app"
}
"""

# Scenario: a safe, small cloud setup, PLUS one dangerous drift case.
#
#   internet
#      |
#   sg-web  (open to the world, port 80 - fine, it's a public web server)
#      |
#   i-web-01 (role: web)
#
#   internet
#      |
#   sg-db  (open to the world, port 22 - NOT fine, this is a database!)
#      |
#   i-db-01 (role: database)   <-- THIS is the drift you should detect
#
#   sg-internal (only allows traffic from inside the VPC - safe, no path from internet)
#      |
#   i-app-01 (role: app)

SAMPLE_RESOURCES = [
    {"id": "internet", "type": "internet"},
    {"id": "vpc-main", "type": "vpc"},

    # Safe: public web server, meant to be open on port 80
    {
        "id": "sg-web",
        "type": "security_group",
        "allows_from": ["0.0.0.0/0"],
        "port": 80,
        "attached_to": "i-web-01",
    },
    {"id": "i-web-01", "type": "instance", "role": "web"},

    # DRIFT: database security group accidentally left open to the whole internet
    {
        "id": "sg-db",
        "type": "security_group",
        "allows_from": ["0.0.0.0/0"],
        "port": 22,
        "attached_to": "i-db-01",
    },
    {"id": "i-db-01", "type": "instance", "role": "database"},

    # Safe: internal-only security group, no path from the internet
    {
        "id": "sg-internal",
        "type": "security_group",
        "allows_from": ["10.0.0.0/16"],  # private VPC range, not the internet
        "port": 5432,
        "attached_to": "i-app-01",
    },
    {"id": "i-app-01", "type": "instance", "role": "app"},
]