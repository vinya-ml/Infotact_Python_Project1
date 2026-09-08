# AeroDrift

## Agentic Cloud Topology & Remediation Graph

AeroDrift is a Python-based CloudOps and infrastructure automation system designed to detect cloud configuration drift and security issues by representing cloud resources and their relationships as a directed graph.

The system analyzes cloud topology using **NetworkX**, detects unsafe network paths such as public access to a private database, generates remediation code using Python's **AST (Abstract Syntax Tree)** module, and safely executes the generated remediation in a controlled dry-run sandbox.

---

##  Problem Statement

Cloud environments can gradually drift away from their intended secure configuration.

For example, an engineer may temporarily open **SSH port 22** to the public internet using a Security Group rule and forget to close it afterward. This can expose a sensitive resource to unwanted network access.

Traditional Infrastructure-as-Code tools can help identify configuration drift, but remediation may still require manual intervention.

AeroDrift addresses this problem by connecting:

**Cloud State → Graph Analysis → Drift Detection → Remediation → Audit**

---

##  Objectives

The main objectives of AeroDrift are:

* Represent cloud infrastructure as a directed graph.
* Model relationships between cloud resources.
* Detect unsafe network paths.
* Identify publicly exposed resources.
* Detect Security Group ingress rules allowing `0.0.0.0/0`.
* Generate remediation scripts programmatically.
* Execute remediation safely using a controlled sandbox.
* Store historical scan information in SQLite.
* Generate automated PDF incident reports.
* Provide a Rich-based command-line dashboard.

---

##  Key Features

### 1. Cloud State Ingestion

AeroDrift works with a structured AWS state containing resources such as:

* EC2 instances
* Subnets
* Security Groups

The current project uses a **controlled mock AWS state** for testing and demonstration.

---

### 2. Network Topology Modeling

Cloud resources are represented using a directed **NetworkX graph**.

Example topology:

```text
Internet
   ↓
Security Group
   ↓
EC2 Database
```

Nodes represent cloud resources, while edges represent relationships or network pathways.

---

### 3. Drift Detection

The system analyzes the graph to identify unsafe connectivity.

A key security condition is:

```text
0.0.0.0/0 → Security Group → Database
```

`0.0.0.0/0` represents all IPv4 addresses.

If a database instance has a network path from the Internet, AeroDrift reports it as a security drift finding.

Example:

```text
Internet → sg-001 → i-001
```

---

### 4. AST-Based Remediation

AeroDrift uses Python's **AST (Abstract Syntax Tree)** module to programmatically generate remediation code.

For an unsafe Security Group ingress rule, the generated code uses:

```python
boto3.revoke_security_group_ingress()
```

The generator creates the Python syntax tree programmatically and converts it back into Python source code using `ast.unparse()`.

Generated scripts are stored in:

```text
generated_remediation/
```

---

### 5. Safe Execution Sandbox

Generated remediation scripts are executed through a controlled sandbox.

The project supports **dry-run mode**, where the real AWS SDK operation is replaced by a mock implementation.

Therefore, during testing:

```text
Generated Script
       ↓
Sandbox
       ↓
Mock boto3 Client
       ↓
Simulated Remediation
```

No real AWS resource is modified during dry-run execution.

---

### 6. Agentic Automation

The automation layer connects detection and remediation into a single workflow.

```text
Detect Drift
     ↓
Convert Finding
     ↓
Generate Remediation
     ↓
Execute in Sandbox
     ↓
Record Result
```

The agent also keeps track of previously seen findings so that the same issue is not repeatedly remediated during subsequent cycles.

---

### 7. Rich CLI Dashboard

AeroDrift provides a terminal-based dashboard using the **Rich** library.

It can display:

* Cloud resource summary
* Network topology
* Security drift findings
* Remediation results
* Persistence information

---

### 8. SQLite Persistence

Historical scan information is stored in a local SQLite database.

The database stores information such as:

* Scan runs
* Drift findings
* Graph snapshots
* Remediation information
* Timestamps

Database file:

```text
aerodrift.db
```

---

### 9. PDF Incident Reports

AeroDrift can generate automated PDF incident reports using **ReportLab**.

The report contains information such as:

* Scan information
* Executive summary
* Topology statistics
* Detected drift findings
* Remediation results

Reports are generated in:

```text
reports/
```

---

##  System Architecture

```text
                 Cloud / Mock AWS State
                           │
                           ▼
                    AWS State Layer
                           │
                           ▼
                  NetworkX Graph Engine
                           │
                           ▼
                   Drift Detection
                           │
                    ┌──────┴──────┐
                    │             │
                 No Drift       Drift Found
                    │             │
                    ▼             ▼
               Dashboard     Finding Adapter
                                  │
                                  ▼
                           AST Code Generator
                                  │
                                  ▼
                         Remediation Script
                                  │
                                  ▼
                           Safe Sandbox
                                  │
                         ┌────────┴────────┐
                         │                 │
                      SQLite          PDF Report
                         │                 │
                         └────────┬────────┘
                                  ▼
                            Audit / History
```

---

##  Project Structure

```text
Infotact_Python_Project1/
│
├── README.md
├── PROJECT.pdf
├── PROJECT_INSTRUCTIONS.pdf
├── Infotact_Project_Execution_Handbook_V1.0.pdf
├── .gitignore
│
├── data/
│   └── aws_state.json
│
├── generated_remediation/
│   └── remediate_sg-001_22.py
│
├── aerodrift.db
├── pytest.ini
│
├── src/
│   │
│   ├── app/
│   │   └── __init__.py
│   │
│   ├── aws/
│   │   ├── __init__.py
│   │   ├── ingestion.py
│   │   ├── mock_data.py
│   │   └── state_manager.py
│   │
│   ├── graph/
│   │   ├── README.md
│   │   └── graph_engine.py
│   │
│   ├── automation/
│   │   ├── README.md
│   │   ├── adapter.py
│   │   ├── generator.py
│   │   ├── sandbox.py
│   │   ├── automation_engine.py
│   │   ├── agent.py
│   │   ├── loop.py
│   │   └── topology_adapter.py
│   │
│   └── cli/
│       ├── main.py
│       ├── dashboard.py
│       ├── database.py
│       ├── report.py
│       ├── test_generator.py
│       └── test_sandbox.py
│
└── tests/
```

---

##  Technology Stack

| Technology    | Purpose                                   |
| ------------- | ----------------------------------------- |
| **Python**    | Core programming language                 |
| **NetworkX**  | Cloud topology and graph analysis         |
| **boto3**     | AWS interaction/remediation interface     |
| **AST**       | Programmatic Python code generation       |
| **asyncio**   | Asynchronous automation loop              |
| **Rich**      | Terminal dashboard and visualization      |
| **SQLite**    | Historical state and scan persistence     |
| **ReportLab** | PDF incident report generation            |
| **pytest**    | Automated testing                         |
| **exec()**    | Controlled execution of generated scripts |

---

##  How AeroDrift Works

### Step 1 — Load Cloud State

The system loads the controlled AWS state containing EC2 instances, Subnets and Security Groups.

### Step 2 — Build the Graph

The cloud state is converted into a directed NetworkX graph.

Example:

```text
Internet
   ↓
sg-001
   ↓
i-001
```

### Step 3 — Analyze the Graph

The system searches for a path from the Internet to sensitive resources such as database instances.

### Step 4 — Detect Drift

If an unsafe path exists because of an open Security Group ingress rule, AeroDrift creates a drift finding.

Example:

```text
Drift Type: open_ingress
Security Group: sg-001
Port: 22
Source: 0.0.0.0/0
Path: Internet → sg-001 → i-001
```

### Step 5 — Generate Remediation

The finding is passed to the automation layer.

The AST generator creates the required remediation code.

### Step 6 — Execute Safely

The generated script is executed through the remediation sandbox.

In dry-run mode, the AWS operation is mocked.

### Step 7 — Persist Results

Scan and remediation information is stored in SQLite.

### Step 8 — Generate Reports

The system can generate a PDF incident report containing the detected drift and remediation results.

---

##  Installation

Clone the repository:

```bash
git clone <your-repository-url>
```

Navigate into the project:

```bash
cd Infotact_Python_Project1
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

If a requirements file is not present, install the required Python packages according to the project environment.

---

##  Running the Project

### Scan Cloud State

```bash
python -m src.cli.main scan
```

This performs the complete topology scan and displays detected drift.

---

### Detect Drift

```bash
python -m src.cli.main detect
```

This focuses on detected security drift findings.

---

### View Dashboard

```bash
python -m src.cli.main dashboard
```

Displays the cloud topology through the Rich CLI interface.

---

### Run Remediation in Dry-Run Mode

```bash
python -m src.cli.main remediate --dry-run
```

This:

1. Detects drift
2. Generates remediation scripts
3. Executes them in dry-run mode
4. Displays remediation results
5. Saves scan information

---

### View Scan History

```bash
python -m src.cli.main history
```

Displays previously stored scan information.

---

### Generate PDF Report

```bash
python -m src.cli.main report
```

Generates an automated incident report in PDF format.

---

##  Testing

The project uses **pytest** for automated testing.

Run:

```bash
python -m pytest -q
```

The current project test suite passes successfully.

---

##  Safety Considerations

AeroDrift includes several safety mechanisms:

* Dry-run remediation mode
* Mock AWS client during dry-run execution
* Controlled execution environment
* Validation of remediation findings
* Live-mode confirmation requirement
* Prevention of repeated remediation for already-seen findings

Live remediation should only be enabled in an appropriately configured and authorized AWS environment.

---

##  Example Detection

Consider the following Security Group rule:

```text
Protocol: TCP
Port: 22
Source: 0.0.0.0/0
```

The resulting topology may be:

```text
Internet
    │
    ▼
Security Group (sg-001)
    │
    ▼
EC2 Database (i-001)
```

AeroDrift identifies this as an unsafe Internet-to-database path and generates remediation for the open ingress rule.

---

##  Generated Remediation

The remediation generator produces an AWS SDK call conceptually equivalent to:

```python
ec2.revoke_security_group_ingress(
    GroupId="sg-001",
    IpPermissions=[{
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"}
        ]
    }]
)
```

The generated script can then be tested through the sandbox in dry-run mode.

---

##  Why NetworkX?

Network security problems are naturally represented as connectivity problems.

Instead of checking resources independently, AeroDrift represents them as a graph and asks questions such as:

```text
"Is there a path from the Internet to this database?"
```

NetworkX provides graph operations such as:

* Directed graphs
* Path detection
* Shortest path analysis
* Node and edge management

This makes topology-based security analysis easier to implement.

---

##  Why AST?

AST stands for **Abstract Syntax Tree**.

Instead of constructing remediation code only as plain strings, AeroDrift programmatically constructs Python syntax using the `ast` module.

This allows the remediation generator to create structured Python code dynamically based on the detected drift.

---

##  Why a Sandbox?

Automatically generated code should not be executed against real cloud infrastructure during testing.

Therefore, AeroDrift provides a controlled execution environment.

In dry-run mode:

```text
Real boto3
     ↓
Replaced with Mock Client
     ↓
No real AWS modification
```

This makes the remediation workflow safer to test.

---

##  Current Implementation Scope

The current project is designed as a controlled demonstration and engineering prototype.

The AWS state used for the current implementation is a **mock/controlled state** rather than a continuously connected production AWS environment.

The project demonstrates the complete detection-to-remediation workflow while keeping actual cloud modification disabled during dry-run testing.

---

## 🔮 Future Scope

Possible future improvements include:

* Live AWS `boto3` ingestion
* More comprehensive asynchronous cloud polling
* Support for additional AWS resources
* VPC and Internet Gateway topology modeling
* Multi-cloud support for GCP
* Advanced security policies
* User approval workflows before live remediation
* Rollback mechanisms
* More comprehensive topology diff commands
* Production-grade authentication and authorization
* Real-time monitoring and alerting
* Integration with CI/CD and Infrastructure-as-Code workflows

---

## Project Contribution

The Graph and Automation modules form the core contribution toward the detection and remediation workflow.

Key areas include:

* Converting cloud state into a directed NetworkX graph
* Defining resource relationships and network paths
* Implementing path-based drift detection
* Connecting graph findings with the automation pipeline
* Converting findings into the format required by the remediation generator
* Generating AWS remediation code using Python AST
* Executing generated remediation safely through the sandbox

---

## 🏁 Conclusion

AeroDrift demonstrates how **Graph Theory, Cloud APIs, Python Metaprogramming and Automation** can be combined to build a CloudOps security workflow.

The overall pipeline is:

```text
Cloud State
     ↓
NetworkX Topology
     ↓
Drift Detection
     ↓
AST Remediation
     ↓
Safe Execution
     ↓
SQLite Persistence
     ↓
Rich Dashboard / PDF Report
```

> **AeroDrift observes the cloud as a graph, detects unsafe network paths, generates the fix, and safely performs the remediation.**
