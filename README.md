# AeroDrift — Agentic Cloud Topology & Remediation Graph

AeroDrift watches a cloud environment for security drift — resources
accidentally exposed to the public internet — and automatically detects,
diagnoses, and safely fixes the problem, without waiting on a manual
review cycle.

**Domain:** Cloud Operations (CloudOps) & Infrastructure Automation
**Program:** Infotact Solutions — Advanced Python Engineering (Vol. II)

## How it works, in one sentence

Real (mock) AWS data is turned into a graph → the graph is checked for
any path from the public internet to a private resource → if found, a
fix is automatically generated and safely executed → the whole thing is
shown on a terminal dashboard.

```
AWS Data (src/aws)
      |
      v
Graph Engine (src/graph)  -- builds topology, detects drift
      |
      v
Automation (src/automation)  -- generates + safely executes fixes
      |
      v
CLI Dashboard (src/cli)  -- displays everything, generates reports
```

## Team & Modules

| Module | Owner |
|---|---|
| `src/aws` — AWS data ingestion | Member 1 |
| `src/graph` — Topology & drift detection (NetworkX) | Member 2 |
| `src/automation` — Code generation & safe execution (ast/exec) | Member 1,Member 2 & Member 3 |
| `src/cli` — Dashboard, reports (Rich) | Member 3 | 

## What's working right now (Week 1–2)

- **`src/aws`**: Provides mock AWS state (VPCs, subnets, security groups
  with ingress rules, EC2 instances).
- **`src/graph`**: `build_graph()` converts AWS data into a NetworkX
  directed graph. `diagnose_drift()` detects any resource reachable from
  the internet. Covered by 3 passing edge-case tests (zero-drift, missing
  fields, shared security groups).
- **`src/automation`**: Takes a detected drift finding, generates the
  exact `boto3` fix code using Python's `ast` module, and safely executes
  it in a sandboxed dry-run mode. Confirmed working end-to-end with real
  data from `src/aws` and `src/graph`.
- **`src/cli`**: Displays the topology, drift findings, and remediation
  results in a Rich-based terminal dashboard, and generates PDF incident
  reports. Currently being connected to the real `src/graph` and
  `src/automation` output (see Known Issues below).

## How to run it

```bash
# From the project root
pip install -r requirements.txt   # networkx, rich, click, reportlab

# Run the graph engine directly
python -m src.graph.graph_engine

# Run the automation pipeline directly
python -m src.automation.automation_engine

# Run the full CLI
python -m src.cli.main dashboard
python -m src.cli.main remediate --dry-run
python -m src.cli.main report
```

## Known issues (actively being resolved)

`src/cli/main.py` originally depended on an earlier standalone prototype
(the `AeroDrift/` folder) that used a different data format and class
structure than what the team's real `src/aws` and `src/graph` modules
produce. This is being corrected to call the real modules directly,
using a small `topology_adapter.py` in `src/automation` so the existing
dashboard code doesn't need to be rewritten. Fix in progress.

## Tech stack

- **NetworkX** — graph modeling and path-finding
- **Python `ast`** — programmatic code generation for fixes
- **Rich** — terminal dashboard rendering
- **ReportLab** — PDF incident report generation
- **SQLite** — scan history persistence
- **pytest** — testing

## Project documents

- `PROJECT.pdf` — original project brief
- `PROJECT_INSTRUCTIONS.pdf` — collaboration guidelines
- `Infotact_Project_Execution_Handbook_V1.0.pdf` — SOP, review schedule, GitHub rules