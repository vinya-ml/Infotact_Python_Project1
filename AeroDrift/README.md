# AeroDrift

**Cloud Topology & Remediation Graph** - A self-healing infrastructure tool for Cloud Operations.

## Problem

Cloud environments (AWS/GCP) drift from secure baselines. An engineer opens a security group to SSH and forgets to close it. AeroDrift detects this drift via a graph-based topology, then autonomously writes and executes remediation code to self-heal.

## Architecture

```
AeroDrift/
├── app/
│   ├── ingestion/       # Cloud state ingestion (JSON/boto3)
│   ├── topology/        # NetworkX directed graph builder
│   ├── detection/       # Drift detection engine
│   ├── remediation/     # AST-based code generator + sandbox
│   ├── cli/             # Rich CLI dashboard + PDF reports
│   └── persistence/     # SQLite historical state storage
├── data/                # Mock AWS state files
├── tests/               # Unit tests (63 tests)
├── reports/             # Generated PDF incident reports
└── main.py              # CLI entry point
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a full scan (ingest -> detect -> remediate -> persist -> report)
python main.py full-scan

# Individual commands
python main.py scan          # Ingest state and detect drift
python main.py dashboard     # Display topology tree
python main.py detect        # Run drift detection only
python main.py remediate     # Generate and execute remediation
python main.py report        # Generate PDF incident report
python main.py history       # View past scan history
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Ingest cloud state, build topology graph, detect drift |
| `dashboard` | Display full cloud dashboard with topology tree |
| `detect` | Run drift detection and display findings |
| `remediate` | Generate and execute remediation scripts (supports `--dry-run`) |
| `report` | Generate PDF incident report |
| `full-scan` | Run complete pipeline end-to-end |
| `history` | Show previous scan history from database |

## Key Features

- **Graph-based topology**: NetworkX directed graph representing cloud infrastructure
- **Drift detection**: Detects private resources exposed to the public internet
- **AST code generation**: Programmatically generates boto3 remediation scripts
- **Execution sandbox**: Safe dry-run mode for testing remediation code
- **Rich CLI**: Beautiful terminal UI with tree rendering and drift highlighting
- **PDF reports**: Incident reports with findings, attack paths, and remediation actions
- **SQLite persistence**: Historical scan storage with diff capability

## Testing

```bash
python -m pytest tests/ -v
```

## Tech Stack

- `boto3` - AWS API interaction
- `networkx` - Graph/topology engine
- `rich` - CLI dashboard rendering
- `click` - CLI framework
- `reportlab` - PDF report generation
- `sqlite3` - Historical state persistence
