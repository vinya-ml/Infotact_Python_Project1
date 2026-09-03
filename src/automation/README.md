# Automation Module (Code Generation & Safe Execution)

## What this module does

Takes a detected security drift (from `graph_engine.diagnose_drift()`) and
automatically generates and safely runs the exact fix for it — the
"self-healing" part of AeroDrift.

## The pipeline

```
diagnose_drift() output (dict)
        |
        v
   adapter.py          <- converts dict into the shape generator.py expects
        |
        v
   generator.py         <- builds real Python/boto3 fix code using ast
        |
        v
   sandbox.py            <- safely executes that code (dry-run by default)
        |
        v
   ExecutionResult        <- success/failure + output
```

## Files

- `adapter.py` — converts `diagnose_drift()`'s dict output into the
  `DriftFinding`-shaped object the generator expects. Includes input
  validation (`InvalidFindingError`) that raises a clear, specific error
  if a finding is missing required fields, rather than failing with a
  confusing generic error later on.
- `generator.py` — builds an AST representing the exact `boto3` fix call,
  then converts it to real, runnable Python code.
- `sandbox.py` — executes generated fix scripts safely. In `dry_run=True`
  mode (the default), it swaps in a mock AWS client, so nothing real is
  ever touched — safe to run anytime, including during testing.
- `automation_engine.py` — the single public entry point. Everything else
  (like the CLI) should call `remediate()` from here, not the individual
  pieces directly.
- `test_adapter.py` / `test_automation_engine.py` — basic functional tests.
- `test_generated_code_structure.py` — parses the generated fix code with
  Python's own `ast` module and verifies its actual structure (correct
  function call, correct arguments) — not just that it runs without error.
- `test_multiple_findings.py` — confirms `generate_all()` correctly
  handles several findings at once, with no data mixing between the
  resulting scripts.

## Current scope (Week 3)

Right now, this module supports exactly one type of drift:
**`open_ingress`** — a security group with a rule allowing traffic from
`0.0.0.0/0` (the open internet). Extending this to a second drift type
depends on the Graph module's detection logic being expanded first;
as of this writing, no second drift type has been finalized by the team.

## How to use it

```python
from graph.graph_engine import build_graph, diagnose_drift
from aws.mock_data import MOCK_AWS_STATE
from automation.automation_engine import remediate

graph = build_graph(MOCK_AWS_STATE)
findings = diagnose_drift(graph)

results = remediate(findings, dry_run=True)

for r in results:
    print(r.success, r.output)
```

## Known assumption

`diagnose_drift()`'s output doesn't currently include a network protocol
(tcp/udp) field, so `adapter.py` defaults every finding to `"tcp"`. This
is reasonable for the common case (e.g. SSH on port 22), but worth
revisiting if the AWS ingestion module adds a real protocol field later.

## Safety note

Always use `dry_run=True` unless there is a specific, intentional reason
to actually execute a real AWS change. The sandbox's dry-run mode
completely replaces the AWS client with a mock — no real API calls are
made in that mode.