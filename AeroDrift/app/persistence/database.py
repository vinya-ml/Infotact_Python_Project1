import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class AeroDriftDB:
    """SQLite persistence layer for AeroDrift graph states and findings."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = (
                Path(__file__).resolve().parents[2] / "aerodrift.db"
            )
        self.db_path = Path(db_path)
        self.conn = None

    def connect(self):
        """Open the database connection and ensure tables exist."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        return self

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def _create_tables(self):
        """Create the schema if it does not already exist."""
        cursor = self.conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                state_file  TEXT,
                node_count  INTEGER,
                edge_count  INTEGER,
                finding_count INTEGER
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS drift_findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id     INTEGER NOT NULL,
                target          TEXT,
                security_group  TEXT,
                protocol        TEXT,
                port            INTEGER,
                source          TEXT,
                path            TEXT,
                remediated      INTEGER DEFAULT 0,
                remediation_script TEXT,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                nodes_json  TEXT,
                edges_json  TEXT,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
            )
        """
        )

        self.conn.commit()

    def save_scan(self, topology, findings, state_file="mock"):
        """Persist a scan run with its graph snapshot and findings."""

        now = datetime.now(timezone.utc).isoformat()
        summary = topology.summary()

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_runs
                (timestamp, state_file, node_count, edge_count, finding_count)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                now,
                state_file,
                summary["nodes"],
                summary["edges"],
                len(findings),
            ),
        )

        scan_id = cursor.lastrowid

        nodes = [
            {"id": n, **attrs}
            for n, attrs in topology.graph.nodes(data=True)
        ]
        edges = [
            {"source": u, "target": v, **attrs}
            for u, v, attrs in topology.graph.edges(data=True)
        ]

        cursor.execute(
            """
            INSERT INTO graph_snapshots (scan_run_id, nodes_json, edges_json)
            VALUES (?, ?, ?)
        """,
            (scan_id, json.dumps(nodes), json.dumps(edges)),
        )

        for finding in findings:
            cursor.execute(
                """
                INSERT INTO drift_findings
                    (scan_run_id, target, security_group,
                     protocol, port, source, path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_id,
                    finding.target,
                    finding.security_group,
                    finding.protocol,
                    finding.port,
                    finding.source,
                    " -> ".join(finding.path),
                ),
            )

        self.conn.commit()
        return scan_id

    def list_scans(self):
        """Return all scan runs ordered by most recent."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC"
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_findings(self, scan_id):
        """Return all findings for a given scan run."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM drift_findings WHERE scan_run_id = ?",
            (scan_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_snapshot(self, scan_id):
        """Return the graph snapshot for a given scan run."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM graph_snapshots WHERE scan_run_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "nodes": json.loads(row["nodes_json"]),
            "edges": json.loads(row["edges_json"]),
        }

    def diff_snapshots(self, scan_id_a, scan_id_b):
        """Compare two scan runs and return added/removed nodes and edges."""
        snap_a = self.get_snapshot(scan_id_a)
        snap_b = self.get_snapshot(scan_id_b)

        if snap_a is None or snap_b is None:
            return None

        nodes_a = {n["id"] for n in snap_a["nodes"]}
        nodes_b = {n["id"] for n in snap_b["nodes"]}

        edges_a = {
            (e["source"], e["target"]) for e in snap_a["edges"]
        }
        edges_b = {
            (e["source"], e["target"]) for e in snap_b["edges"]
        }

        return {
            "nodes_added": sorted(nodes_b - nodes_a),
            "nodes_removed": sorted(nodes_a - nodes_b),
            "edges_added": sorted(edges_b - edges_a),
            "edges_removed": sorted(edges_a - edges_b),
        }
