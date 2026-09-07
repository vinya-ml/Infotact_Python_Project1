"""
report.py - PDF Incident Report Generator

Generates styled A4 PDF reports using ReportLab with:
  - Executive summary (finding count, graph stats)
  - Drift findings table
  - Remediation actions table (if results provided)
  - Footer with generation timestamp

Public API:
    ReportGenerator(output_dir=None)
        .generate(findings, graph, remediation_results=None, scan_id=None)
            -> Path to the generated PDF
"""

from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table as RLTable,
    TableStyle,
    HRFlowable,
)

_BRAND_DARK = colors.HexColor("#1a1a2e")
_BRAND_RED = colors.HexColor("#e94560")
_BRAND_LIGHT = colors.HexColor("#fff5f5")


class ReportGenerator:
    """Generates PDF incident reports from scan results."""

    def __init__(self, output_dir=None):
        if output_dir is None:
            output_dir = Path(__file__).resolve().parents[2] / "reports"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        findings,
        graph,
        remediation_results=None,
        scan_id=None,
    ):
        """Create a full PDF incident report and return the file path.

        Args:
            findings:            list of dicts from diagnose_drift()
            graph:               NetworkX DiGraph from build_graph()
            remediation_results: list of ExecutionResult (optional)
            scan_id:             integer scan ID from the DB (optional)
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"aerodrift_report_{timestamp}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        elements = []

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            textColor=_BRAND_DARK,
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#555555"),
            spaceAfter=20,
        )
        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=_BRAND_RED,
            spaceBefore=16,
            spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "BodyText",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=6,
        )

        # ── Title ──
        elements.append(Paragraph("AeroDrift Incident Report", title_style))

        generated_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        scan_label = f"Scan #{scan_id}" if scan_id else "Ad-hoc"
        elements.append(
            Paragraph(
                f"Generated: {generated_at} &nbsp;|&nbsp; Scan: {scan_label}",
                subtitle_style,
            )
        )

        elements.append(
            HRFlowable(width="100%", thickness=2, color=_BRAND_RED)
        )

        # ── 1. Executive Summary ──
        elements.append(Paragraph("1. Executive Summary", heading_style))

        if not findings:
            elements.append(
                Paragraph(
                    "No security drift was detected during this scan. "
                    "All private resources are properly isolated from "
                    "the public internet.",
                    body_style,
                )
            )
        else:
            elements.append(
                Paragraph(
                    f"<b>{len(findings)}</b> security drift "
                    f"finding(s) were detected. Private resources "
                    f"are reachable from the public internet through "
                    f"overly permissive security group rules.",
                    body_style,
                )
            )

        node_count = graph.number_of_nodes()
        edge_count = graph.number_of_edges()
        elements.append(
            Paragraph(
                f"The topology graph contains <b>{node_count}</b> "
                f"nodes and <b>{edge_count}</b> edges.",
                body_style,
            )
        )

        # ── 2. Drift Findings ──
        elements.append(Paragraph("2. Drift Findings", heading_style))

        if findings:
            header = ["Drift Type", "Resource", "Port", "CIDR", "Path"]
            table_data = [header]

            for f in findings:
                bad_rule = f.get("bad_rule", {})
                table_data.append([
                    f.get("drift_type", "-"),
                    f.get("resource_id", "-"),
                    str(bad_rule.get("port", "-")),
                    bad_rule.get("cidr", "-"),
                    " -> ".join(f.get("path", [])),
                ])

            tbl = RLTable(table_data, repeatRows=1)
            tbl.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), _BRAND_RED),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_BRAND_LIGHT, colors.white]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            elements.append(tbl)
        else:
            elements.append(Paragraph("No findings to display.", body_style))

        # ── 3. Remediation Actions ──
        if remediation_results:
            elements.append(Paragraph("3. Remediation Actions", heading_style))

            rem_header = ["Script", "Status", "Output"]
            rem_data = [rem_header]

            for r in remediation_results:
                status = "SUCCESS" if r.success else "FAILED"
                output = r.error[:60] if r.error else r.output[:60]
                rem_data.append([str(r.script_path), status, output])

            rem_tbl = RLTable(rem_data, repeatRows=1)
            rem_tbl.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), _BRAND_DARK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ])
            )
            elements.append(rem_tbl)

        # ── Footer ──
        elements.append(Spacer(1, 20))
        elements.append(
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"))
        )
        elements.append(
            Paragraph(
                "Report generated by AeroDrift - Cloud Topology &amp; Remediation Graph",
                ParagraphStyle(
                    "Footer",
                    parent=styles["Normal"],
                    fontSize=8,
                    textColor=colors.HexColor("#999999"),
                    spaceBefore=8,
                ),
            )
        )

        doc.build(elements)
        return filepath
