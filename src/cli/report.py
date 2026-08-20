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
        topology,
        remediation_results=None,
        scan_id=None,
    ):
        """Create a full PDF incident report and return the file path."""

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
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
            textColor=colors.HexColor("#1a1a2e"),
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
            textColor=colors.HexColor("#e94560"),
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

        elements.append(
            Paragraph("AeroDrift Incident Report", title_style)
        )

        generated_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        scan_label = f"Scan #{scan_id}" if scan_id else "Ad-hoc"
        elements.append(
            Paragraph(
                f"Generated: {generated_at} &nbsp;|&nbsp; "
                f"Scan: {scan_label}",
                subtitle_style,
            )
        )

        elements.append(
            HRFlowable(
                width="100%", thickness=2,
                color=colors.HexColor("#e94560"),
            )
        )

        elements.append(
            Paragraph("1. Executive Summary", heading_style)
        )

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

        summary = topology.summary()
        elements.append(
            Paragraph(
                f"The topology graph contains <b>{summary['nodes']}</b> "
                f"nodes and <b>{summary['edges']}</b> edges.",
                body_style,
            )
        )

        elements.append(
            Paragraph("2. Drift Findings", heading_style)
        )

        if findings:
            header = [
                "Target",
                "Security Group",
                "Protocol",
                "Port",
                "Source CIDR",
                "Path",
            ]
            table_data = [header]

            for f in findings:
                table_data.append(
                    [
                        f.target,
                        f.security_group,
                        f.protocol,
                        str(f.port),
                        f.source,
                        " -> ".join(f.path),
                    ]
                )

            tbl = RLTable(table_data, repeatRows=1)
            tbl.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#e94560"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.HexColor("#fff5f5"), colors.white],
                        ),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )

            elements.append(tbl)
        else:
            elements.append(
                Paragraph(
                    "No findings to display.",
                    body_style,
                )
            )

        if remediation_results:
            elements.append(
                Paragraph("3. Remediation Actions", heading_style)
            )

            rem_header = ["Script", "Status", "Output"]
            rem_data = [rem_header]

            for r in remediation_results:
                status = "SUCCESS" if r.success else "FAILED"
                output = r.output[:60]
                if r.error:
                    output = r.error[:60]
                rem_data.append(
                    [str(r.script_path), status, output]
                )

            rem_tbl = RLTable(rem_data, repeatRows=1)
            rem_tbl.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#1a1a2e"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "FONTNAME",
                            (0, 0),
                            (-1, 0),
                            "Helvetica-Bold",
                        ),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey,
                        ),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )

            elements.append(rem_tbl)

        elements.append(Spacer(1, 20))
        elements.append(
            HRFlowable(
                width="100%", thickness=1,
                color=colors.HexColor("#cccccc"),
            )
        )
        elements.append(
            Paragraph(
                f"Report generated by AeroDrift - "
                f"Cloud Topology &amp; Remediation Graph",
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
