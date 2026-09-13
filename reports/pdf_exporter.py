from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReportExporter:
    """Generate a professional PDF security assessment report."""

    def generate(self, report):
        """Generate a PDF byte stream from structured report data."""

        if not report:
            raise ValueError("Report data is required.")

        report_info = report.get("report") or {}
        executive = report.get("executive_summary") or {}
        statistics = report.get("statistics") or {}
        hosts = report.get("hosts") or []
        services = report.get("services") or []
        findings = report.get("findings") or []
        recommendations = report.get("recommendations") or []
        conclusion = report.get("conclusion") or ""

        severity = statistics.get("severity") or {}
        priority = statistics.get("priority") or {}
        risk = statistics.get("risk") or {}

        buffer = BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=str(
                report_info.get(
                    "title",
                    "nvscan Security Assessment Report",
                )
            ),
            author="nvscan",
            subject="Automated Network Security Assessment Report",
        )

        styles = self._build_styles()

        story = []

        # ---------------------------------------------------------
        # Cover / Header
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "NVSCAN",
                styles["CoverTitle"],
            )
        )

        story.append(
            Paragraph(
                "Automated Network Security Assessment",
                styles["CoverSubtitle"],
            )
        )

        story.append(Spacer(1, 10 * mm))

        header_data = [
            [
                Paragraph("<b>Scan ID</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("scan_id")),
                    styles["TableCell"],
                ),
            ],
            [
                Paragraph("<b>Target</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("target")),
                    styles["TableCell"],
                ),
            ],
            [
                Paragraph("<b>Target Type</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("target_type")),
                    styles["TableCell"],
                ),
            ],
            [
                Paragraph("<b>Status</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("status")),
                    styles["TableCell"],
                ),
            ],
            [
                Paragraph("<b>Started</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("started_at")),
                    styles["TableCell"],
                ),
            ],
            [
                Paragraph("<b>Completed</b>", styles["TableCell"]),
                Paragraph(
                    self._safe(report_info.get("completed_at")),
                    styles["TableCell"],
                ),
            ],
        ]

        header_table = Table(
            header_data,
            colWidths=[
                45 * mm,
                130 * mm,
            ],
        )

        header_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#e5e7eb"),
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#cbd5e1"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        story.append(header_table)
        story.append(Spacer(1, 10 * mm))

        story.append(
            Paragraph(
                "Confidential Security Assessment",
                styles["Confidential"],
            )
        )

        story.append(PageBreak())

        # ---------------------------------------------------------
        # Executive Summary
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "1. Executive Summary",
                styles["SectionTitle"],
            )
        )

        story.append(
            Paragraph(
                self._safe(
                    executive.get(
                        "summary",
                        "No executive summary available.",
                    )
                ),
                styles["Body"],
            )
        )

        story.append(Spacer(1, 5 * mm))

        summary_data = [
            [
                "Metric",
                "Value",
            ],
            [
                "Hosts Identified",
                self._safe(executive.get("hosts", 0)),
            ],
            [
                "Services Detected",
                self._safe(executive.get("services", 0)),
            ],
            [
                "Security Findings",
                self._safe(executive.get("findings", 0)),
            ],
            [
                "Average Risk Score",
                self._safe(risk.get("average_score", 0)),
            ],
            [
                "Maximum Risk Score",
                self._safe(risk.get("maximum_score", 0)),
            ],
            [
                "Minimum Risk Score",
                self._safe(risk.get("minimum_score", 0)),
            ],
        ]

        story.append(
            self._make_table(
                summary_data,
                widths=[
                    90 * mm,
                    85 * mm,
                ],
            )
        )

        story.append(Spacer(1, 8 * mm))

        # ---------------------------------------------------------
        # Severity Distribution
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "2. Severity and Risk Summary",
                styles["SectionTitle"],
            )
        )

        severity_data = [
            [
                "Severity",
                "Findings",
            ],
            [
                "Critical",
                self._safe(severity.get("CRITICAL", 0)),
            ],
            [
                "High",
                self._safe(severity.get("HIGH", 0)),
            ],
            [
                "Medium",
                self._safe(severity.get("MEDIUM", 0)),
            ],
            [
                "Low",
                self._safe(severity.get("LOW", 0)),
            ],
            [
                "Informational",
                self._safe(severity.get("INFO", 0)),
            ],
        ]

        story.append(
            self._make_table(
                severity_data,
                widths=[
                    90 * mm,
                    85 * mm,
                ],
            )
        )

        story.append(Spacer(1, 6 * mm))

        priority_data = [
            [
                "Priority",
                "Findings",
            ],
            [
                "Critical",
                self._safe(priority.get("CRITICAL", 0)),
            ],
            [
                "High",
                self._safe(priority.get("HIGH", 0)),
            ],
            [
                "Medium",
                self._safe(priority.get("MEDIUM", 0)),
            ],
            [
                "Low",
                self._safe(priority.get("LOW", 0)),
            ],
            [
                "Informational",
                self._safe(priority.get("INFO", 0)),
            ],
        ]

        story.append(
            self._make_table(
                priority_data,
                widths=[
                    90 * mm,
                    85 * mm,
                ],
            )
        )

        story.append(PageBreak())

        # ---------------------------------------------------------
        # Hosts
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "3. Discovered Hosts",
                styles["SectionTitle"],
            )
        )

        if hosts:
            host_data = [
                [
                    "Address",
                    "Hostname",
                    "State",
                ]
            ]

            for host in hosts:
                host_data.append(
                    [
                        self._safe(
                            host.get("address", "-")
                        ),
                        self._safe(
                            host.get("hostname") or "-"
                        ),
                        self._safe(
                            host.get("state") or "-"
                        ),
                    ]
                )

            story.append(
                self._make_table(
                    host_data,
                    widths=[
                        65 * mm,
                        65 * mm,
                        45 * mm,
                    ],
                )
            )
        else:
            story.append(
                Paragraph(
                    "No hosts were detected.",
                    styles["Body"],
                )
            )

        story.append(Spacer(1, 8 * mm))

        # ---------------------------------------------------------
        # Services
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "4. Detected Services",
                styles["SectionTitle"],
            )
        )

        if services:
            service_data = [
                [
                    "Address",
                    "Port",
                    "Protocol",
                    "Service",
                    "Product",
                    "Version",
                ]
            ]

            for service in services:
                service_data.append(
                    [
                        self._safe(
                            service.get("address", "-")
                        ),
                        self._safe(
                            service.get("port", "-")
                        ),
                        self._safe(
                            service.get("protocol", "-")
                        ),
                        self._safe(
                            service.get("service", "-")
                        ),
                        self._safe(
                            service.get("product") or "-"
                        ),
                        self._safe(
                            service.get("version") or "-"
                        ),
                    ]
                )

            story.append(
                self._make_table(
                    service_data,
                    widths=[
                        35 * mm,
                        18 * mm,
                        23 * mm,
                        28 * mm,
                        38 * mm,
                        33 * mm,
                    ],
                    small=True,
                )
            )
        else:
            story.append(
                Paragraph(
                    "No services were detected.",
                    styles["Body"],
                )
            )

        story.append(PageBreak())

        # ---------------------------------------------------------
        # Security Findings
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "5. Security Findings",
                styles["SectionTitle"],
            )
        )

        if not findings:
            story.append(
                Paragraph(
                    "No security findings were generated.",
                    styles["Body"],
                )
            )
        else:
            for index, finding in enumerate(findings, start=1):
                story.append(
                    self._finding_block(
                        index,
                        finding,
                        styles,
                    )
                )

                story.append(
                    Spacer(
                        1,
                        6 * mm,
                    )
                )

        story.append(PageBreak())

        # ---------------------------------------------------------
        # Recommendations
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "6. Recommendations",
                styles["SectionTitle"],
            )
        )

        if recommendations:
            for index, recommendation in enumerate(
                recommendations,
                start=1,
            ):
                story.append(
                    Paragraph(
                        f"{index}. "
                        f"{self._safe(recommendation)}",
                        styles["Body"],
                    )
                )
                story.append(
                    Spacer(
                        1,
                        2 * mm,
                    )
                )
        else:
            story.append(
                Paragraph(
                    "No recommendations were generated.",
                    styles["Body"],
                )
            )

        story.append(Spacer(1, 8 * mm))

        # ---------------------------------------------------------
        # Conclusion
        # ---------------------------------------------------------

        story.append(
            Paragraph(
                "7. Conclusion",
                styles["SectionTitle"],
            )
        )

        story.append(
            Paragraph(
                self._safe(conclusion),
                styles["Body"],
            )
        )

        story.append(Spacer(1, 12 * mm))

        story.append(
            HRFlowable(
                width="100%",
                thickness=0.7,
                color=colors.HexColor("#cbd5e1"),
            )
        )

        story.append(Spacer(1, 4 * mm))

        story.append(
            Paragraph(
                "Generated automatically by nvscan.",
                styles["Footer"],
            )
        )

        document.build(
            story,
            onFirstPage=self._draw_page,
            onLaterPages=self._draw_page,
        )

        buffer.seek(0)

        return buffer.getvalue()

    def _finding_block(self, index, finding, styles):
        """Build the PDF section for one security finding."""

        finding_id = finding.get(
            "finding_id",
            "-",
        )

        title = finding.get(
            "title",
            "-",
        )

        severity = finding.get(
            "severity",
            "-",
        )

        priority = finding.get(
            "priority",
            "-",
        )

        score = finding.get(
            "score",
            0,
        )

        description = finding.get(
            "description",
            "",
        )

        host = finding.get(
            "host",
            "-",
        )

        port = finding.get(
            "port",
            "-",
        )

        service = finding.get(
            "service",
            "-",
        )

        product = finding.get(
            "product",
            "-",
        )

        version = finding.get(
            "version",
            "-",
        )

        recommendation = finding.get(
            "recommendation",
            "-",
        )

        evidence = finding.get(
            "evidence",
            {},
        )

        remediation = finding.get(
            "remediation",
        )

        elements = []

        elements.append(
            Paragraph(
                f"{index}. {self._safe(finding_id)} - "
                f"{self._safe(title)}",
                styles["FindingTitle"],
            )
        )

        metadata = [
            [
                "Severity",
                self._safe(severity),
                "Priority",
                self._safe(priority),
            ],
            [
                "Risk Score",
                self._safe(score),
                "Host",
                self._safe(host),
            ],
            [
                "Port",
                self._safe(port),
                "Service",
                self._safe(service),
            ],
            [
                "Product",
                self._safe(product),
                "Version",
                self._safe(version),
            ],
        ]

        metadata_table = Table(
            metadata,
            colWidths=[
                28 * mm,
                58 * mm,
                28 * mm,
                61 * mm,
            ],
        )

        metadata_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#cbd5e1"),
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#f1f5f9"),
                    ),
                    (
                        "BACKGROUND",
                        (2, 0),
                        (2, -1),
                        colors.HexColor("#f1f5f9"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, -1),
                        "Helvetica",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        elements.append(metadata_table)
        elements.append(Spacer(1, 4 * mm))

        elements.append(
            Paragraph(
                "<b>Description</b>",
                styles["Subheading"],
            )
        )

        elements.append(
            Paragraph(
                self._safe(description),
                styles["BodySmall"],
            )
        )

        elements.append(Spacer(1, 2 * mm))

        elements.append(
            Paragraph(
                "<b>Evidence</b>",
                styles["Subheading"],
            )
        )

        elements.append(
            Paragraph(
                self._safe(evidence),
                styles["CodeBlock"],
            )
        )

        elements.append(Spacer(1, 2 * mm))

        elements.append(
            Paragraph(
                "<b>Recommended Action</b>",
                styles["Subheading"],
            )
        )

        elements.append(
            Paragraph(
                self._safe(recommendation),
                styles["BodySmall"],
            )
        )

        if remediation:
            action = remediation.get(
                "action"
            )

            steps = remediation.get(
                "steps"
            ) or []

            verification = remediation.get(
                "verification"
            ) or []

            elements.append(Spacer(1, 2 * mm))

            elements.append(
                Paragraph(
                    "<b>Remediation Action</b>",
                    styles["Subheading"],
                )
            )

            elements.append(
                Paragraph(
                    self._safe(
                        action,
                        "-"
                    ),
                    styles["BodySmall"],
                )
            )

            if steps:
                elements.append(
                    Paragraph(
                        "<b>Remediation Steps</b>",
                        styles["Subheading"],
                    )
                )

                for step_number, step in enumerate(
                    steps,
                    start=1,
                ):
                    elements.append(
                        Paragraph(
                            f"{step_number}. "
                            f"{self._safe(step)}",
                            styles["BodySmall"],
                        )
                    )

            if verification:
                elements.append(
                    Paragraph(
                        "<b>Verification Steps</b>",
                        styles["Subheading"],
                    )
                )

                for step_number, step in enumerate(
                    verification,
                    start=1,
                ):
                    elements.append(
                        Paragraph(
                            f"{step_number}. "
                            f"{self._safe(step)}",
                            styles["BodySmall"],
                        )
                    )

        return KeepTogether(elements)

    def _make_table(
        self,
        data,
        widths,
        small=False,
    ):
        """Create a consistently styled report table."""

        table = Table(
            data,
            colWidths=widths,
            repeatRows=1,
        )

        font_size = 7 if small else 9

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1f2937"),
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
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        font_size,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#cbd5e1"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [
                            colors.white,
                            colors.HexColor("#f8fafc"),
                        ],
                    ),
                ]
            )
        )

        return table

    def _build_styles(self):
        """Build ReportLab paragraph styles."""

        base = getSampleStyleSheet()

        return {
            "CoverTitle": ParagraphStyle(
                "CoverTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=28,
                leading=32,
                alignment=TA_CENTER,
                spaceAfter=5 * mm,
                textColor=colors.HexColor("#111827"),
            ),
            "CoverSubtitle": ParagraphStyle(
                "CoverSubtitle",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=14,
                leading=18,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#475569"),
            ),
            "SectionTitle": ParagraphStyle(
                "SectionTitle",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=16,
                leading=20,
                spaceBefore=4 * mm,
                spaceAfter=5 * mm,
                textColor=colors.HexColor("#111827"),
            ),
            "FindingTitle": ParagraphStyle(
                "FindingTitle",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                spaceAfter=3 * mm,
                textColor=colors.HexColor("#111827"),
            ),
            "Subheading": ParagraphStyle(
                "Subheading",
                parent=base["Heading3"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                spaceBefore=2 * mm,
                spaceAfter=1 * mm,
                textColor=colors.HexColor("#334155"),
            ),
            "Body": ParagraphStyle(
                "Body",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                alignment=TA_LEFT,
                spaceAfter=3 * mm,
                textColor=colors.HexColor("#1f2937"),
            ),
            "BodySmall": ParagraphStyle(
                "BodySmall",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                alignment=TA_LEFT,
                spaceAfter=2 * mm,
                textColor=colors.HexColor("#1f2937"),
            ),
            "TableCell": ParagraphStyle(
                "TableCell",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8,
                leading=10,
            ),
            "CodeBlock": ParagraphStyle(
                "CodeBlock",
                parent=base["Code"],
                fontName="Courier",
                fontSize=7,
                leading=9,
                leftIndent=4,
                rightIndent=4,
                spaceBefore=1 * mm,
                spaceAfter=2 * mm,
                backColor=colors.HexColor("#f1f5f9"),
            ),
            "Confidential": ParagraphStyle(
                "Confidential",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#64748b"),
            ),
            "Footer": ParagraphStyle(
                "Footer",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7,
                leading=9,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#64748b"),
            ),
        }

    def _safe(self, value, default="-"):
        """Convert arbitrary values into PDF-safe text."""

        if value is None:
            return default

        if isinstance(value, (dict, list, tuple)):
            value = str(value)

        value = str(value)

        if not value.strip():
            return default

        # ReportLab Paragraph uses XML-like markup.
        value = (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        value = value.replace("\n", "<br/>")

        return value

    def _draw_page(self, canvas, document):
        """Draw page number and report footer."""

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.setFillColor(
            colors.HexColor("#64748b")
        )

        canvas.drawString(
            15 * mm,
            9 * mm,
            "nvscan Security Assessment",
        )

        canvas.drawRightString(
            A4[0] - 15 * mm,
            9 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()


if __name__ == "__main__":
    print(
        "PDFReportExporter module loaded successfully."
    )
