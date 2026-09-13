from html import escape


class HTMLReportExporter:
    """Generate a standalone HTML security assessment report."""

    def generate(self, report):
        """Convert a structured report into standalone HTML."""

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

        # ---------------------------------------------------------
        # Detected services
        # ---------------------------------------------------------

        services_html = ""

        if services:
            services_html = "".join(
                f"""
                <tr>
                    <td>{escape(str(service.get("address", "-")))}</td>
                    <td>{escape(str(service.get("port", "-")))}</td>
                    <td>{escape(str(service.get("protocol", "-")))}</td>
                    <td>{escape(str(service.get("service", "-")))}</td>
                    <td>{escape(str(service.get("product") or "-"))}</td>
                    <td>{escape(str(service.get("version") or "-"))}</td>
                </tr>
                """
                for service in services
            )
        else:
            services_html = """
                <tr>
                    <td colspan="6">No services were detected.</td>
                </tr>
            """

        # ---------------------------------------------------------
        # Security findings
        # ---------------------------------------------------------

        findings_html = ""

        if findings:
            findings_html = "".join(
                f"""
                <div class="finding">

                    <h3>
                        {escape(
                            str(
                                finding.get(
                                    "finding_id",
                                    "-"
                                )
                            )
                        )}
                        -
                        {escape(
                            str(
                                finding.get(
                                    "title",
                                    "-"
                                )
                            )
                        )}
                    </h3>

                    <p>
                        {escape(
                            str(
                                finding.get(
                                    "description",
                                    ""
                                )
                            )
                        )}
                    </p>

                    <div class="badges">

                        <span class="badge">
                            Severity:
                            {escape(
                                str(
                                    finding.get(
                                        "severity",
                                        "-"
                                    )
                                )
                            )}
                        </span>

                        <span class="badge">
                            Priority:
                            {escape(
                                str(
                                    finding.get(
                                        "priority",
                                        "-"
                                    )
                                )
                            )}
                        </span>

                        <span class="badge">
                            Risk:
                            {escape(
                                str(
                                    finding.get(
                                        "score",
                                        0
                                    )
                                )
                            )}
                        </span>

                    </div>

                    <p>
                        <strong>Host:</strong>
                        {escape(
                            str(
                                finding.get(
                                    "host",
                                    "-"
                                )
                            )
                        )}
                    </p>

                    <p>
                        <strong>Service:</strong>
                        {escape(
                            str(
                                finding.get(
                                    "service",
                                    "-"
                                )
                            )
                        )}
                    </p>

                    <p>
                        <strong>Recommendation:</strong>
                        {escape(
                            str(
                                finding.get(
                                    "recommendation",
                                    "-"
                                )
                            )
                        )}
                    </p>

                    <p>
                        <strong>Evidence:</strong>
                    </p>

                    <pre>{escape(
                        str(
                            finding.get(
                                "evidence",
                                {}
                            )
                        )
                    )}</pre>

                </div>
                """
                for finding in findings
            )
        else:
            findings_html = """
                <p>No security findings were generated.</p>
            """

        # ---------------------------------------------------------
        # Recommendations
        # ---------------------------------------------------------

        recommendations_html = ""

        if recommendations:
            recommendations_html = f"""
                <ol>
                    {
                        "".join(
                            f"<li>{escape(str(item))}</li>"
                            for item in recommendations
                        )
                    }
                </ol>
            """
        else:
            recommendations_html = """
                <p>No recommendations available.</p>
            """

        # ---------------------------------------------------------
        # Hosts
        # ---------------------------------------------------------

        hosts_html = ""

        if hosts:
            hosts_html = "".join(
                f"""
                <tr>
                    <td>{escape(str(host.get("address", "-")))}</td>
                    <td>{escape(str(host.get("hostname") or "-"))}</td>
                    <td>{escape(str(host.get("state") or "-"))}</td>
                </tr>
                """
                for host in hosts
            )
        else:
            hosts_html = """
                <tr>
                    <td colspan="3">No hosts were detected.</td>
                </tr>
            """

        # ---------------------------------------------------------
        # Generate standalone HTML report
        # ---------------------------------------------------------

        return f"""<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <meta
        name="description"
        content="nvscan automated network security assessment report"
    >

    <title>
        {escape(
            str(
                report_info.get(
                    "title",
                    "nvscan Security Assessment Report"
                )
            )
        )}
    </title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family:
                Arial,
                Helvetica,
                sans-serif;
            background: #f4f6f8;
            color: #222;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }}

        .header {{
            background: #1f2937;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 25px;
        }}

        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 30px;
        }}

        .header p {{
            margin: 5px 0;
        }}

        .grid {{
            display: grid;
            grid-template-columns:
                repeat(4, minmax(0, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}

        .card {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
        }}

        .stat-label {{
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
        }}

        .stat-value {{
            font-size: 30px;
            font-weight: bold;
        }}

        .section {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }}

        .section h2 {{
            margin-top: 0;
            margin-bottom: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }}

        th {{
            background: #f1f3f5;
            font-weight: bold;
        }}

        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}

        .finding:last-child {{
            margin-bottom: 0;
        }}

        .finding h3 {{
            margin-top: 0;
            line-height: 1.4;
        }}

        .badges {{
            margin: 15px 0;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 12px;
            background: #e5e7eb;
            font-size: 12px;
            margin-right: 5px;
            margin-bottom: 5px;
        }}

        pre {{
            background: #f4f4f4;
            padding: 15px;
            overflow-x: auto;
            border-radius: 5px;
            white-space: pre-wrap;
            word-break: break-word;
        }}

        ol {{
            padding-left: 25px;
        }}

        li {{
            margin-bottom: 8px;
        }}

        .footer {{
            text-align: center;
            color: #666;
            font-size: 13px;
            margin-top: 30px;
            padding-bottom: 20px;
        }}

        .empty {{
            color: #666;
            font-style: italic;
        }}

        @media print {{

            body {{
                background: white;
            }}

            .container {{
                max-width: none;
                padding: 20px;
            }}

            .section,
            .card,
            .finding {{
                break-inside: avoid;
            }}

            .header {{
                color: black;
                background: white;
                border: 1px solid #ddd;
            }}

        }}

        @media (max-width: 800px) {{

            .grid {{
                grid-template-columns:
                    repeat(2, 1fr);
            }}

            .container {{
                padding: 20px;
            }}

            table {{
                display: block;
                overflow-x: auto;
            }}

        }}

        @media (max-width: 500px) {{

            .grid {{
                grid-template-columns: 1fr;
            }}

            .container {{
                padding: 10px;
            }}

            .section {{
                padding: 15px;
            }}

        }}

    </style>

</head>

<body>

<div class="container">

    <!-- =====================================================
         REPORT HEADER
         ===================================================== -->

    <div class="header">

        <h1>
            {escape(
                str(
                    report_info.get(
                        "title",
                        "nvscan Security Assessment Report"
                    )
                )
            )}
        </h1>

        <p>
            <strong>Target:</strong>
            {escape(
                str(
                    report_info.get(
                        "target",
                        "-"
                    )
                )
            )}
        </p>

        <p>
            <strong>Scan ID:</strong>
            {escape(
                str(
                    report_info.get(
                        "scan_id",
                        "-"
                    )
                )
            )}
        </p>

        <p>
            <strong>Status:</strong>
            {escape(
                str(
                    report_info.get(
                        "status",
                        "-"
                    )
                )
            )}
        </p>

    </div>


    <!-- =====================================================
         STATISTICS
         ===================================================== -->

    <div class="grid">

        <div class="card">

            <div class="stat-label">
                Hosts
            </div>

            <div class="stat-value">
                {statistics.get("hosts", 0)}
            </div>

        </div>


        <div class="card">

            <div class="stat-label">
                Services
            </div>

            <div class="stat-value">
                {statistics.get("services", 0)}
            </div>

        </div>


        <div class="card">

            <div class="stat-label">
                Findings
            </div>

            <div class="stat-value">
                {statistics.get("findings", 0)}
            </div>

        </div>


        <div class="card">

            <div class="stat-label">
                Maximum Risk
            </div>

            <div class="stat-value">
                {risk.get("maximum_score", 0)}
            </div>

        </div>

    </div>


    <!-- =====================================================
         EXECUTIVE SUMMARY
         ===================================================== -->

    <div class="section">

        <h2>
            Executive Summary
        </h2>

        <p>
            {escape(
                str(
                    executive.get(
                        "summary",
                        "No summary available."
                    )
                )
            )}
        </p>

    </div>


    <!-- =====================================================
         SCAN INFORMATION
         ===================================================== -->

    <div class="section">

        <h2>
            Scan Information
        </h2>

        <table>

            <tr>
                <th>Target</th>
                <td>
                    {escape(
                        str(
                            report_info.get(
                                "target",
                                "-"
                            )
                        )
                    )}
                </td>
            </tr>

            <tr>
                <th>Target Type</th>
                <td>
                    {escape(
                        str(
                            report_info.get(
                                "target_type",
                                "-"
                            )
                        )
                    )}
                </td>
            </tr>

            <tr>
                <th>Started</th>
                <td>
                    {escape(
                        str(
                            report_info.get(
                                "started_at",
                                "-"
                            )
                        )
                    )}
                </td>
            </tr>

            <tr>
                <th>Completed</th>
                <td>
                    {escape(
                        str(
                            report_info.get(
                                "completed_at",
                                "-"
                            )
                        )
                    )}
                </td>
            </tr>

        </table>

    </div>


    <!-- =====================================================
         HOSTS
         ===================================================== -->

    <div class="section">

        <h2>
            Discovered Hosts
        </h2>

        <table>

            <tr>
                <th>Address</th>
                <th>Hostname</th>
                <th>State</th>
            </tr>

            {hosts_html}

        </table>

    </div>


    <!-- =====================================================
         SEVERITY SUMMARY
         ===================================================== -->

    <div class="section">

        <h2>
            Severity Summary
        </h2>

        <table>

            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>

            <tr>
                <td>CRITICAL</td>
                <td>{severity.get("CRITICAL", 0)}</td>
            </tr>

            <tr>
                <td>HIGH</td>
                <td>{severity.get("HIGH", 0)}</td>
            </tr>

            <tr>
                <td>MEDIUM</td>
                <td>{severity.get("MEDIUM", 0)}</td>
            </tr>

            <tr>
                <td>LOW</td>
                <td>{severity.get("LOW", 0)}</td>
            </tr>

            <tr>
                <td>INFO</td>
                <td>{severity.get("INFO", 0)}</td>
            </tr>

        </table>

    </div>


    <!-- =====================================================
         PRIORITY SUMMARY
         ===================================================== -->

    <div class="section">

        <h2>
            Risk Priority Summary
        </h2>

        <table>

            <tr>
                <th>Priority</th>
                <th>Count</th>
            </tr>

            <tr>
                <td>CRITICAL</td>
                <td>{priority.get("CRITICAL", 0)}</td>
            </tr>

            <tr>
                <td>HIGH</td>
                <td>{priority.get("HIGH", 0)}</td>
            </tr>

            <tr>
                <td>MEDIUM</td>
                <td>{priority.get("MEDIUM", 0)}</td>
            </tr>

            <tr>
                <td>LOW</td>
                <td>{priority.get("LOW", 0)}</td>
            </tr>

            <tr>
                <td>INFO</td>
                <td>{priority.get("INFO", 0)}</td>
            </tr>

        </table>

    </div>


    <!-- =====================================================
         RISK SUMMARY
         ===================================================== -->

    <div class="section">

        <h2>
            Risk Summary
        </h2>

        <table>

            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>

            <tr>
                <td>Average Risk Score</td>
                <td>
                    {risk.get("average_score", 0)}
                </td>
            </tr>

            <tr>
                <td>Maximum Risk Score</td>
                <td>
                    {risk.get("maximum_score", 0)}
                </td>
            </tr>

            <tr>
                <td>Minimum Risk Score</td>
                <td>
                    {risk.get("minimum_score", 0)}
                </td>
            </tr>

        </table>

    </div>


    <!-- =====================================================
         DETECTED SERVICES
         ===================================================== -->

    <div class="section">

        <h2>
            Detected Services
        </h2>

        <table>

            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
            </tr>

            {services_html}

        </table>

    </div>


    <!-- =====================================================
         SECURITY FINDINGS
         ===================================================== -->

    <div class="section">

        <h2>
            Security Findings
        </h2>

        {findings_html}

    </div>


    <!-- =====================================================
         RECOMMENDATIONS
         ===================================================== -->

    <div class="section">

        <h2>
            Recommendations
        </h2>

        {recommendations_html}

    </div>


    <!-- =====================================================
         CONCLUSION
         ===================================================== -->

    <div class="section">

        <h2>
            Conclusion
        </h2>

        <p>
            {escape(str(conclusion))}
        </p>

    </div>


    <!-- =====================================================
         FOOTER
         ===================================================== -->

    <div class="footer">

        Generated by nvscan

    </div>

</div>

</body>

</html>
"""

    def export(self, report):
        """Compatibility wrapper for callers using the export() method."""
        return self.generate(report)


if __name__ == "__main__":
    print(
        "HTMLReportExporter module loaded successfully."
    )


