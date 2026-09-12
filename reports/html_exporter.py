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
        risk = statistics.get("risk") or {}

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>{escape(report_info.get("title", "nvscan Report"))}</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
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
        }}

        .header p {{
            margin: 4px 0;
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
        }}

        th {{
            background: #f1f3f5;
        }}

        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}

        .finding h3 {{
            margin-top: 0;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 9px;
            border-radius: 12px;
            background: #e5e7eb;
            font-size: 12px;
            margin-right: 5px;
        }}

        pre {{
            background: #f4f4f4;
            padding: 15px;
            overflow-x: auto;
            border-radius: 5px;
        }}

        ol {{
            padding-left: 25px;
        }}

        .footer {{
            text-align: center;
            color: #666;
            font-size: 13px;
            margin-top: 30px;
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
            .card {{
                break-inside: avoid;
            }}
        }}

        @media (max-width: 800px) {{
            .grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .container {{
                padding: 20px;
            }}
        }}
    </style>
</head>

<body>

<div class="container">

    <div class="header">
        <h1>{escape(
            report_info.get(
                "title",
                "nvscan Security Assessment Report"
            )
        )}</h1>

        <p>
            <strong>Target:</strong>
            {escape(str(report_info.get("target", "-")))}
        </p>

        <p>
            <strong>Scan ID:</strong>
            {escape(str(report_info.get("scan_id", "-")))}
        </p>

        <p>
            <strong>Status:</strong>
            {escape(str(report_info.get("status", "-")))}
        </p>
    </div>

    <div class="grid">

        <div class="card">
            <div class="stat-label">Hosts</div>
            <div class="stat-value">
                {statistics.get("hosts", 0)}
            </div>
        </div>

        <div class="card">
            <div class="stat-label">Services</div>
            <div class="stat-value">
                {statistics.get("services", 0)}
            </div>
        </div>

        <div class="card">
            <div class="stat-label">Findings</div>
            <div class="stat-value">
                {statistics.get("findings", 0)}
            </div>
        </div>

        <div class="card">
            <div class="stat-label">Maximum Risk</div>
            <div class="stat-value">
                {risk.get("maximum_score", 0)}
            </div>
        </div>

    </div>

    <div class="section">

        <h2>Executive Summary</h2>

        <p>
            {escape(
                executive.get(
                    "summary",
                    "No summary available."
                )
            )}
        </p>

    </div>

    <div class="section">

        <h2>Scan Information</h2>

        <table>

            <tr>
                <th>Target</th>
                <td>
                    {escape(str(report_info.get("target", "-")))}
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

    <div class="section">

        <h2>Severity Summary</h2>

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

    <div class="section">

        <h2>Detected Services</h2>

        <table>

            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
            </tr>

            {
                "".join(
                    f'''
                    <tr>
                        <td>{escape(str(
                            service.get("address", "-")
                        ))}</td>
                        <td>{escape(str(
                            service.get("port", "-")
                        ))}</td>
                        <td>{escape(str(
                            service.get("protocol", "-")
                        ))}</td>
                        <td>{escape(str(
                            service.get("service", "-")
                        ))}</td>
                        <td>{escape(str(
                            service.get("product") or "-"
                        ))}</td>
                        <td>{escape(str(
                            service.get("version") or "-"
                        ))}</td>
                    </tr>
                    '''
                    for service in services
                )
            }

        </table>

    </div>

    <div class="section">

        <h2>Security Findings</h2>

        {
            "".join(
                f'''
                <div class="finding">

                    <h3>
                        {escape(str(
                            finding.get(
                                "finding_id",
                                "-"
                            )
                        ))}
                        -
                        {escape(str(
                            finding.get(
                                "title",
                                "-"
                            )
                        ))}
                    </h3>

                    <p>
                        {escape(str(
                            finding.get(
                                "description",
                                ""
                            )
                        ))}
                    </p>

                    <p>
                        <span class="badge">
                            Severity:
                            {escape(str(
                                finding.get(
                                    "severity",
                                    "-"
                                )
                            ))}
                        </span>

                        <span class="badge">
                            Priority:
                            {escape(str(
                                finding.get(
                                    "priority",
                                    "-"
                                )
                            ))}
                        </span>

                        <span class="badge">
                            Risk:
                            {escape(str(
                                finding.get(
                                    "score",
                                    0
                                )
                            ))}
                        </span>
                    </p>

                    <p>
                        <strong>Host:</strong>
                        {escape(str(
                            finding.get(
                                "host",
                                "-"
                            )
                        ))}
                    </p>

                    <p>
                        <strong>Service:</strong>
                        {escape(str(
                            finding.get(
                                "service",
                                "-"
                            )
                        ))}
                    </p>

                    <p>
                        <strong>Recommendation:</strong>
                        {escape(str(
                            finding.get(
                                "recommendation",
                                "-"
                            )
                        ))}
                    </p>

                    <strong>Evidence:</strong>

                    <pre>{escape(
                        str(
                            finding.get(
                                "evidence",
                                {}
                            )
                        )
                    )}</pre>

                </div>
                '''
                for finding in findings
            )
            if findings
            else '<p>No security findings were generated.</p>'
        }

    </div>

    <div class="section">

        <h2>Recommendations</h2>

        {
            "".join(
                f"<li>{escape(str(item))}</li>"
                for item in recommendations
            )
            if recommendations
            else "<p>No recommendations available.</p>"
        }

        {
            f"<ol>{''.join(f'<li>{escape(str(item))}</li>' for item in recommendations)}</ol>"
            if recommendations
            else ""
        }

    </div>

    <div class="section">

        <h2>Conclusion</h2>

        <p>
            {escape(conclusion)}
        </p>

    </div>

    <div class="footer">
        Generated by nvscan
    </div>

</div>

</body>
</html>
"""


if __name__ == "__main__":
    print("HTMLReportExporter module loaded successfully.")
