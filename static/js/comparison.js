(function () {
    "use strict";

    const loadingElement = document.getElementById("comparison-loading");
    const errorElement = document.getElementById("comparison-error");
    const contentElement = document.getElementById("comparison-content");

    if (!loadingElement || !contentElement) {
        return;
    }

    function escapeHtml(value) {
        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatNumber(value) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "0.0";
        }

        return number.toFixed(1);
    }

    function formatDate(value) {
        if (!value) {
            return "-";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return escapeHtml(value);
        }

        return date.toLocaleString();
    }

    function setText(id, value) {
        const element = document.getElementById(id);

        if (element) {
            element.textContent = value;
        }
    }

    function renderEmpty(containerId, message) {
        const container = document.getElementById(containerId);

        if (!container) {
            return;
        }

        container.innerHTML = `
            <div class="empty-state">
                ${escapeHtml(message)}
            </div>
        `;
    }

    function severityBadge(severity) {
        const normalized = String(
            severity || "INFO"
        ).toUpperCase();

        const allowed = [
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ];

        const badgeClass = allowed.includes(normalized)
            ? `badge-${normalized.toLowerCase()}`
            : "badge-info";

        return `
            <span class="badge ${badgeClass}">
                ${escapeHtml(normalized)}
            </span>
        `;
    }

    function renderFindingTable(containerId, findings, emptyMessage) {
        const container = document.getElementById(containerId);

        if (!container) {
            return;
        }

        if (!Array.isArray(findings) || findings.length === 0) {
            renderEmpty(containerId, emptyMessage);
            return;
        }

        const rows = findings.map((finding) => {
            const findingId =
                finding.finding_id ||
                finding.id ||
                "-";

            const title =
                finding.title ||
                finding.name ||
                finding.description ||
                "Finding";

            const severity =
                finding.severity ||
                finding.priority ||
                "INFO";

            const host =
                finding.host ||
                finding.address ||
                "-";

            const port =
                finding.port ||
                "-";

            const service =
                finding.service ||
                finding.product ||
                "-";

            const version =
                finding.version ||
                "-";

            const recommendation =
                finding.recommendation ||
                finding.remediation ||
                "-";

            return `
                <tr>
                    <td>
                        <strong>
                            ${escapeHtml(findingId)}
                        </strong>
                    </td>

                    <td>
                        ${escapeHtml(title)}
                    </td>

                    <td>
                        ${severityBadge(severity)}
                    </td>

                    <td>
                        ${escapeHtml(host)}
                    </td>

                    <td>
                        ${escapeHtml(port)}
                    </td>

                    <td>
                        ${escapeHtml(service)}
                    </td>

                    <td>
                        ${escapeHtml(version)}
                    </td>

                    <td>
                        ${escapeHtml(recommendation)}
                    </td>
                </tr>
            `;
        }).join("");

        container.innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Finding</th>
                            <th>Severity</th>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>

                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderServiceTable(containerId, services, emptyMessage) {
        const container = document.getElementById(containerId);

        if (!container) {
            return;
        }

        if (!Array.isArray(services) || services.length === 0) {
            renderEmpty(containerId, emptyMessage);
            return;
        }

        const rows = services.map((service) => {
            const address =
                service.address ||
                service.host ||
                "-";

            const hostname =
                service.hostname ||
                "-";

            const port =
                service.port ||
                "-";

            const protocol =
                service.protocol ||
                "-";

            const serviceName =
                service.service ||
                service.name ||
                "-";

            const product =
                service.product ||
                "-";

            const version =
                service.version ||
                "-";

            return `
                <tr>
                    <td>
                        ${escapeHtml(address)}
                    </td>

                    <td>
                        ${escapeHtml(hostname)}
                    </td>

                    <td>
                        ${escapeHtml(port)}
                    </td>

                    <td>
                        ${escapeHtml(protocol)}
                    </td>

                    <td>
                        ${escapeHtml(serviceName)}
                    </td>

                    <td>
                        ${escapeHtml(product)}
                    </td>

                    <td>
                        ${escapeHtml(version)}
                    </td>
                </tr>
            `;
        }).join("");

        container.innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Hostname</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                        </tr>
                    </thead>

                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    }

    function applyRiskStatus(status) {
        const normalized = String(
            status || "UNCHANGED"
        ).toUpperCase();

        const statusElement =
            document.getElementById("overall-status");

        const riskStatusElement =
            document.getElementById("risk-status");

        if (statusElement) {
            statusElement.textContent = normalized;
        }

        if (riskStatusElement) {
            riskStatusElement.textContent = normalized;
        }
    }

    function displayComparison(comparison) {
        const previousScan =
            comparison.previous_scan || {};

        const currentScan =
            comparison.current_scan || {};

        const findings =
            comparison.findings || {};

        const services =
            comparison.services || {};

        const risk =
            comparison.risk || {};

        setText(
            "previous-scan",
            `#${previousScan.id || "-"}`
        );

        setText(
            "current-scan",
            `#${currentScan.id || "-"}`
        );

        setText(
            "previous-date",
            formatDate(
                previousScan.completed_at ||
                previousScan.started_at
            )
        );

        setText(
            "current-date",
            formatDate(
                currentScan.completed_at ||
                currentScan.started_at
            )
        );

        const newFindings =
            findings.new || [];

        const resolvedFindings =
            findings.resolved || [];

        const persistentFindings =
            findings.persistent || [];

        const newServices =
            services.new || [];

        const closedServices =
            services.closed || [];

        const newFindingCount =
            findings.new_count ??
            newFindings.length;

        const resolvedFindingCount =
            findings.resolved_count ??
            resolvedFindings.length;

        const persistentFindingCount =
            findings.persistent_count ??
            persistentFindings.length;

        const currentFindingCount =
            findings.current_count ??
            (
                newFindingCount +
                persistentFindingCount
            );

        const newServiceCount =
            services.new_count ??
            newServices.length;

        const closedServiceCount =
            services.closed_count ??
            closedServices.length;

        setText(
            "new-findings-count",
            newFindingCount
        );

        setText(
            "resolved-findings-count",
            resolvedFindingCount
        );

        setText(
            "persistent-findings-count",
            persistentFindingCount
        );

        setText(
            "current-findings-count",
            currentFindingCount
        );

        setText(
            "findings-changed",
            Number(newFindingCount) +
            Number(resolvedFindingCount)
        );

        setText(
            "new-services-count",
            newServiceCount
        );

        setText(
            "closed-services-count",
            closedServiceCount
        );

        const previousRisk =
            Number(
                risk.previous ??
                risk.previous_score ??
                0
            );

        const currentRisk =
            Number(
                risk.current ??
                risk.current_score ??
                0
            );

        const riskChange =
            Number(
                risk.change ??
                risk.risk_change ??
                (
                    currentRisk -
                    previousRisk
                )
            );

        const riskStatus =
            risk.status ||
            comparison.status ||
            "UNCHANGED";

        setText(
            "previous-risk",
            formatNumber(previousRisk)
        );

        setText(
            "current-risk",
            formatNumber(currentRisk)
        );

        const changePrefix =
            riskChange > 0
                ? "+"
                : "";

        setText(
            "risk-change",
            `${changePrefix}${formatNumber(riskChange)}`
        );

        applyRiskStatus(riskStatus);

        renderFindingTable(
            "new-findings-container",
            newFindings,
            "No new findings detected."
        );

        renderFindingTable(
            "resolved-findings-container",
            resolvedFindings,
            "No resolved findings detected."
        );

        renderFindingTable(
            "persistent-findings-container",
            persistentFindings,
            "No persistent findings."
        );

        renderServiceTable(
            "new-services-container",
            newServices,
            "No new services detected."
        );

        renderServiceTable(
            "closed-services-container",
            closedServices,
            "No closed services detected."
        );

        loadingElement.style.display = "none";
        errorElement.style.display = "none";
        contentElement.style.display = "block";
    }

    function showError(message) {
        loadingElement.style.display = "none";
        contentElement.style.display = "none";
        errorElement.style.display = "block";

        errorElement.textContent = message;
    }

    async function loadComparison() {
        try {
            if (
                typeof comparisonScanId === "undefined" ||
                comparisonScanId === null
            ) {
                throw new Error(
                    "Comparison scan ID is missing."
                );
            }

            const response = await fetch(
                `/api/scans/${encodeURIComponent(
                    comparisonScanId
                )}/comparison`,
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );

            let data;

            try {
                data = await response.json();
            } catch (error) {
                throw new Error(
                    "The comparison API returned an invalid response."
                );
            }

            if (!response.ok || !data.success) {
                throw new Error(
                    data.error ||
                    "Unable to load scan comparison."
                );
            }

            if (!data.comparison) {
                throw new Error(
                    "Comparison data was not returned by the API."
                );
            }

            displayComparison(
                data.comparison
            );

        } catch (error) {
            console.error(
                "Historical comparison error:",
                error
            );

            showError(
                error.message ||
                "Unable to load scan comparison."
            );
        }
    }

    loadComparison();

})();
