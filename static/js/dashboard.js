"use strict";


async function loadDashboard() {
    const totalTargets =
        document.getElementById(
            "total-targets"
        );

    const totalScans =
        document.getElementById(
            "total-scans"
        );

    const totalFindings =
        document.getElementById(
            "total-findings"
        );

    const highRisk =
        document.getElementById(
            "high-risk"
        );

    const recentScans =
        document.getElementById(
            "recent-scans"
        );

    try {

        const response = await fetch(
            "/api/dashboard"
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(
                data.error ||
                "Failed to load dashboard data."
            );
        }

        totalTargets.textContent =
            data.summary.targets;

        totalScans.textContent =
            data.summary.scans;

        totalFindings.textContent =
            data.summary.findings;

        highRisk.textContent =
            data.summary.high_risk;

        renderRecentScans(
            recentScans,
            data.recent_scans
        );

    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

        recentScans.textContent =
            "Unable to load dashboard data.";
    }
}


function renderRecentScans(
    container,
    scans
) {

    if (!scans || scans.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                No scans have been recorded yet.
            </div>
        `;

        return;
    }

    const rows = scans.map(
        (scan) => {

            const statusClass =
                scan.status === "completed"
                    ? "badge-low"
                    : "badge-info";

            return `
                <tr>
                    <td>
                        #${scan.id}
                    </td>

                    <td>
                        ${escapeHtml(
                            scan.target
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            scan.target_type
                        )}
                    </td>

                    <td>
                        <span
                            class="badge ${statusClass}"
                        >
                            ${escapeHtml(
                                scan.status
                            )}
                        </span>
                    </td>

                    <td>
                        ${escapeHtml(
                            scan.started_at
                        )}
                    </td>

                    <td>
                        <a
                            class="button button-primary"
                            href="/api/scans/${scan.id}"
                            target="_blank"
                        >
                            View
                        </a>
                    </td>
                </tr>
            `;
        }
    ).join("");

    container.innerHTML = `
        <div class="table-container">

            <table class="data-table">

                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Target</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Results</th>
                    </tr>
                </thead>

                <tbody>
                    ${rows}
                </tbody>

            </table>

        </div>
    `;
}


function escapeHtml(value) {

    if (value === null ||
        value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


document.addEventListener(
    "DOMContentLoaded",
    loadDashboard
);
