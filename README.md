# IntelliScan

## Automated Network Vulnerability Assessment, Risk Prioritization and Remediation Platform

IntelliScan is an automated cybersecurity assessment platform developed as a final-year cybersecurity project.

The platform combines network discovery, service detection, web security checks, vulnerability detection, risk prioritization, CVE correlation, remediation generation, historical scan comparison, authentication, and HTML/PDF reporting into a single web-based application.

IntelliScan is designed for authorized cybersecurity laboratories, academic demonstrations, penetration-testing environments, and systems for which explicit testing permission has been obtained.

---

# 1. Project Overview

Traditional vulnerability assessment often requires security professionals to manually perform several activities:

1. Identify live hosts.
2. Discover open ports.
3. Identify services and versions.
4. Analyze security weaknesses.
5. Determine the severity of findings.
6. Prioritize risks.
7. Research possible vulnerabilities.
8. Prepare remediation instructions.
9. Compare results with previous assessments.
10. Prepare security reports.

IntelliScan automates these activities through a centralized assessment workflow.

The system uses Nmap for network discovery and service detection, a rule-based vulnerability detection engine for security findings, a risk engine for prioritization, a local CVE correlation engine, a remediation engine, a historical comparison engine, and reporting modules.

---

# 2. Project Objectives

The main objectives of IntelliScan are:

- Automate network host discovery.
- Identify open ports and exposed services.
- Detect service and product information.
- Perform basic web security analysis.
- Normalize scanner output.
- Detect security weaknesses using predefined rules.
- Assign severity levels to findings.
- Calculate risk scores.
- Prioritize findings.
- Correlate detected products with a local CVE database.
- Generate remediation recommendations.
- Generate verification steps.
- Store scan history.
- Compare previous and current scans.
- Generate HTML security reports.
- Generate PDF security reports.
- Provide a browser-based security dashboard.
- Protect application access using authentication.
- Provide a practical cybersecurity assessment workflow suitable for academic demonstration.

---

# 3. Main Features

## 3.1 Target Management

Users can manage assessment targets through the web interface.

Targets can represent:

- IP addresses
- Hostnames
- Authorized laboratory systems
- Network assessment targets

Target validation is performed before scanning.

---

## 3.2 Network Discovery

IntelliScan uses Nmap to discover reachable systems and exposed network services.

The scanner can identify:

- Live hosts
- Open ports
- Protocols
- Services
- Product names
- Service versions

---

## 3.3 Port and Service Detection

After discovering hosts, IntelliScan analyzes available network services.

Examples include:

- SSH
- HTTP
- HTTPS
- FTP
- RPC
- NFS
- Other TCP services discovered by Nmap

The raw scanner output is converted into normalized internal data.

---

# 4. Web Security Scanning

For web services, IntelliScan performs additional HTTP-based security checks.

The web scanner can identify issues such as:

- Missing HSTS
- Missing Content-Security-Policy
- Missing clickjacking protection
- Missing MIME sniffing protection
- Missing Referrer-Policy
- Web server information disclosure

The web scanning layer works together with the network scanning pipeline.

---

# 5. Vulnerability Detection Engine

The vulnerability detection engine analyzes normalized scan results and applies predefined security detection rules.

Examples of detected conditions include:

- FTP exposure
- RPC exposure
- NFS exposure
- Security header weaknesses
- Web server information disclosure
- Other rule-defined service or web weaknesses

Each finding contains security-related information such as:

- Finding ID
- Title
- Description
- Severity
- Evidence
- Recommendation
- Related service information

---

# 6. Risk Prioritization

IntelliScan converts security findings into numerical risk scores.

The current severity mapping is:

| Severity | Base Score |
|---|---:|
| INFO | 0 |
| LOW | 25 |
| MEDIUM | 50 |
| HIGH | 75 |
| CRITICAL | 100 |

Risk scoring also considers exposure characteristics.

The resulting score is converted into a priority that helps security teams determine which findings should be addressed first.

---

# 7. CVE Correlation

IntelliScan includes a local CVE correlation engine.

The correlation process compares detected:

- Product
- Service
- Version

against locally stored vulnerability information.

The system only reports a CVE when the matching conditions are satisfied.

This prevents unrelated CVEs from being incorrectly attached to detected software versions.

The current demonstration database contains selected CVE information rather than a complete continuously updated vulnerability feed.

---

# 8. Remediation Engine

The remediation engine converts security findings into actionable recommendations.

For supported findings, IntelliScan generates:

- Recommended action
- Remediation steps
- Verification steps
- Priority
- Related vulnerability information when applicable

The remediation information is stored with the assessment results and can be displayed through the application.

All remediation instructions should be reviewed by an administrator before being applied to production systems.

---

# 9. Historical Scan Comparison

IntelliScan can compare completed scans.

The comparison engine identifies:

- New findings
- Resolved findings
- Persistent findings
- New services
- Closed services
- Previous risk score
- Current risk score
- Risk-score change
- Overall security posture status

Possible comparison states include:

- IMPROVED
- STABLE
- REGRESSED

This allows security teams to track whether the security posture is improving or deteriorating over time.

---

# 10. Reporting

IntelliScan supports:

## HTML Reports

HTML reports provide browser-readable security assessment information.

Reports can contain:

- Scan information
- Target information
- Host information
- Services
- Findings
- Severity
- Risk scores
- Priority
- Evidence
- Recommendations
- Remediation steps
- Verification steps
- CVE information
- Conclusions

## PDF Reports

PDF reports are generated using ReportLab.

The PDF output is suitable for:

- Academic submission
- Security assessment documentation
- Demonstration
- Management review
- Archival purposes

---

# 11. Authentication

IntelliScan includes session-based authentication.

The authentication system provides:

- Login
- Logout
- Protected application pages
- Protected application APIs
- Active-user validation
- Secure password hashing

Passwords are not stored as plaintext.

Werkzeug password hashing is used for password verification.

The health endpoint remains available for application health checking.

---

# 12. System Architecture

The overall IntelliScan workflow is:

    Web Browser
         |
         v
    Flask Web Application
         |
         +--------------------+
         |                    |
         v                    v
    Target Management     Authentication
         |
         v
    Scan Controller
         |
         v
    Nmap Scanner
         |
         +-----------------------+
         |                       |
         v                       v
    Host Discovery        Service Detection
         |                       |
         +-----------+-----------+
                     |
                     v
              Result Normalizer
                     |
                     v
              Web Security Scanner
                     |
                     v
               Finding Engine
                     |
          +----------+----------+
          |          |           |
          v          v           v
      Risk Engine  CVE Engine  Database
          |          |
          +----------+
               |
               v
        Remediation Engine
               |
               v
          SQLite Database
               |
       +-------+--------+
       |                |
       v                v
    Dashboard       Reporting
                    |
                +---+---+
                |       |
                v       v
               HTML    PDF

---

# 13. Detailed Assessment Workflow

The complete processing sequence is:

    1. User Login
          |
          v
    2. Target Creation
          |
          v
    3. Target Validation
          |
          v
    4. Start Scan
          |
          v
    5. Host Discovery
          |
          v
    6. Port Scanning
          |
          v
    7. Service Detection
          |
          v
    8. Result Normalization
          |
          v
    9. Web Security Checks
          |
          v
    10. Finding Detection
          |
          v
    11. Risk Scoring
          |
          v
    12. CVE Correlation
          |
          v
    13. Remediation Generation
          |
          v
    14. Database Storage
          |
          v
    15. Dashboard / Results
          |
          v
    16. Historical Comparison
          |
          v
    17. HTML / PDF Reporting

---

# 14. Technology Stack

## Operating System

- Red Hat Enterprise Linux 10

## Programming Language

- Python 3

## Web Framework

- Flask

## Database

- SQLite

## Network Scanner

- Nmap

## PDF Generator

- ReportLab

## Authentication

- Flask session
- Werkzeug password hashing

## Frontend

- HTML
- CSS
- JavaScript
- Jinja2 templates

## Testing

- Pytest

## Version Control

- Git

---

# 15. Project Structure

    nvscan/
    |
    +-- app.py
    +-- auth.py
    +-- config.py
    +-- requirements.txt
    +-- README.md
    +-- .gitignore
    |
    +-- api/
    |   +-- __init__.py
    |
    +-- database/
    |   +-- __init__.py
    |   +-- database.py
    |   +-- schema.sql
    |
    +-- scanner/
    |   +-- __init__.py
    |   +-- comparison_engine.py
    |   +-- detection_rules.py
    |   +-- discovery.py
    |   +-- finding_engine.py
    |   +-- nmap_engine.py
    |   +-- normalizer.py
    |   +-- parser.py
    |   +-- port_scanner.py
    |   +-- service_detection.py
    |   +-- target_validator.py
    |
    +-- web_scanner/
    |   +-- __init__.py
    |   +-- directory_enum.py
    |   +-- http_scanner.py
    |
    +-- vulnerability_engine/
    |   +-- __init__.py
    |   +-- correlator.py
    |   +-- cve_database.py
    |
    +-- risk_engine/
    |   +-- __init__.py
    |   +-- scorer.py
    |
    +-- remediation_engine/
    |   +-- __init__.py
    |   +-- engine.py
    |
    +-- reports/
    |   +-- __init__.py
    |   +-- html_exporter.py
    |   +-- pdf_exporter.py
    |   +-- report_generator.py
    |
    +-- templates/
    |   +-- base.html
    |   +-- login.html
    |   +-- dashboard.html
    |   +-- targets.html
    |   +-- scan_history.html
    |   +-- scan_results.html
    |   +-- comparison.html
    |   +-- report.html
    |   +-- results.html
    |
    +-- static/
    |
    +-- tests/
    |   +-- test_intelliscan.py

---

# 16. Installation

## 16.1 System Requirements

The system requires:

- Red Hat Enterprise Linux 10
- Python 3
- Python virtual environment support
- Nmap
- Git

Verify Python:

    python3 --version

Verify Nmap:

    nmap --version

Verify Git:

    git --version

---

# 17. Create Python Virtual Environment

Move into the project directory:

    cd /opt/nvscan

Create the virtual environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

---

# 18. Install Python Dependencies

Install the project dependencies:

    pip install -r requirements.txt

Verify Flask:

    python3 -c "import flask; print(flask.__version__)"

Verify ReportLab:

    python3 -c "import reportlab; print(reportlab.Version)"

Verify Pytest:

    pytest --version

---

# 19. Nmap Requirement

Nmap is a system-level dependency and is not installed through the Python requirements file.

Verify Nmap:

    nmap --version

If Nmap is not installed, install it through the configured RHEL repository.

---

# 20. Database

IntelliScan uses SQLite.

The database stores information about:

- Users
- Targets
- Scans
- Hosts
- Services
- Findings
- Risk scores
- Remediation information

The application/database layer initializes and maintains the required database structures.

For source-code distribution, the runtime SQLite database should normally not be committed to Git because it contains generated assessment data and authentication information.

---

# 21. Running the Application

Activate the virtual environment:

    cd /opt/nvscan
    source .venv/bin/activate

Start IntelliScan:

    python3 app.py

The Flask application runs on:

    http://127.0.0.1:5000

From another system that can reach the RHEL VM:

    http://<VM-IP>:5000

---

# 22. Application Pages

The web interface provides:

- Login
- Dashboard
- Targets
- Scan History
- Scan Results
- Historical Comparison
- Reports

The dashboard provides an overview of the assessment environment.

---

# 23. API Functionality

The application provides API endpoints for operations including:

- Health checking
- Dashboard data
- Target management
- Scan management
- Scan results
- Remediation
- HTML report generation
- PDF report generation
- Structured report data

The majority of application APIs require authentication.

The health endpoint is available for health checking.

---

# 24. Testing

The project contains automated tests using Pytest.

Run the test suite:

    pytest -q

Expected successful result:

    18 passed

Additional validation performed during development included:

- Python compilation
- Authentication testing
- Dashboard access testing
- Scan API testing
- Real network scan testing
- Finding detection
- Risk scoring
- CVE correlation
- Remediation generation
- Historical comparison
- HTML reporting
- PDF reporting

---

# 25. Demonstration Scan

A real project scan was completed during development.

Example Scan #11 produced:

    Live hosts:            1
    Normalized results:   14
    Security findings:     9
    CVE matches:           0
    Risk scores:           9
    Remediation actions:   9

Detected findings included:

    WEB-009  Missing HSTS security header
    WEB-010  Missing Content-Security-Policy header
    WEB-011  Missing clickjacking protection header
    WEB-012  Missing MIME sniffing protection header
    WEB-013  Missing Referrer-Policy header
    WEB-014  Web server information disclosed
    NET-002  FTP service exposed
    NET-006  RPC service exposed
    NET-007  NFS service exposed

The Apache version detected during the demonstration was 2.4.63.

The local CVE database contained older Apache vulnerability records, therefore the system correctly produced zero CVE matches for the detected Apache version rather than incorrectly reporting an unrelated CVE.

---

# 26. Risk Result Example

The demonstration findings produced risk scores such as:

    Missing HSTS security header
    Risk Score: 50.0
    Priority: MEDIUM

    Missing Content-Security-Policy header
    Risk Score: 50.0
    Priority: MEDIUM

    Missing clickjacking protection header
    Risk Score: 25.0
    Priority: LOW

    FTP service exposed
    Risk Score: 55.0
    Priority: MEDIUM

    RPC service exposed
    Risk Score: 55.0
    Priority: MEDIUM

    NFS service exposed
    Risk Score: 57.5
    Priority: MEDIUM

---

# 27. Historical Comparison Example

An example comparison between Scan #8 and Scan #9 produced:

    Previous Scan:       #8
    Current Scan:        #9

    New Findings:         0
    Resolved Findings:    0
    Persistent Findings: 10

    New Services:         0
    Closed Services:      0

    Previous Risk:       50.0
    Current Risk:        57.5

    Risk Change:         +7.5
    Status:              REGRESSED

The comparison functionality allows security posture changes to be tracked across multiple assessments.

---

# 28. Security Design

Important security design elements include:

- Password hashing
- Session-based authentication
- HTTP-only session cookies
- SameSite session-cookie configuration
- Target validation
- Authentication-protected application pages
- Authentication-protected assessment APIs
- Separation of scanning, analysis, risk, remediation, and reporting modules

The application should use a strong secret key in a real deployment.

---

# 29. Responsible Use

IntelliScan is intended for authorized security assessment.

Only scan:

- Systems owned by the tester
- Cybersecurity laboratory systems
- Educational environments
- Authorized penetration-testing targets
- Systems for which explicit permission has been obtained

Do not use IntelliScan to scan systems without authorization.

Unauthorized security scanning may violate organizational policies and applicable laws.

---

# 30. Limitations

The current implementation is primarily designed for an academic and laboratory demonstration.

Limitations include:

- The CVE database is local and limited.
- The CVE database is not a continuously synchronized NVD feed.
- Risk scoring is rule-based.
- The platform is not intended to replace enterprise vulnerability management systems.
- Remediation guidance requires administrator review.
- The Flask development server is not a production deployment platform.
- Advanced authenticated scanning is outside the current scope.
- Distributed scanning is outside the current scope.
- Large-scale asset management is outside the current scope.

---

# 31. Future Scope

Potential future enhancements include:

- Live NVD/CVE feed integration
- CVSS-based scoring
- EPSS integration
- Machine-learning-assisted risk prioritization
- Distributed scanning agents
- Scheduled scanning
- Email notifications
- Role-based access control
- Multi-user security teams
- Asset inventory
- Authenticated web scanning
- Additional vulnerability detection rules
- Docker deployment
- Kubernetes deployment
- SIEM integration
- Security orchestration and automated response
- Cloud asset scanning
- Advanced executive dashboards

---

# 32. Academic Information

Project Name:

IntelliScan – Automated Network Vulnerability Assessment, Risk Prioritization and Remediation Platform

Project Type:

Final-Year Cybersecurity Project

Primary Domain:

Cybersecurity / Vulnerability Assessment / Network Security

Primary Technologies:

Python, Flask, SQLite, Nmap, ReportLab, HTML, CSS, JavaScript, Pytest and Git

Primary Purpose:

To automate network security assessment and transform raw network and web scanning results into prioritized security findings, risk scores, remediation guidance, historical comparisons, and professional security reports.

---

# 33. Quick Demonstration Procedure

For a final demonstration:

    1. Start RHEL VM.
    2. Open terminal.
    3. Start IntelliScan.
    4. Open browser.
    5. Login.
    6. Open Dashboard.
    7. Add authorized target.
    8. Start a scan.
    9. Show discovered host.
    10. Show open services.
    11. Show security findings.
    12. Show risk scores.
    13. Show remediation.
    14. Show historical comparison.
    15. Open HTML report.
    16. Generate PDF report.
    17. Explain architecture.
    18. Explain risk calculation.
    19. Explain CVE correlation.
    20. Explain limitations and future scope.

---

# 34. Final Project Status

The current IntelliScan implementation includes:

    [✓] Project structure
    [✓] Python environment
    [✓] SQLite database
    [✓] Target management
    [✓] Target validation
    [✓] Nmap discovery
    [✓] Port scanning
    [✓] Service detection
    [✓] Result normalization
    [✓] Web security scanning
    [✓] Finding engine
    [✓] Risk engine
    [✓] CVE correlation
    [✓] Remediation engine
    [✓] Historical comparison
    [✓] Authentication
    [✓] Dashboard
    [✓] Scan history
    [✓] Scan results
    [✓] HTML reporting
    [✓] PDF reporting
    [✓] API endpoints
    [✓] Automated tests
    [✓] Real scan validation
    [✓] Git version control

---

# 35. Final Notes

IntelliScan demonstrates how multiple cybersecurity assessment activities can be integrated into a single automated platform.

The main contribution of the project is not only network scanning, but the complete processing pipeline:

    Discovery
        ↓
    Detection
        ↓
    Risk Prioritization
        ↓
    CVE Correlation
        ↓
    Remediation
        ↓
    Historical Analysis
        ↓
    Security Reporting

This transforms raw technical scan information into structured and actionable security assessment results.
