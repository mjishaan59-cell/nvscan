# nvscan

## Automated Network Vulnerability Assessment, Risk Analysis and Remediation Platform

`nvscan` is an automated cybersecurity assessment platform developed as a final-year cybersecurity project.

The platform is designed to automate multiple stages of a network and web security assessment through a centralized workflow. It combines target management, host discovery, port and service discovery, web security checks, vulnerability finding detection, CVE correlation, risk scoring, remediation guidance, historical scan comparison, reporting, authentication, and Docker-based deployment.

> **Authorized use only:** nvscan is intended for systems, networks, laboratories, virtual machines, and applications for which the user has explicit authorization to perform security testing.

---

# 1. Project Overview

Traditional vulnerability assessment often requires security professionals to execute several tools manually, interpret their results, prioritize findings, prepare remediation guidance, and generate reports.

`nvscan` integrates these activities into one application.

The platform accepts an authorized target and performs a structured assessment workflow:

```text
Target Registration
        |
        v
Target Validation
        |
        v
Host Discovery
        |
        v
Port Scanning
        |
        v
Service Detection
        |
        v
Web Security Scanning
        |
        v
Result Normalization
        |
        v
Finding Detection
        |
        v
CVE Correlation
        |
        v
Risk Scoring
        |
        v
Remediation Generation
        |
        v
Database Persistence
        |
        v
Reports / Dashboard / History
```

---

# 2. Problem Statement

Security assessment can become time-consuming when network discovery, service analysis, web checks, vulnerability identification, risk prioritization, remediation planning, and reporting are performed separately.

The problem addressed by nvscan is:

> How can multiple vulnerability assessment activities be integrated into a centralized and automated platform that produces structured findings, risk information, remediation guidance, historical comparisons, and reports?

---

# 3. Project Objectives

The main objectives of nvscan are:

* Automate authorized network vulnerability assessment.
* Validate assessment targets before scanning.
* Discover reachable hosts.
* Identify exposed network ports.
* Detect network services.
* Perform HTTP-based web security checks.
* Normalize scanner output.
* Detect security findings using defined detection rules.
* Correlate supported findings with known CVE information.
* Calculate explainable risk scores.
* Assign finding priorities.
* Generate remediation guidance.
* Persist assessment results in SQLite.
* Maintain scan history.
* Compare completed scans.
* Generate HTML reports.
* Generate PDF reports.
* Provide an authenticated web dashboard.
* Provide Docker-based deployment.
* Support repeatable security assessment workflows.

---

# 4. Main Features

## 4.1 Target Management

Users can register authorized assessment targets.

Supported target information includes:

* IPv4 addresses
* Hostnames
* Target type classification

The platform prevents duplicate target registration and maintains registered targets in the database.

---

## 4.2 Target Validation

Before a scan begins, the target passes through validation.

The validation stage helps ensure that the supplied target is syntactically acceptable before the assessment workflow starts.

---

## 4.3 Host Discovery

nvscan determines whether the target contains reachable hosts.

This allows the scanner to distinguish between:

```text
Reachable target
```

and:

```text
Unreachable/offline target
```

An unreachable target is handled gracefully without causing the complete application to fail.

---

## 4.4 Port Scanning

The platform uses Nmap-based scanning to identify exposed network ports.

Example categories include:

```text
22    SSH
21    FTP
80    HTTP
443   HTTPS
111   RPC
2049  NFS
```

The actual results depend on the authorized target being assessed.

---

## 4.5 Service Detection

After identifying open ports, nvscan analyzes available services.

Service information can include:

* Port
* Protocol
* Service name
* Service version where available

This information is later used by the finding and risk analysis stages.

---

## 4.6 Web Security Scanning

For discovered HTTP services, nvscan performs additional HTTP-based checks.

The web scanner evaluates security-related characteristics such as HTTP response headers and web server information disclosure.

Implemented checks include findings such as:

* Missing HSTS
* Missing Content-Security-Policy
* Missing clickjacking protection
* Missing MIME sniffing protection
* Missing Referrer-Policy
* Web server information disclosure

---

# 5. Finding Detection Engine

The finding engine converts normalized scanner observations into structured security findings.

Each finding can contain information such as:

```text
Finding ID
Severity
Title
Description
Evidence
Affected target
Affected service
```

Example finding identifiers include:

```text
WEB-009
WEB-010
WEB-011
NET-002
NET-006
NET-007
```

The detection rules are implemented in:

```text
scanner/detection_rules.py
scanner/finding_engine.py
```

---

# 6. CVE Correlation Engine

nvscan contains a local vulnerability correlation component.

The CVE correlation engine evaluates supported service and vulnerability information against the application's local CVE data.

The purpose is to associate applicable findings with known vulnerability identifiers where sufficient information is available.

Main components:

```text
vulnerability_engine/
├── __init__.py
├── correlator.py
└── cve_database.py
```

A scan can complete successfully even when no CVE matches are identified.

For example:

```text
Findings detected: 9
CVE matches: 0
```

This means that findings were successfully detected, but the available correlation data did not produce a matching CVE.

---

# 7. Risk Scoring

nvscan contains an explainable risk scoring engine.

The risk engine converts security findings into numerical risk information and assigns a priority.

Example output:

```text
Finding                    Risk       Priority
------------------------------------------------
Missing HSTS               50.0       MEDIUM
Missing CSP                50.0       MEDIUM
FTP exposed                55.0       MEDIUM
RPC exposed                55.0       MEDIUM
NFS exposed                57.5       MEDIUM
```

> The nvscan risk score is an application-specific risk score. It should not be interpreted as a CVSS score.

The risk engine is implemented in:

```text
risk_engine/scorer.py
```

---

# 8. Remediation Engine

After findings and risk scores are generated, nvscan produces remediation guidance.

The remediation engine provides actions associated with detected findings.

The workflow is:

```text
Finding
   |
   v
Risk Score
   |
   v
Priority
   |
   v
Remediation Guidance
```

Main implementation:

```text
remediation_engine/engine.py
```

Remediation guidance is stored with the assessment results.

---

# 9. Scan Controller

The central scan controller coordinates the complete assessment pipeline.

Main implementation:

```text
scanner/controller.py
```

The controller integrates:

```text
Host Discovery
      |
Port Scanning
      |
Service Detection
      |
Web Scanning
      |
Normalization
      |
Finding Detection
      |
CVE Correlation
      |
Risk Scoring
      |
Remediation
      |
Database Persistence
```

This provides a single workflow instead of requiring the user to manually execute each component.

---

# 10. Historical Scan Comparison

nvscan stores completed scans so that users can compare assessment results over time.

The comparison functionality can help identify:

* New findings
* Resolved findings
* Persistent findings
* Changes in risk
* Changes between assessment periods

Implementation:

```text
scanner/comparison_engine.py
```

The web interface provides a dedicated comparison page.

---

# 11. Reporting

nvscan provides multiple reporting capabilities.

## HTML Reports

HTML reports are generated using:

```text
reports/html_exporter.py
```

## PDF Reports

PDF reports are generated using:

```text
reports/pdf_exporter.py
```

The PDF exporter uses ReportLab.

The reporting workflow is:

```text
Stored Scan Results
        |
        v
Report Generator
        |
        +----> HTML Report
        |
        +----> PDF Report
```

---

# 12. Web Application

The platform provides a Flask-based web interface.

Major pages include:

```text
/login
/dashboard
/targets
/scans
/reports
/comparison
/scan results
```

The web interface provides access to:

* Target management
* Starting scans
* Scan history
* Scan results
* Risk information
* Remediation information
* Reports
* Historical comparison

---

# 13. Authentication

nvscan includes session-based authentication.

The authentication implementation includes:

* Login
* Logout
* Password hash verification
* Active-user checking
* Session management
* Protected routes

Main implementation:

```text
auth.py
```

The Flask session uses:

```text
HTTPOnly cookies
SameSite=Lax
```

The application also supports a configurable secret key through:

```text
NVSCAN_SECRET_KEY
```

---

# 14. Database

nvscan uses SQLite for persistent application data.

Database implementation:

```text
database/database.py
```

Database schema:

```text
database/schema.sql
```

The database stores information related to:

* Users
* Targets
* Scans
* Hosts
* Services
* Findings
* Risk scores
* CVE information
* Remediation actions
* Scan history

The database allows assessment results to remain available after a scan has completed.

---

# 15. Technology Stack

| Component               | Technology                                |
| ----------------------- | ----------------------------------------- |
| Operating System        | RHEL 10                                   |
| Programming Language    | Python                                    |
| Web Framework           | Flask                                     |
| Database                | SQLite                                    |
| Network Scanner         | Nmap                                      |
| Web Scanner             | Python HTTP-based scanning                |
| Authentication          | Flask session + Werkzeug password hashing |
| PDF Generation          | ReportLab                                 |
| Testing                 | Pytest                                    |
| Containerization        | Docker                                    |
| Container Orchestration | Docker Compose                            |
| Version Control         | Git                                       |
| Repository Hosting      | GitHub                                    |

---

# 16. Project Structure

```text
nvscan/
│
├── api/
│   └── __init__.py
│
├── database/
│   ├── __init__.py
│   ├── database.py
│   └── schema.sql
│
├── remediation_engine/
│   ├── __init__.py
│   └── engine.py
│
├── reports/
│   ├── __init__.py
│   ├── html_exporter.py
│   ├── pdf_exporter.py
│   └── report_generator.py
│
├── risk_engine/
│   ├── __init__.py
│   └── scorer.py
│
├── scanner/
│   ├── __init__.py
│   ├── comparison_engine.py
│   ├── controller.py
│   ├── detection_rules.py
│   ├── discovery.py
│   ├── finding_engine.py
│   ├── nmap_engine.py
│   ├── normalizer.py
│   ├── parser.py
│   ├── port_scanner.py
│   ├── service_detection.py
│   └── target_validator.py
│
├── tests/
│   └── test_nvscan.py
│
├── templates/
│   ├── base.html
│   ├── comparison.html
│   ├── dashboard.html
│   ├── login.html
│   ├── report.html
│   ├── results.html
│   ├── scan_history.html
│   ├── scan_results.html
│   └── targets.html
│
├── vulnerability_engine/
│   ├── __init__.py
│   ├── correlator.py
│   └── cve_database.py
│
├── web_scanner/
│   ├── __init__.py
│   ├── directory_enum.py
│   └── http_scanner.py
│
├── app.py
├── auth.py
├── config.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

# 17. Installation

## Requirements

The project requires:

* RHEL 10 or a compatible Linux environment
* Python 3
* Nmap
* Git
* Docker for container deployment
* Docker Compose for container deployment

---

## Clone the Repository

```bash
git clone https://github.com/mjishaan59-cell/nvscan.git
cd nvscan
```

---

## Create Python Virtual Environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

---

## Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## Run nvscan

```bash
python app.py
```

The application listens on:

```text
http://127.0.0.1:5000
```

When configured for remote access, the Flask application can listen on:

```text
0.0.0.0:5000
```

---

# 18. Docker Deployment

nvscan includes a Dockerfile and Docker Compose configuration.

Build and start the application:

```bash
docker compose up -d --build
```

Check the running container:

```bash
docker ps
```

Expected container:

```text
nvscan
```

Check application health:

```bash
curl -s http://127.0.0.1:5000/api/health
```

Expected response:

```json
{
    "application": "nvscan",
    "status": "healthy",
    "success": true
}
```

Stop the application:

```bash
docker compose down
```

Start it again:

```bash
docker compose up -d
```

---

# 19. Starting a Security Scan

After logging into the web interface:

```text
Dashboard
    |
    v
Targets
    |
    v
Register authorized target
    |
    v
Start Scan
    |
    v
Scan Processing
    |
    v
Results
```

The scan controller then executes the assessment pipeline.

---

# 20. Example Assessment Workflow

For an authorized target:

```text
192.168.x.x
```

nvscan performs:

```text
1. Target validation
2. Host discovery
3. Port scanning
4. Service detection
5. Web scanning
6. Result normalization
7. Finding analysis
8. CVE correlation
9. Risk scoring
10. Remediation generation
11. Database persistence
12. Report generation
```

---

# 21. Example Finding Results

A completed assessment can produce findings such as:

```text
WEB-009  Missing HSTS security header
WEB-010  Missing Content-Security-Policy header
WEB-011  Missing clickjacking protection header
WEB-012  Missing MIME sniffing protection header
WEB-013  Missing Referrer-Policy header
WEB-014  Web server information disclosed

NET-002  FTP service exposed
NET-006  RPC service exposed
NET-007  NFS service exposed
```

The exact findings depend on the authorized target being assessed.

---

# 22. Testing

The project includes automated tests using Pytest.

Test execution:

```bash
pytest -q
```

The current automated test suite has been successfully verified with:

```text
18 passed
```

Manual testing has also been performed for major application functions, including:

* Application health
* Docker operation
* Authentication
* Target registration
* Duplicate target handling
* Target validation
* Start Scan functionality
* Host discovery
* Port scanning
* Service discovery
* Finding detection
* CVE correlation
* Risk scoring
* Remediation generation
* Database persistence
* Scan history
* Historical comparison
* HTML reporting
* PDF reporting
* Offline/unreachable target handling
* Docker restart behavior

---

# 23. Offline Target Handling

nvscan handles unreachable targets gracefully.

Example:

```text
Host discovery complete: 0 live host(s)

Normalization complete: 0 result(s)

Finding analysis complete: 0 finding(s)

CVE correlation complete: 0 CVE finding(s)

Risk scoring complete: 0 finding(s)

Remediation guidance generated for 0 finding(s)
```

The scan completes without crashing the application.

---

# 24. Security Considerations

The project includes several security-related controls:

* Authentication-protected application routes
* Password hash verification
* Active-user validation
* Session clearing during logout
* HTTPOnly session cookies
* SameSite cookie configuration
* Configurable Flask secret key
* Target validation
* Authorized-use warning
* Structured database persistence
* Docker isolation

The application should still be deployed using appropriate production security controls before exposure to an untrusted network.

---

# 25. Docker Architecture

The Docker deployment can be represented as:

```text
                    Kali / Browser
                         |
                         | HTTP :5000
                         v
              +----------------------+
              |     Docker Host      |
              |       RHEL 10        |
              |                      |
              |  +----------------+  |
              |  |     nvscan     |  |
              |  | Flask + Python |  |
              |  | Nmap            |  |
              |  +-------+--------+  |
              |          |           |
              |          v           |
              |      SQLite DB       |
              +----------------------+
```

---

# 26. Data Flow

```text
                 Authorized Target
                        |
                        v
                Target Validator
                        |
                        v
                 Host Discovery
                        |
                        v
                  Port Scanner
                        |
                        v
                Service Detection
                        |
                        v
                  Web Scanner
                        |
                        v
                Result Normalizer
                        |
                        v
                Finding Engine
                        |
                        v
               CVE Correlator
                        |
                        v
                 Risk Engine
                        |
                        v
              Remediation Engine
                        |
                        v
                 SQLite Database
                        |
             +----------+----------+
             |          |          |
             v          v          v
          Dashboard   Reports   Comparison
```

---

# 27. Git Workflow

The project is maintained using Git.

Typical workflow:

```bash
git status
git add -A
git commit -m "Describe change"
git push origin main
```

The main branch is:

```text
main
```

Repository:

```text
https://github.com/mjishaan59-cell/nvscan
```

---

# 28. Project Limitations

The current implementation is primarily designed as an academic and controlled security assessment platform.

Potential limitations include:

* Detection coverage depends on implemented rules.
* CVE correlation depends on the available local vulnerability data.
* Risk scores are application-specific and are not CVSS scores.
* Advanced authenticated web application testing is outside the current core workflow.
* Exploit execution is not part of the core assessment pipeline.
* Large-scale distributed scanning is outside the current implementation.
* Production deployments require additional hardening.

---

# 29. Future Enhancements

Potential future improvements include:

* Expanded vulnerability detection rules
* Larger and regularly updated CVE datasets
* CVSS integration
* Authenticated scanning
* Expanded web vulnerability testing
* API token authentication
* Role-based access control
* Background/asynchronous scanning
* Scan scheduling
* Email notifications
* Advanced dashboards
* More detailed asset inventory
* Distributed scanning agents
* Container image scanning
* Cloud asset assessment
* SIEM integration
* Security alerting
* Continuous vulnerability monitoring

---

# 30. Academic Value

nvscan demonstrates the integration of multiple cybersecurity concepts into a practical software platform.

The project combines:

```text
Networking
+
Vulnerability Assessment
+
Web Security
+
Security Automation
+
Risk Analysis
+
CVE Correlation
+
Remediation
+
Database Engineering
+
Web Development
+
Authentication
+
Containerization
+
Linux Administration
```

This makes nvscan suitable for demonstrating practical knowledge across multiple areas of cybersecurity and system administration.

---

# 31. Conclusion

nvscan provides a centralized approach to automated vulnerability assessment.

Instead of treating discovery, service analysis, vulnerability detection, risk analysis, remediation, and reporting as isolated activities, the platform combines them into one workflow.

The completed system demonstrates:

```text
Discover
   ↓
Analyze
   ↓
Detect
   ↓
Correlate
   ↓
Prioritize
   ↓
Remediate
   ↓
Report
   ↓
Compare
```

The project has been tested through automated tests and manual end-to-end validation and is deployable using Docker.

---

## 32. Authorized Use

nvscan must only be used against systems and applications for which explicit authorization has been obtained.

Do not scan, test, exploit, or otherwise assess systems that you do not own or have permission to assess.

---

**Project:** nvscan
**Type:** Final-Year Cybersecurity Project
**Focus:** Automated Network Vulnerability Assessment, Risk Analysis and Remediation

