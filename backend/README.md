# AegisCrypta Forensics Engine

FastAPI backend for AegisCrypta, an email-security and cryptographic-posture scanner. It evaluates a domain's DNS authentication, mail routing, TLS configuration, certificates, cipher suites, and passive PCAP evidence, then returns deterministic scores and remediation data.

> **Repository note:** This checkout contains AegisCrypta, not an AGScript implementation. There are no lexer, parser, interpreter, `.ag`/`.ags` loader, or AGScript grammar files under `backend/`. The language-tour requirement below therefore uses the implemented HTTP/JSON contract and Python API seams. AGScript-specific syntax should be added only after its source and grammar are present.

Set `AEGIS_API_KEY` before starting the service. All `/api/*` routes require that value in the `X-API-Key` header; `/health` remains public for availability checks. Enter the same key in Console Settings, where it is retained in the current browser session only. Do not place a production key in frontend build variables or commit it. A browser-delivered key is extractable by users, so public deployments still need a trusted reverse proxy or network restriction.

## Contents

- [Overview and motivation](#overview-and-motivation)
- [Architecture and execution flow](#architecture-and-execution-flow)
- [Syntax and API contract tour](#syntax-and-api-contract-tour)
- [Project structure](#project-structure)
- [Setup and installation](#setup-and-installation)
- [Usage and quickstart](#usage-and-quickstart)
- [Development and testing](#development-and-testing)
- [Roadmap](#roadmap)

## Overview and motivation

Mail security is distributed across DNS records, SMTP behavior, TLS negotiation, certificate hygiene, and operational policy. AegisCrypta turns those signals into one inspectable result for a domain:

- authentication checks for SPF, DMARC, DKIM, DNSSEC, MTA-STS, TLS-RPT, and DANE/TLSA;
- active probes for SMTP, IMAP, and POP3 services, including STARTTLS and direct TLS;
- certificate and cipher analysis, including forward secrecy, weak algorithms, and post-quantum hybrid indicators;
- passive PCAP analysis for mail protocols, cleartext credentials, STARTTLS stripping, and TLS handshakes;
- a deterministic 0-100 posture score, letter grade, findings, CVSS metrics, risk assessment, and configuration playbooks;
- JSON, standalone HTML, and PDF report outputs.

The numerical posture score is computed by the local scoring engine. Optional Gemini integration can enrich remediation narratives, but it is not required to run the API or calculate the baseline score.

## Architecture and execution flow

### Active domain scan

```text
POST /api/scan { domain }
        |
        v
  Pydantic validation and normalization
        |
        v
  Public DNS resolution and active domain scanner
        |-- SPF, DMARC, DKIM, MX/STARTTLS
        |-- MTA-STS, TLS-RPT, DANE/TLSA, DNSSEC
        |-- SMTP/IMAP/POP3 TLS probes and HTTPS fallback
        |-- X.509 certificate and cipher evaluation
        v
  Deterministic scoring and prioritized findings
        |-- cryptographic risk model
        |-- IsolationForest/heuristic anomaly detection
        |-- CVSS v3.1 metrics
        |-- remediation playbook generation
        v
  ScanResponse JSON
```

### Passive PCAP path

`POST /api/analyze-pcap` and its alias `POST /api/scan/pcap` accept a multipart upload. The PCAP analyzer groups TCP packets into flows, identifies SMTP/IMAP/POP3 or implicit TLS traffic, detects accepted STARTTLS/STLS transitions and authentication markers, reconstructs common TLS handshake metadata, and validates captured certificate chains against system roots when intermediates are present.

PCAP analysis is intentionally best effort. It sorts captured payload segments by TCP sequence number but does not currently perform retransmission/overlap handling or gap recovery; it also omits revocation checks and full TLS 1.3 key-share analysis.

### Report path

The same active scan result can be rendered as:

- JSON from `/api/scan` or `/api/scan/forensic`;
- a standalone HTML document from `/api/scan/html`;
- a downloadable PDF from `/api/export-pdf` or `/api/scan/pdf`.

## Syntax and API contract tour

AGScript syntax is not present in this repository. The following examples show the concrete request syntax used by the implemented service.

### Scan a domain

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_AEGIS_API_KEY' \
  -d '{"domain":"google.com"}'
```

The `domain` field is normalized to lowercase, accepts an optional `http://` or `https://` prefix, and must match a domain name with a two-character-or-longer TLD. The response contains `score`, `checks`, `crypto_posture`, `ai_risk_score`, `anomaly_detection`, `prioritized_findings`, `cvss_metrics`, and `remediation_playbook`.

### Probe one mail service

```json
{
  "host": "smtp.example.com",
  "port": 587,
  "protocol": "smtp",
  "use_starttls": true
}
```

Send this object to `POST /api/crypto/probe`. Supported protocol values are `smtp`, `imap`, and `pop3`; ports are constrained to `1-65535`. Use `false` for `use_starttls` when probing an implicit-TLS service such as SMTPS or IMAPS.

### Upload a capture

```bash
curl -X POST http://localhost:8000/api/scan/pcap \
  -H 'X-API-Key: YOUR_AEGIS_API_KEY' \
  -F 'file=@capture.pcap'
```

The response includes `total_packets`, `total_tcp_streams`, `identified_protocols`, `streams`, `summary_findings`, and `processed_at`. Empty uploads are rejected with HTTP 400.

### Use the Python API directly

```python
from app.ai_engine import evaluate_ai_remediation
from app.checks.dmarc import check_dmarc
from app.checks.spf import check_spf

domain = "example.com"
checks = [check_spf(domain), check_dmarc(domain)]
score, grade, risk, cvss, playbook = evaluate_ai_remediation(
    domain=domain,
    checks=checks,
    crypto_posture=None,
    findings=[],
)
print(score, grade, risk.risk_level, cvss.base_score)
```

This is a library seam for deterministic remediation and scoring. Network-dependent checks should be isolated or mocked in tests.

## Project structure

```text
backend/
├── app/
│   ├── main.py                         # FastAPI app, validation, routes, orchestration
│   ├── models.py                       # Pydantic request, response, and finding contracts
│   ├── active_scanner.py               # End-to-end domain scan coordinator
│   ├── resolver.py                     # DNS resolver configuration and record helpers
│   ├── scoring.py                      # Deterministic posture score and grade
│   ├── ai_engine.py                    # CVSS, risk synthesis, and playbook generation
│   ├── pcap_analyzer.py                # PCAP response assembly and analysis entry point
│   ├── pdf_report.py                   # PDF report renderer
│   ├── checks/
│   │   ├── spf.py                      # SPF record validation
│   │   ├── dmarc.py                    # DMARC policy validation
│   │   ├── dkim.py                     # Common-selector DKIM discovery
│   │   └── mx_starttls.py              # MX lookup and SMTP STARTTLS checks
│   ├── crypto/
│   │   ├── tls_probe.py                # SMTP/IMAP/POP3 and HTTPS TLS probing
│   │   ├── cert_analyzer.py             # X.509 metadata and certificate warnings
│   │   ├── cipher_evaluator.py          # Cipher, PFS, weak-crypto, and PQC flags
│   │   └── mail_discovery.py            # MTA-STS, TLS-RPT, and DANE/TLSA
│   ├── ai/
│   │   ├── risk_scorer.py               # Weighted cryptographic risk model
│   │   └── anomaly_detector.py          # IsolationForest and heuristic anomalies
│   ├── pcap/
│   │   ├── stream_reconstructor.py      # TCP flow and mail protocol analysis
│   │   └── tls_reconstructor.py         # Passive TLS handshake extraction
│   └── reports/
│       └── html_report.py               # Standalone HTML report renderer
├── requirements.txt                    # Runtime dependencies
└── tests/                              # API, crypto, PCAP, AI, and scoring tests
```

## Setup and installation

### Prerequisites

- Python 3.10 or newer; Python 3.11+ is recommended.
- Network access for live DNS and TLS probes.
- `libpcap` support may be required by Scapy on some operating systems.
- Node.js is required only for the separate frontend, not this backend.

### Create an environment

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

To enable optional Gemini remediation enrichment, set `GEMINI_API_KEY` in the environment or in a local `.env` file. The deterministic path works without it. Do not commit credentials.

## Usage and quickstart

Start the development server from `backend/`:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Useful URLs:

| URL | Purpose |
| --- | --- |
| `http://127.0.0.1:8000/` | Service metadata and endpoint directory |
| `http://127.0.0.1:8000/health` | Health check |
| `http://127.0.0.1:8000/docs` | Interactive OpenAPI/Swagger UI |
| `http://127.0.0.1:8000/redoc` | ReDoc API reference |

### Endpoint reference

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service metadata |
| `GET` | `/health` | Health check |
| `POST` | `/api/scan` | Full active posture scan |
| `POST` | `/api/crypto/probe` | Direct mail-service TLS probe |
| `POST` | `/api/analyze-pcap` | Passive PCAP analysis |
| `POST` | `/api/scan/pcap` | Alias for PCAP analysis |
| `POST` | `/api/export-pdf` | PDF report export |
| `POST` | `/api/scan/pdf` | Alias for PDF export |
| `POST` | `/api/scan/html` | Standalone HTML report |
| `POST` | `/api/scan/forensic` | Expanded forensic JSON |

Live scans can take longer than a local unit test because they depend on DNS, remote service availability, firewall policy, and TLS negotiation. Port 25 may be blocked by an ISP; the scanner also considers submission, SMTPS, and HTTPS SNI evidence where implemented.

## Development and testing

Run the focused deterministic suite first:

```bash
cd backend
python -m pytest tests/test_scoring_deterministic.py
```

Run all tests with pytest:

```bash
python -m pytest
```

The test modules cover:

- `test_scoring_deterministic.py`: score deductions, grades, TLS, cipher, and policy combinations;
- `test_crypto.py`: active cryptographic and certificate behavior;
- `test_pcap.py`: synthetic TCP stream reconstruction and upload handling;
- `test_ai_and_reports.py`: risk scoring, anomaly detection, HTML, and forensic JSON;
- `test_api.py`: health, validation, live scan, and PDF endpoints.

When adding a check or language-like API construct:

1. Define or update its Pydantic contract in `app/models.py`.
2. Keep network or filesystem access behind a small function that can be mocked.
3. Add deterministic unit tests before wiring the route.
4. Add the route only in `app/main.py`, preserving the response model and error behavior.
5. Update this README and the root README when the public API changes.

## Roadmap

Planned improvements should be tracked against the implementation rather than presented as current capabilities:

- add true AGScript source, grammar, lexer, parser, interpreter/runtime, and `.ag`/`.ags` execution support;
- replace heuristic DKIM selector discovery with configurable selectors and stronger verification;
- complete sequence-aware TCP reassembly, retransmission handling, and TLS 1.3 key-share parsing for PCAPs;
- add certificate-chain trust and revocation validation;
- pass passive PCAP findings through the AI/risk pipeline;
- add broader API contract tests that mock DNS and remote TLS services;
- tighten production deployment defaults, including explicit CORS origins and authentication/rate limiting;
- document and validate the frontend-to-backend configuration contract.

## License and contribution notes

This repository does not currently define a license or contribution policy in the backend. Before external distribution, add the project license, supported Python versions, security disclosure process, and a CI workflow that runs the test suite.
