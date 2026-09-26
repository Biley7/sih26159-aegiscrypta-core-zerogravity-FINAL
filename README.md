<p align="center">
  <strong>AegisCrypta</strong><br/>
  <em>Dual-Paradigm Email Security & Cryptographic Posture Platform</em>
</p>

<p align="center">
  <code>SIH2026159 / NTRO Architecture Standards</code>
</p>

---

## What It Does

AegisCrypta scans any email domain and produces a **deterministic 0–100 security posture score** by probing:

| Layer | Checks Performed |
|---|---|
| **DNS Authentication** | SPF, DMARC, DKIM (multi-selector), DNSSEC |
| **Transport Security** | MX routing, opportunistic STARTTLS, TLS version & cipher suite, Forward Secrecy, X.509 certificate chain |
| **Policy Enforcement** | MTA-STS (`_mta-sts.` TXT + `/.well-known/mta-sts.txt`), TLS-RPT (`_smtp._tls.` TXT), DANE/TLSA |
| **Post-Quantum Readiness** | Kyber / ML-KEM hybrid handshake detection, SNDL quantum threat tagging |
| **AI Risk Synthesis** | CVSS v3.1 vector computation, Gemini 2.5 Flash–enhanced remediation summaries (optional), anomaly detection via Isolation Forest |
| **Passive Forensics** | PCAP upload → TCP stream reconstruction, plaintext credential exposure, STARTTLS stripping detection |

It also generates **PDF and HTML forensic audit reports** and provides **syntax-checked remediation playbooks** (SPF, DMARC, MTA-STS configs) ready to paste into DNS.

---

## Scoring Model

Deterministic 100-point posture formula — no randomness, no AI drift on the numerical score:

| Category | Points | Criteria |
|---|:---:|---|
| **SPF Configured** | +20 | `PASS` or valid mechanism (`-all`, `~all`, `redirect=`). +10 for `?all`. 0 if missing or `+all`. |
| **DMARC Policy** | +25 | `p=reject` or `p=quarantine`. +10 for `p=none` (+5 bonus for `sp=quarantine`/`sp=reject` subdomain enforcement). 0 if missing. |
| **Valid TLS 1.2/1.3 + STARTTLS** | +30 | Negotiated TLS 1.2 or 1.3 via SMTP STARTTLS, submission (587), SMTPS (465), or HTTPS SNI fallback. +15 for legacy TLS 1.0/1.1. |
| **MTA-STS / DANE TLSA** | +15 | MTA-STS policy published and valid, or TLSA record present. |
| **Post-Quantum / Modern Cipher** | +10 | Kyber/ML-KEM hybrid detected, or modern cipher with Forward Secrecy (ECDHE/DHE + AES-GCM/ChaCha20). |

**Bonus** (capped at 100 total): DKIM discovered (+5), TLS-RPT configured (+5).

**Grade Scale**: `A+` ≥ 90 · `A` ≥ 80 · `B` ≥ 65 · `C` ≥ 50 · `F` < 50

### Reference Scores

| Domain | Expected Score | Grade | Notes |
|---|:---:|:---:|---|
| `gmail.com` | 90 | A+ | SPF ✓, DMARC p=none + sp=quarantine (+15), TLS 1.3 + STARTTLS (+30), MTA-STS (+15), Modern Cipher (+10), DKIM (+5) |
| `rbi.org.in` | 85 | A | SPF ✓, DMARC p=quarantine (+25), TLS 1.2 via HTTPS SNI fallback (+30), Modern Cipher (+10) |
| `defense.gov.in` | 0 | F | NXDOMAIN — no DNS records resolvable |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Frontend (React + Vite)                      │
│  ┌──────────┐ ┌───────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │  Header   │ │HeroGauges │ │ProtocolMatrix│ │TerminalDrawer    │  │
│  │(Scan Bar) │ │(Score Dial)│ │(Check Grid)  │ │(Live Scan Log)   │  │
│  └──────────┘ └───────────┘ └──────────────┘ └──────────────────┘  │
│  ┌──────────────────┐ ┌─────────────────┐ ┌──────────────────────┐ │
│  │HandshakeTable    │ │CertificateInsp. │ │RemediationEngine     │ │
│  │(TLS Telemetry)   │ │(X.509 Details)  │ │(Playbooks + CVSS)    │ │
│  └──────────────────┘ └─────────────────┘ └──────────────────────┘ │
│  ┌──────────────────┐ ┌─────────────────┐ ┌──────────────────────┐ │
│  │PcapForensicsView │ │SettingsModal    │ │Footer                │ │
│  │(PCAP Analysis)   │ │(Theme/API Cfg)  │ │(Credits + Links)     │ │
│  └──────────────────┘ └─────────────────┘ └──────────────────────┘ │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ axios (30s timeout)
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Backend (FastAPI + Uvicorn)                        │
│                                                                     │
│  main.py ─── POST /api/scan ──────────────────────────────────────▶ │
│     │        POST /api/crypto/probe                                 │
│     │        POST /api/analyze-pcap                                 │
│     │        POST /api/export-pdf                                   │
│     │        POST /api/scan/html                                    │
│     │        POST /api/scan/forensic                                │
│     │        GET  /health                                           │
│     ▼                                                               │
│  active_scanner.py ──▶ resolver.py (8.8.8.8 / 1.1.1.1 / 9.9.9.9) │
│     │                     └─▶ clean_txt_rdata() / resolve_mx_hosts()│
│     ├─▶ checks/spf.py                                              │
│     ├─▶ checks/dmarc.py                                            │
│     ├─▶ checks/dkim.py (12+ selectors)                             │
│     ├─▶ checks/mx_starttls.py (ports 25 → 587 → 465)              │
│     ├─▶ crypto/tls_probe.py (STARTTLS + HTTPS SNI fallback)        │
│     ├─▶ crypto/cert_analyzer.py (X.509 chain)                      │
│     ├─▶ crypto/cipher_evaluator.py (PQC / Forward Secrecy)         │
│     └─▶ crypto/mail_discovery.py (MTA-STS / DANE / TLS-RPT)       │
│                                                                     │
│  scoring.py ──▶ calculate_posture_score() [deterministic 0-100]    │
│                                                                     │
│  ai_engine.py ──▶ CVSS v3.1 + Remediation Playbooks               │
│     └─▶ (optional) Gemini 2.5 Flash for narrative summaries        │
│                                                                     │
│  ai/risk_scorer.py ──▶ Cryptographic risk factor analysis          │
│  ai/anomaly_detector.py ──▶ Isolation Forest session anomalies     │
│                                                                     │
│  pcap_analyzer.py ──▶ pcap/stream_reconstructor.py                 │
│                       pcap/tls_reconstructor.py                     │
│                                                                     │
│  pdf_report.py ──▶ ReportLab PDF generation                        │
│  reports/html_report.py ──▶ Jinja2 standalone HTML report          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```text
mail-security-posture-scanner/
├── backend/
│   ├── app/
│   │   ├── active_scanner.py      # Orchestrates full domain scan (DNS + socket probes)
│   │   ├── ai_engine.py           # AI risk scoring, CVSS v3.1, remediation playbooks
│   │   ├── main.py                # FastAPI entrypoint, 7 API endpoints, CORS, error handling
│   │   ├── models.py              # Pydantic v2 schemas (ScanResponse, CryptographicPosture, etc.)
│   │   ├── pcap_analyzer.py       # PCAP file parsing and passive forensic analysis
│   │   ├── pdf_report.py          # ReportLab PDF audit report generator
│   │   ├── resolver.py            # Public DNS resolver (8.8.8.8/1.1.1.1/9.9.9.9), TXT parsing
│   │   ├── scoring.py             # Deterministic 100-pt posture scoring engine
│   │   │
│   │   ├── checks/                # Individual DNS authentication checks
│   │   │   ├── spf.py             # SPF record validation (mechanism parsing, lookup limits)
│   │   │   ├── dmarc.py           # DMARC policy parsing (p=, sp=, pct=, rua=, ruf=)
│   │   │   ├── dkim.py            # DKIM selector probing (12+ common selectors)
│   │   │   └── mx_starttls.py     # MX resolution + multi-port STARTTLS verification
│   │   │
│   │   ├── crypto/                # Cryptographic protocol inspection
│   │   │   ├── tls_probe.py       # Active TLS handshake prober (SMTP/IMAP/POP3 + HTTPS SNI fallback)
│   │   │   ├── cert_analyzer.py   # X.509 certificate chain analysis (SANs, expiry, key size)
│   │   │   ├── cipher_evaluator.py# Cipher suite classification (PQC, Forward Secrecy, weak ciphers)
│   │   │   └── mail_discovery.py  # MTA-STS, DANE/TLSA, TLS-RPT discovery and validation
│   │   │
│   │   ├── ai/                    # AI/ML modules
│   │   │   ├── risk_scorer.py     # Cryptographic risk factor analysis
│   │   │   └── anomaly_detector.py# Isolation Forest–based session anomaly detection
│   │   │
│   │   ├── pcap/                  # Passive network forensics
│   │   │   ├── stream_reconstructor.py  # TCP stream reconstruction (SMTP/IMAP/POP3)
│   │   │   └── tls_reconstructor.py     # Passive TLS handshake extraction
│   │   │
│   │   └── reports/               # Report generators
│   │       └── html_report.py     # Standalone HTML forensic report (dark theme, print CSS)
│   │
│   ├── requirements.txt           # Python dependencies
│   └── venv/                      # Python virtual environment (not committed)
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx                # Main application shell (scan orchestration, state management)
│   │   ├── api.ts                 # Axios API client (30s timeout, health check, PDF download)
│   │   ├── main.tsx               # React DOM entry point
│   │   ├── types.ts               # TypeScript type definitions
│   │   ├── mockData.ts            # Offline fallback mock data (used when backend is unreachable)
│   │   ├── styles.css             # Full CSS design system (glassmorphism, dark theme, animations)
│   │   └── components/
│   │       ├── Header.tsx         # Domain search bar, preset pills, dark/light toggle
│   │       ├── HeroGauges.tsx     # Circular score dial, grade badge, AI risk meters
│   │       ├── ProtocolMatrix.tsx # DNS check status grid (SPF/DMARC/DKIM/STARTTLS)
│   │       ├── HandshakeTable.tsx # TLS handshake telemetry table (version, cipher, FS)
│   │       ├── CertificateInspector.tsx # X.509 certificate detail viewer
│   │       ├── RemediationEngine.tsx    # CVSS v3.1 display + remediation playbooks
│   │       ├── PcapForensicsView.tsx    # PCAP upload + forensic analysis results
│   │       ├── TerminalDrawer.tsx       # Live scan progress terminal overlay
│   │       ├── Terminal.tsx             # Terminal output component
│   │       ├── SettingsModal.tsx        # Theme, API endpoint, and scan config settings
│   │       ├── Toast.tsx                # Notification toast component
│   │       └── Footer.tsx              # Footer with credits and external links
│   │
│   ├── package.json               # npm dependencies (React, Vite, Axios, Lucide)
│   ├── tsconfig.json              # TypeScript configuration
│   └── vite.config.ts             # Vite bundler configuration
│
├── README.md                      # ← You are here
└── .gitignore
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.10 |
| Node.js | ≥ 18 LTS |
| npm | ≥ 9 |

Optional: A `GOOGLE_API_KEY` environment variable to enable Gemini 2.5 Flash narrative summaries in remediation playbooks. Without it, the AI engine runs in deterministic-only mode.

---

## Setup & Run

### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # macOS / Linux
# venv\Scripts\activate           # Windows

pip install -r requirements.txt

# (Optional) Create .env for Gemini AI summaries
echo "GOOGLE_API_KEY=your-key-here" > .env

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend is live at **http://localhost:8000** · Swagger docs at **http://localhost:8000/docs**

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend is live at **http://localhost:5173** · Connects to backend at `http://localhost:8000`

---

## API Reference

All endpoints accept and return `application/json` unless stated otherwise.

### `GET /`
Health banner with service metadata and endpoint listing.

### `GET /health`
Returns `{"status": "ok", "timestamp": "..."}`.

---

### `POST /api/scan`
**Full security posture scan** — the primary endpoint.

**Request:**
```json
{ "domain": "gmail.com" }
```

**Response** (abbreviated):
```json
{
  "domain": "gmail.com",
  "score": 90,
  "checks": [
    { "name": "SPF", "status": "pass", "details": {...}, "recommendation": null },
    { "name": "DMARC", "status": "warn", "details": {"policy": "none", "subdomain_policy": "quarantine", ...} },
    { "name": "DKIM", "status": "pass", "details": {"selector": "20230601", ...} },
    { "name": "MX & STARTTLS", "status": "pass", "details": {...} },
    { "name": "DNSSEC", "status": "pass", "details": {...} },
    { "name": "MTA-STS", "status": "pass", "details": {...} },
    { "name": "TLS-RPT", "status": "pass", "details": {...} },
    { "name": "DANE/TLSA", "status": "warn", "details": {...} }
  ],
  "crypto_posture": {
    "grade": "A+",
    "protocols_audited": [...],
    "prioritized_findings": [...]
  },
  "ai_risk_score": { "risk_score": 10, "risk_level": "LOW", ... },
  "cvss_metrics": { "base_score": 3.7, "vector_string": "CVSS:3.1/...", ... },
  "remediation_playbook": { "spf_record": "...", "dmarc_record": "...", ... },
  "anomaly_detection": { "anomalies_detected": false, ... },
  "prioritized_findings": [...],
  "scanned_at": "2026-09-12 17:30:00 UTC"
}
```

---

### `POST /api/crypto/probe`
**Direct TLS handshake probe** on a specific host and port.

**Request:**
```json
{
  "host": "alt1.gmail-smtp-in.l.google.com",
  "port": 25,
  "protocol": "SMTP",
  "use_starttls": true
}
```

**Response**: `ProtocolAuditResult` with full TLS handshake telemetry, cipher suite details, and X.509 certificate chain.

---

### `POST /api/analyze-pcap`
**Passive forensic analysis** of uploaded `.pcap` / `.pcapng` files.

**Request**: `multipart/form-data` with `file` field.

**Response**: TCP stream reconstruction, plaintext credential exposure, STARTTLS stripping detection, passive TLS handshake extraction.

---

### `POST /api/export-pdf`
Scans domain and returns a **downloadable binary PDF** forensic audit report.

**Request:**
```json
{ "domain": "rbi.org.in" }
```

**Response**: `application/pdf` binary stream with `Content-Disposition: attachment`.

---

### `POST /api/scan/html`
Generates a **standalone HTML forensic report** with dark styling, metrics cards, prioritized findings, certificate hierarchy, and print-ready CSS.

**Request:**
```json
{ "domain": "gmail.com" }
```

**Response**: `text/html` — self-contained, no external dependencies.

---

### `POST /api/scan/forensic`
Returns **raw JSON telemetry** including all handshake data, AI risk assessment, CVSS metrics, anomaly detection, and remediation playbooks.

**Request:**
```json
{ "domain": "gmail.com" }
```

---

## Network Resilience

### Residential ISP Port 25 Blocking

Most residential ISPs block outbound TCP port 25. AegisCrypta handles this with a **multi-port sequential prober**:

```
Port 25  (SMTP + STARTTLS)       ──▶  attempt first
Port 587 (Submission + STARTTLS) ──▶  fallback #1
Port 465 (Implicit SMTPS)        ──▶  fallback #2
Port 443 (HTTPS SNI)             ──▶  fallback #3 (extracts TLS version, cipher, cert via SNI)
```

If all SMTP ports are filtered, the prober extracts cryptographic capabilities via HTTPS SNI on port 443, ensuring live servers are **never misclassified as insecure**. The score remains stable regardless of ISP filtering.

### DNS Resolver Hardening

All DNS queries bypass the local system resolver and go directly to:
- `8.8.8.8` (Google Public DNS)
- `1.1.1.1` (Cloudflare)
- `9.9.9.9` (Quad9)

With `timeout = 2.0s` and `lifetime = 4.0s`. NXDOMAIN and NoAnswer are explicitly caught and handled — never silently swallowed as UNKNOWN.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Deterministic scoring** (no AI influence on numbers) | Scans of the same domain must return the same score on every run. AI only enhances narrative summaries. |
| **HTTPS SNI fallback for TLS validation** | Ensures accurate posture assessment from environments where SMTP ports are blocked. |
| **12+ DKIM selectors** (`20230601`, `20210112`, `google`, `default`, `mail`, `k1`, `selector1`, `selector2`, `nic2024`, `sig1`, `2024`, `smtp`, `dkim`) | Maximizes DKIM discovery across major providers (Google Workspace, Microsoft 365, Mailchimp, etc.). |
| **30s frontend timeout** (up from 12s) | Multi-port sequential probing can take 10-20s under adverse network conditions. |
| **Race condition guard** (`scanCounterRef`) | Prevents stale async responses from overwriting current scan results when users click presets rapidly. |
| **NXDOMAIN → FAIL, not UNKNOWN** | Domains that don't exist should score 0, not show ambiguous "UNKNOWN" status. |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend Framework | FastAPI 0.110+ with Uvicorn |
| DNS Engine | dnspython 2.6+ |
| TLS/Crypto | Python `ssl` stdlib + `cryptography` 42+ |
| AI / ML | scikit-learn (Isolation Forest), Google Generative AI (Gemini 2.5 Flash, optional) |
| PCAP Parsing | Scapy 2.5+ |
| PDF Reports | ReportLab 4.1+ |
| HTML Reports | Jinja2 3.1+ |
| Frontend | React 19 + TypeScript + Vite |
| UI Icons | Lucide React |
| HTTP Client | Axios |
| Styling | Custom CSS (glassmorphism, dark theme, micro-animations) |

---

## Environment Variables

| Variable | Required | Description |
|---|:---:|---|
| `GOOGLE_API_KEY` | No | Gemini 2.5 Flash API key for AI-enhanced remediation narratives. Without it, playbooks use deterministic template generation. |

---

## Verification

### Quick Smoke Test

```bash
# From backend/ with venv activated:
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain":"gmail.com"}' | python3 -m json.tool | head -5
```

Expected:
```json
{
    "domain": "gmail.com",
    "score": 90,
    ...
}
```

### Automated Scoring Validation

```bash
cd backend
source venv/bin/activate

python3 -c "
from app.active_scanner import run_active_domain_scan
from app.scoring import calculate_posture_score

for target, exp_min, exp_max in [
    ('gmail.com', 88, 95),
    ('rbi.org.in', 80, 90),
    ('defense.gov.in', 0, 45)
]:
    checks, crypto, findings = run_active_domain_scan(target)
    score, grade, _, _ = calculate_posture_score(checks, target, crypto, findings)
    print(f'{target}: score={score}, grade={grade}')
    assert exp_min <= score <= exp_max, f'{target} score {score} outside [{exp_min}, {exp_max}]'
print('ALL TESTS PASSED')
"
```

---

## License

This project is developed for **Smart India Hackathon 2026 (Problem Statement 159)** under NTRO architecture standards.
