# AegisCrypta — Cyber Posture Ops

**AI-Assisted Cryptographic Posture Assessment & Mail Forensics for Critical Infrastructure**

`SIH2026159` · `NTRO Architecture Standards` · Platform version `2.4.0`

---

## Overview

AegisCrypta is a dual-paradigm security posture platform for **critical mail infrastructure**. It actively audits a target email domain — DNS authentication, transport encryption, certificate health, post-quantum readiness — and passively reconstructs network forensics from packet captures, then fuses everything into a single deterministic posture index with an explainable rule trace.

| Capability | What It Delivers |
|---|---|
| **DNS Authentication** | SPF, DMARC (`p=`, `sp=`, `pct=`, `rua=`, `ruf=`), DKIM (10 common selectors), DNSSEC |
| **Transport Security** | MX routing, opportunistic STARTTLS, negotiated TLS version & cipher suite, Forward Secrecy |
| **Certificate Integrity** | X.509 chain validation against the platform trust store, SAN matching, expiry, key size, SHA-256 fingerprint |
| **Policy Enforcement** | MTA-STS (`_mta-sts.` TXT + `/.well-known/mta-sts.txt`), TLS-RPT (`_smtp._tls.` TXT), DANE/TLSA |
| **Post-Quantum Readiness** | ML-KEM-768 / Kyber hybrid handshake detection with explicit evaluated / not-evaluated reporting |
| **Risk Fusion** | Hierarchical fuzzy inference (CDI · PED · ELI → Posture Risk Index) with activated-rule explainability |
| **AI Narratives** | CVSS v3.1 vectors, remediation playbooks, Isolation-Forest session anomaly detection (optional Gemini summaries) |
| **Passive Forensics** | PCAP → TCP stream reassembly, cleartext credential exposure, STARTTLS stripping detection, passive TLS reconstruction |
| **Reporting** | Downloadable PDF dossier, standalone HTML forensic report, JSON session audit export |

**AegisCrypta never invents data.** When a signal cannot be observed (no handshake captured, no certificate presented, PQC evaluator not run), the UI and API report it as *not reported* rather than assuming a safe default.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND — React 19 + Vite + Tailwind                 │
│  HeaderBar        ThreatCenter        KeyProtocolCard     RemediationEngine  │
│  (scan / auth)    (risk index gauge)  (protocol matrix)   (CVSS + playbooks) │
│  Sidebar          CryptoSessionsCard  EmailCredentialsCard CertificateInsp.  │
│  ActiveReportCard ActivityTrendCard   AuditVolumeCard     ChallengeRouteCard │
│  DockedTerminal (live audit log)      PcapForensicsView   SettingsModal, etc.│
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │  same-origin `/api` (nginx proxy) or direct
                                    │  `X-API-Key` header · 30s timeout
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                       BACKEND — FastAPI + Uvicorn (Python 3.14)              │
│                                                                              │
│  main.py ──▶ auth middleware (X-API-Key) · sanitised error envelope · CORS   │
│     │                                                                        │
│     ├── POST /api/scan          ──▶ active_scanner.py ──▶ checks/*, crypto/* │
│     ├── POST /api/crypto/probe    ──▶ crypto/tls_probe.py (SSRF-guarded)     │
│     ├── POST /api/analyze-pcap    ──▶ pcap_analyzer.py ──▶ pcap/*            │
│     ├── POST /api/export-pdf      ──▶ pdf_report.py (ReportLab)              │
│     ├── POST /api/scan/html       ──▶ reports/html_report.py (Jinja2)        │
│     ├── POST /api/scan/forensic   ──▶ raw JSON telemetry                     │
│     └── GET  /health, /                                                      │
│                                                                              │
│  scoring.py ──▶ risk_engine/ ──▶ CDI · PED · ELI ──▶ posture_risk.py         │
│                                 (Tier-1 composites → Tier-2 fuzzy fusion)    │
│                                                                              │
│  ai_engine.py ──▶ CVSS v3.1 · remediation playbooks · optional Gemini        │
│  ai/risk_scorer.py · ai/anomaly_detector.py (Isolation Forest)               │
└──────────────────────────────────────────────────────────────────────────────┘
```

| Layer | Stack |
|---|---|
| **Backend** | Python 3.14 · FastAPI · Uvicorn · Pydantic v2 · dnspython · cryptography · scapy · scikit-fuzzy · scikit-learn · ReportLab · Jinja2 |
| **Frontend** | React 19 · TypeScript (strict) · Vite 8 · Tailwind CSS 3 · Recharts · Lucide icons · Axios |
| **Edge** | nginx reverse proxy (same-origin `/api`), multi-stage Docker build |

**Design principles**

1. **Deterministic scoring** — identical inputs produce identical scores. AI only narrates; it never moves the number.
2. **Explicit state honesty** — `not reported` ≠ `pass`. Unverifiable signals never silently become compliance.
3. **Fail-closed security** — no API key configured means `503`, not an open endpoint.
4. **No internal leakage** — raw exception text stays in the server log; clients receive sanitised messages plus a correlation ID.

---

## Quick Start (Local Development)

### Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.11 (validated on 3.14.7) |
| Node.js | ≥ 20 LTS (validated on 24.x) |
| npm | ≥ 10 |

### 1. Backend

```bash
# One-time setup
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

```bash
# Run (from the repository root; requires AEGIS_API_KEY and a matching CORS origin)
cd backend && AEGIS_API_KEY="your-key" CORS_ORIGINS="http://localhost:5173" uvicorn app.main:app --port 8000 --reload
```

Backend serves on **http://localhost:8000** · OpenAPI docs at **http://localhost:8000/docs**

Both variables are mandatory in practice: the service refuses every `/api/*` request with `503` until `AEGIS_API_KEY` is set, and browsers are only allowed from the origins listed in `CORS_ORIGINS` (a comma-separated allowlist; `CORS_ALLOWED_ORIGINS` is accepted as a legacy alias).

### 2. Frontend

```bash
cd frontend && npm install && npm run dev
```

Frontend serves on **http://localhost:5173**. Open **Settings** in the app to set the API base URL (default `http://localhost:8000`) and the shared API key.

### 3. Verify the stack

```bash
# Unauthenticated request must be rejected
curl -s -i -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' -d '{"domain":"gmail.com"}' | head -1
# → HTTP/1.1 401 Unauthorized

# Authenticated scan
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-key' \
  -d '{"domain":"gmail.com"}' | python3 -m json.tool | head -20
```

### 4. Run the test suite

```bash
cd backend && .venv/bin/python -m pytest -q      # → 102 passed
cd frontend && npx tsc -b && npm run build       # → 0 errors, dist/ emitted
```

---

## Docker Deployment

The compose topology runs the API and the SPA on an internal network: the browser only ever talks to nginx, which reverse-proxies `/api` to the API container. The API port is never published.

```bash
# AEGIS_API_KEY is mandatory — compose refuses to start without it
AEGIS_API_KEY="$(openssl rand -hex 32)" docker compose up --build
```

Or, if the key is already exported:

```bash
docker compose up --build
```

The web UI is then available on **http://localhost:8080** (override with `WEB_PORT`). Put a TLS-terminating proxy or load balancer in front of `aegiscrypta-web` for production traffic.

**Image layout (multi-stage):**

| Stage | Base | Notes |
|---|---|---|
| `backend` | `python:3.14-slim` | Installs from `requirements.lock.txt` so the image matches the environment the test suite passed in |
| `frontend-build` | `node:22-slim` | `npm ci` (lockfile-exact) then `vite build` |
| `frontend` | `nginx:alpine` | Template-expanded `nginx.conf`; only `${AEGIS_API_UPSTREAM}` is substituted |

**nginx routing:** `location /api/ → http://${AEGIS_API_UPSTREAM}` (default `aegiscrypta-api:8000`), plus `/health`, `/openapi.json`, `/redoc`, `/docs`, SPA `try_files` fallback, immutable caching for hashed assets, `client_max_body_size 64m` for PCAP uploads and 300s proxy timeouts for long live scans.

---

## Team

**Team Zero Gravity** — Smart India Hackathon 2026, Problem Statement 159 (NTRO architecture standards)

| Role | Name |
|---|---|
| **Team Lead** | **Binayak Roy** |
| Team | Team Zero Gravity |

---

## Scoring Model

Scores are produced by a **hierarchical fuzzy inference system** (`app/risk_engine/`), not by an additive checklist, so that one severe weakness cannot be diluted by unrelated strengths.

**Tier 1 — composite indices** (each 0–100):

| Index | Measures |
|---|---|
| **CDI** — Crypto Deprecation Index | TLS version, cipher suite strength, certificate health, forward secrecy |
| **PED** — Posture Exposure Deficit | Email authentication posture (SPF / DKIM / DMARC / MTA-STS / TLS-RPT / DANE) |
| **ELI** — Exploitation Likelihood Index | Exposure, exploit availability and asset criticality (`is_customer_facing`) |

**Tier 2 — posture risk fusion** (`posture_risk.py`) merges the three composites into the Posture Risk Index and a five-tier linguistic classification:

| Band | Posture Risk | Classification |
|---|:---:|---|
| Excellent | 0–20 | `EXCELLENT` |
| Good | 20–40 | `GOOD` |
| Acceptable | 40–60 | `ACCEPTABLE` |
| Poor | 60–80 | `POOR` |
| Critical | 80–100 | `CRITICAL` |

An explicit **OR rule across composites** forces the critical tier when any single composite is High — an expired certificate, deprecated TLS 1.0 or unenforced DMARC is never masked.

**Explainability** — every scan returns the evidence, not just the number:

```json
{
  "score": 50,
  "fuzzy_score": 50.1,
  "linguistic_classification": "ACCEPTABLE",
  "defuzzification_confidence": 1.0,
  "antecedent_scores": {
    "tls_compliance": 1.0, "cipher_strength": 1.0, "certificate_health": 0.8,
    "pqc_readiness": 0.1, "email_auth_posture": 0.5, "exploitation_likelihood": 0.132
  },
  "activated_rules": ["IF TLS Strong AND Cipher Strong AND Key Strong AND Cert Moderate AND Forward Secrecy THEN CDI Moderate (activation: 0.69)"]
}
```

The headline `score` is `int(fuzzy_score)`; `activated_rules` is the exact rule trace that produced it, and `defuzzification_confidence` reports how strongly the inputs agreed.

**Certificate grade** (`crypto_posture.grade`, derived from `crypto_score`):

| Grade | A+ | A | B | C | D | F |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Score | ≥ 95 | ≥ 85 | ≥ 70 | ≥ 55 | ≥ 40 | < 40 |

**Verified reference scan** (live, `gmail.com`, 2026-09-29): `score 50` · `ACCEPTABLE` · crypto grade `A` (`crypto_score 85`) · CVSS `5.3 MEDIUM` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) · checks `SPF pass, DKIM pass, DMARC warn, MTA-STS pass, TLS-RPT pass, DANE/TLSA warn` · PQC indicators evaluated. Scores are domain- and posture-dependent by design; treat any single value as a point-in-time snapshot.

---

## API Reference

All endpoints require the `X-API-Key` header. Bodies are `application/json` unless noted.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Service banner and endpoint listing |
| `GET` | `/health` | Liveness probe → `{"status":"ok","timestamp":"…"}` |
| `POST` | `/api/scan` | **Primary scan** — DNS auth, transport crypto, certs, PQC, risk fusion, playbooks |
| `POST` | `/api/crypto/probe` | Direct TLS/STARTTLS probe of one host + port (`smtp` \| `imap` \| `pop3`), SSRF-guarded |
| `POST` | `/api/analyze-pcap` · `/api/scan/pcap` | `multipart/form-data` PCAP upload → stream forensics |
| `POST` | `/api/export-pdf` · `/api/scan/pdf` | Binary PDF forensic dossier |
| `POST` | `/api/scan/html` · `/api/export-html` | Standalone HTML dossier (self-contained, print-ready) |
| `POST` | `/api/scan/forensic` | Raw JSON telemetry for SIEM ingest |

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Scan/analysis completed |
| `400` | Target rejected or unresolvable — `{"detail":"Domain resolution failed or unreachable."}` |
| `401` | Missing or invalid `X-API-Key` (`WWW-Authenticate: ApiKey`) |
| `403` | SSRF guard blocked a probe target (private / loopback / metadata address) |
| `422` | Pydantic request validation failure |
| `503` | `AEGIS_API_KEY` not configured on the server, or public DNS unavailable |
| `500` | Sanitised envelope with `correlation_id` — full trace stays in the server log |

---

## Environment Variables

| Variable | Required | Scope | Description |
|---|:---:|---|---|
| `AEGIS_API_KEY` | **Yes** | Backend / compose | Shared key for every `/api/*` request. Unset ⇒ all API calls return `503`. |
| `CORS_ORIGINS` | **Yes** (prod) | Backend | Comma-separated browser origin allowlist. `CORS_ALLOWED_ORIGINS` is honoured as a legacy alias. `*` is accepted but disables credentialed CORS and logs a warning. |
| `GEMINI_API_KEY` | No | Backend | Enables Gemini-enhanced remediation narratives. Without it the AI engine runs deterministic-only. |
| `AEGIS_API_UPSTREAM` | No | nginx | API upstream for the reverse proxy. Default `aegiscrypta-api:8000`. |
| `VITE_API_BASE_URL` | No | Frontend build | Empty (default) keeps the bundle same-origin and routed through the proxy. |
| `WEB_PORT` | No | compose | Published port for the web container. Default `8080`. |

---

## Security Model

- **Authentication** — a FastAPI middleware guards every `/api/*` path with a constant-time `hmac.compare_digest` comparison of the `X-API-Key` header. `OPTIONS` preflight is exempt so browsers are never blocked at CORS negotiation.
- **Fail-closed** — running with no `AEGIS_API_KEY` returns `503` for every API call rather than exposing an open scanner. `docker compose` refuses to start without one.
- **CORS** — `allow_origins` is derived strictly from the configured allowlist. `"*"` never combines with `allow_credentials=True`.
- **SSRF defence** — `/api/crypto/probe` validates the FQDN and protocol against an allowlist and rejects any target resolving to a private, loopback or metadata address *before* a socket is opened.
- **Error hygiene** — a global exception handler redacts stack traces behind a `correlation_id`; NXDOMAIN and resolver failures surface as generic 400/503 messages, with diagnostics written to the server log only. The frontend never renders a raw backend payload — it maps status codes to fixed, actionable copy.
- **Secrets** — no credentials are committed; all configuration arrives via environment variables. `.env`, `dist/`, `__pycache__/` and `.DS_Store` are git-ignored.
- **Supply chain** — Python dependencies are fully pinned in `requirements.txt` / `requirements.lock.txt` (including `certifi`, the CA bundle used when the platform trust store ships no roots); npm dependencies are exact-pinned with a committed `package-lock.json` installed via `npm ci`.

---

## Testing & Verification

```bash
cd backend && .venv/bin/python -m pytest -q        # 102 passed
cd frontend && npx tsc -b                          # exit 0 (strict mode)
cd frontend && npm run build                       # 1939 modules → dist/
```

Coverage highlights: DNS check contracts, TLS/STARTTLS probing, certificate validation (including the certifi trust-store fallback and wildcard/host-vs-apex SAN cases), forward-secrecy regression, fuzzy engine bounds & rescaling, risk-engine fusion, API auth/error paths, and PCAP forensics (stream reassembly, credential exposure, STARTTLS stripping, TLS/cert extraction, malformed captures).

**Live end-to-end verification** (`uvicorn`, `AEGIS_API_KEY=production-test-key`, `CORS_ORIGINS=http://localhost:5173`):

| Probe | Observed |
|---|---|
| `POST /api/scan` without a key | `401` + `WWW-Authenticate: ApiKey` |
| `OPTIONS` preflight from the allowed origin | `200`, origin echoed, credentials allowed |
| `POST /api/scan` unresolvable domain | `400` sanitised detail (reason only in server log, 0 tracebacks) |
| `POST /api/scan` `gmail.com` | `200`, full posture payload (see Scoring Model) |
| `POST /api/analyze-pcap` (+ alias) | `401` without key · `200` with key; cleartext credentials & STARTTLS stripping detected |

---

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app: auth middleware, CORS, 9 API routes (+ /, /health)
│   │   ├── models.py               # Pydantic v2 schemas
│   │   ├── active_scanner.py       # Scan orchestration (DNS + socket probes)
│   │   ├── resolver.py             # Public DNS resolver + TXT parsing helpers
│   │   ├── scoring.py              # Fuzzy scoring entry point, exposes rule trace
│   │   ├── ai_engine.py            # CVSS v3.1, remediation playbooks, optional Gemini
│   │   ├── pcap_analyzer.py        # PCAP forensics: streams, credentials, STARTTLS, TLS
│   │   ├── pdf_report.py           # ReportLab PDF dossier
│   │   ├── checks/                 # spf · dmarc · dkim · mx_starttls
│   │   ├── crypto/                 # tls_probe · cert_analyzer · cipher_evaluator · mail_discovery
│   │   ├── risk_engine/            # crypto_deprecation (CDI) · posture_exposure (PED)
│   │   │                           # exploitation_likelihood (ELI) · posture_risk (Tier-2 fusion)
│   │   ├── ai/                     # risk_scorer · anomaly_detector (Isolation Forest)
│   │   ├── pcap/                   # stream_reconstructor · tls_reconstructor
│   │   └── reports/html_report.py  # Standalone HTML forensic report
│   ├── tests/                      # 102 pytest cases
│   ├── requirements.txt            # Direct, exact-pinned dependencies
│   └── requirements.lock.txt       # Full resolved environment used in the image
├── frontend/
│   ├── src/
│   │   ├── App.tsx                 # Shell: scan orchestration, state, toasts, tabs
│   │   ├── api.ts                  # Axios client (X-API-Key, timeouts, PDF/PCAP helpers)
│   │   ├── types.ts                # Backend contract types
│   │   ├── scanMetrics.ts          # Derived metric helpers
│   │   ├── styles.css              # Design tokens + component layers
│   │   └── components/             # ThreatCenter · KeyProtocolCard · RemediationEngine
│   │                               # CryptoSessionsCard · EmailCredentialsCard · Sidebar
│   │                               # HeaderBar · ActiveReportCard · ActivityTrendCard
│   │                               # AuditVolumeCard · ChallengeRouteCard · DockedTerminal
│   │                               # CertificateInspectorModal · SecurityReportModal
│   │                               # SettingsModal · PcapForensicsView · Footer · Toast · Logo
│   ├── package.json                # Exact-pinned dependencies
│   └── nginx.conf                  # Reverse-proxy template used by the web image
├── Dockerfile                      # 3 stages: backend · frontend-build · nginx
├── docker-compose.yml              # api + web topology
└── README.md
```

> **Legacy modules:** `backend/app/pcap_engine/` and the frontend components `ProtocolMatrix.tsx`, `Terminal.tsx`, `TerminalDrawer.tsx` are no longer imported by the running application. They are retained for reference and are candidates for removal in a future cleanup.

---

## Network Resilience

**Residential ISP port-25 blocking.** Most consumer ISPs filter outbound port 25. AegisCrypta walks a multi-port sequence and, if every SMTP port is filtered, still extracts cryptographic capability via HTTPS SNI — live servers are never misclassified as insecure by an ISP policy:

```
25  SMTP + STARTTLS        → primary
587 Submission + STARTTLS  → fallback 1
465 Implicit SMTPS         → fallback 2
443 HTTPS SNI              → fallback 3 (TLS version, cipher, certificate)
```

**DNS resolution.** Queries bypass the local resolver and go straight to `8.8.8.8`, `1.1.1.1` and `9.9.9.9` (`timeout 2.0s`, `lifetime 4.0s`). `NXDOMAIN` fails the scan (an unresolvable domain scores as unreachable, never as "UNKNOWN"), while `NoAnswer` moves on to the next record type.

**Certificate validation portability.** When the platform trust store is empty (python.org framework builds, slim containers), the analyzer falls back to the bundled `certifi` root set so chain validation still works.

---

## License

Developed for **Smart India Hackathon 2026 — Problem Statement 159** under NTRO architecture standards. © 2026 Team Zero Gravity.
