# AegisCrypta — Evaluator & Judge Guide

**Problem Statement (SIH2026159):** *Assessing Cryptographic Posture for Mail Infrastructure.*
**Team:** Binayak Roy (Team Lead) — see `README.md` §Team.
**Repository:** `sih26159-aegiscrypta-core-zerogravity-FINAL`

This document is the scripted walkthrough for a live evaluation. Every value quoted below was
captured from a live run of this repository on **2026-09-29**; anything that varies with the
internet is marked as a point-in-time snapshot so no judge is ever shown a fabricated number.

---

## 0. What the system does in one paragraph

AegisCrypta audits the **cryptographic posture of mail infrastructure** end to end: it discovers
the mail path from DNS (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA), performs real
STARTTLS handshakes against the discovered gateways to extract the negotiated TLS version, cipher
suite, key exchange, forward secrecy and full X.509 chain, fuses those findings through a
**6-antecedent fuzzy inference engine**, maps them to **deterministic NIST/FIPS references**, and
finally lets an analyst replay a **passive packet capture** to prove what actually crossed the wire
— including cleartext credential exposure and certificate-level detail for traffic that was never
decrypted.

Everything it reports is derived from a live probe or a real packet; the platform has **no mock
data path**. When a target cannot be resolved or reached it returns an explicit, sanitised error
instead of inventing a result (demonstrated in Step 3 below).

---

## 1. Problem statement — why mail infrastructure

| Reality | Consequence | AegisCrypta's answer |
|---|---|---|
| Mail gateways negotiate TLS silently | Nobody knows if STARTTLS is actually enforced or stripped | Active STARTTLS probes of every MX on the discovered path |
| TLS 1.0/1.1 and 1024-bit RSA still live in the wild | Traffic is decryptable today | **CDI** — Crypto Deprecation Index (NIST SP 800-52r2 / SP 800-57) |
| SPF/DKIM/DMARC are misconfigured far more often than absent | Spoofing and phishing succeed | **PED** — Posture Exposure Deficit across six DNS controls |
| Post-quantum migration is 5–10 years out, harvesting is happening now | Recorded mail is decryptable later ("store-now-decrypt-later") | PQC readiness antecedent + **ML-KEM-768 / FIPS 203** guidance |
| Auditors need proof, not a checklist score | Findings get argued away | Fuzzy rule trace (`activated_rules`) + passive PCAP ground truth |

---

## 2. Live Demo Script

### 2.0 Bring the stack up (2 minutes)

```bash
# Terminal 1 — backend
cd backend && AEGIS_API_KEY="sih-demo-key" CORS_ORIGINS="http://localhost:5173" \
  uvicorn app.main:app --port 8000

# Terminal 2 — frontend
cd frontend && npm run dev        # http://localhost:5173
```

In the dashboard, open **Settings** and confirm:

* **API base URL** = `http://localhost:8000`
* **API key** = `sih-demo-key` (the same value passed to `AEGIS_API_KEY`)

> Why this matters: the API rejects every `/api/*` request without the key, and it refuses to
> serve **anything** (`503`) if `AEGIS_API_KEY` is unset. Demonstrating that gate is part of the
> security story — see Step 3.

**Suggested theme for the projector:** *Settings → Visual Theme → Pure Black* (true `#000000` OLED
canvas, maximum projector contrast). *Deep Dark* is the navy SOC default; *Slate Light* is the
daylight/print view. All three are visually distinct and switch instantly.

---

### 2.1 Step 1 — `gmail.com`: the "well-run but not perfect" reference

Type `gmail.com` into the audit bar and press **RUN AUDIT**.

| Field | Observed value (live, 2026-09-29) |
|---|---|
| Deterministic posture score | **50 / 100** |
| `fuzzy_score` | 50.1 |
| `linguistic_classification` | **ACCEPTABLE** |
| CVSS v3.1 | **5.3 MEDIUM** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| Checks | `SPF pass · DKIM pass · DMARC warn · MTA-STS pass · TLS-RPT pass · DANE/TLSA warn` |
| Top findings | SNDL quantum exposure (MEDIUM); DMARC in monitoring mode `p=none` (MEDIUM) |
| Protocols audited | `SMTP` (multiple MX hosts) |

**Narration:** "This is a globally hardened provider — TLS 1.2+, strong ciphers, SPF and DKIM
passing, MTA-STS enforced. It still cannot reach the top band, and the reason is visible in the
evidence, not hidden in the score: DMARC is published as `p=none`, so an attacker can still spoof
the domain and only be *monitored*, not rejected. The engine also flags every classical key
exchange as harvestable for store-now-decrypt-later. So a 50 is not a bug — it is an accurate
reading of a real, publishable weakness."

**Judge-facing point:** the score is decomposed on screen into `antecedent_scores`
(`tls_compliance`, `cipher_strength`, `certificate_health`, `pqc_readiness`,
`email_auth_posture`, `exploitation_likelihood`) plus the exact fuzzy rule trace
(`activated_rules`) and `defuzzification_confidence`. Nothing is a black box.

---

### 2.2 Step 2 — `rcciit.edu.in`: the "typical institutional domain"

Run the audit again with `rcciit.edu.in`.

| Field | Observed value (live, 2026-09-29) |
|---|---|
| Deterministic posture score | **12 / 100** |
| `fuzzy_score` | 12.7 |
| `linguistic_classification` | **CRITICAL** |
| CVSS v3.1 | **7.5 HIGH** |
| Checks | `SPF pass · DKIM pass · DMARC fail · MTA-STS warn · TLS-RPT warn · DANE/TLSA warn` |
| Top findings | **Missing DMARC Protection (HIGH)**; SNDL quantum exposure (MEDIUM) |
| Protocols audited | `SMTP` |

**Narration:** "Same scanner, dramatically different result — and the headline jumps from
ACCEPTABLE to CRITICAL because of a single missing control. SPF and DKIM are published, but with
no DMARC record, a receiver has nothing to bind the two together: any attacker can send mail *as*
this domain and there is no policy telling the world what to do about it. This is the
non-dilution guarantee in action — the weak axis is not averaged away by the strong SPF/DKIM
results. The Remediation Engine immediately produces a copy-pasteable DNS record and a
`p=reject` cut-over plan."

**Judge-facing point:** this is the most common real-world finding in Indian academia, and the
platform converts it into a fix, not just a verdict. The remediation playbook emits provider-ready
config (Postfix TLS hardening per NIST SP 800-52r2, Exim, Sendmail, BIND zone snippets).

---

### 2.3 Step 3 — `defense.gov.in`: the honesty demonstration

Run the audit with `defense.gov.in`.

**Observed behaviour:** the API returns **HTTP 400** with a sanitised detail message:

```json
{"detail": "Domain resolution failed or unreachable."}
```

The backend log records the reason server-side; the client only ever sees the sanitised string.
`defense.gov.in` **does not exist in public DNS** — the real Government of India defence namespace
is not what a `.gov.in` guess produces.

**Narration (this is a strength, not a failure):** "We deliberately demo a domain that cannot be
resolved. A security scanner that returns a plausible-looking score for a host it never reached is
worse than useless — it is dangerous. AegisCrypta failed closed: no resolution, no inference, no
fabricated risk. Every check in the product follows the same rule: a value is reported only when
it was actually observed."

Then, with the backend still running, delete the key from the header (or use Swagger with the
*Authorize* box cleared) and re-issue one request to show the **401** gate:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' -d '{"domain":"gmail.com"}'
# → 401
```

---

## 3. Passive PCAP Forensics — `samples/aegis_demo_smtp.pcap`

### 3.1 The sample capture

`samples/aegis_demo_smtp.pcap` is committed to the repository so no judge has to supply their own
traffic. It is a single SMTP conversation that performs a **clean STARTTLS upgrade**:

```
S >  220 mail.aegis-demo.test ESMTP Postfix
C >  EHLO client.aegis-demo.test
S >  250-mail.aegis-demo.test ... 250-STARTTLS ... 250 OK
C >  STARTTLS
S >  220 2.0.0 Ready to start TLS
C >  TLS ClientHello   (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256)
S <  TLS ServerHello   (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256)
```

* 12 packets · 1 TCP stream · 1,159 bytes
* Addresses come from the RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`) —
  **no real host is referenced anywhere in the file**

Regenerate it at any time (deterministic output):

```bash
backend/.venv/bin/python samples/generate_demo_pcap.py --check
```

`--check` regenerates the capture and immediately runs the production analyzer over it.

### 3.2 The demo

1. In the sidebar open **Cryptographic Sessions** (or click the chevron on the *Audit Volume · Core
   Inquiries* card). The view is headed *Passive PCAP Network Forensics & Stream Reassembly*.
2. Drag `samples/aegis_demo_smtp.pcap` onto the drop zone titled *"Ingest .pcap or .pcapng Network
   Packet Capture"* (accepts `.pcap`, `.pcapng`, `.cap`).
3. Walk the results top to bottom.

**Expected, verified output:**

| Field | Value |
|---|---|
| `total_packets` | 12 |
| `total_tcp_streams` | 1 |
| `identified_protocols` | `["SMTP"]` |
| `streams[0].starttls_detected` | **`true`** |
| `streams[0].tls_handshake_detected` | `true` |
| `streams[0].tls_version` | `TLSv1.2` |
| `streams[0].cipher_suite` | `ECDHE-RSA-AES128-GCM-SHA256` |
| `streams[0].findings` | SNDL quantum exposure (MEDIUM) |
| `summary_findings` | CRITICAL *fuzzy* assessment · MEDIUM SNDL · LOW DNS-assumption disclosure · INFO "No X.509 Certificate Observed in Capture" |

### 3.3 Explaining the aggregate verdict — say this out loud

The per-stream row (the ground truth for *this* capture) is healthy: the session **was** upgraded
and the TLS parameters are modern. The aggregate fuzzy verdict still lands on **CRITICAL**, and the
product tells you exactly why instead of hiding it:

> *A passive capture cannot observe DNS authentication posture. The fused score assumes SPF, DKIM,
> DMARC enforcement and DNSSEC are all absent, and that conservative assumption dominates the PED
> axis.*
> — surfaced as the **LOW** finding *"Fused Score Relies on an Unverifiable DNS Assumption"*

**Narration:** "Read the stream row for what the capture proves, and the aggregate for what an
unknown-DNS mail path could mean. The engine refuses to report a comfortable number it cannot
justify — if it cannot see DNS, it says so, in the findings list, in plain English."

The other two findings are equally deliberate: **INFO — No X.509 Certificate Observed** because the
capture stops at ServerHello (the Certificate message was never recorded), and **MEDIUM — SNDL**
because ECDHE is classical asymmetric key exchange. Both are accurate, capture-scoped statements.

### 3.4 Why this matters

The capture ends immediately after ServerHello, so the session payload after that point is
encrypted and unreadable — by design. AegisCrypta still reports the negotiated protocol version,
the exact cipher suite, the STARTTLS upgrade, and the certificate evidence status. **No decryption
is performed, no key material is derived, and no private key is ever required.** Pair this with the
cleartext-credential detector (which fires a HIGH finding when `AUTH PLAIN` / `LOGIN` credentials
appear before STARTTLS) to show both halves of the story: proof of upgrade, and proof of failure to
upgrade.

---

## 4. Core Innovation

### 4.1 The Fuzzy Risk Engine — six antecedents, three composites, one fusion

A checklist produces "7 of 10 controls pass". That number is meaningless when the three failures
are trivial and the one gap is a missing DMARC record on a bank. AegisCrypta instead models risk
the way an auditor reasons.

**Tier 1 — three composite indices** (`backend/app/risk_engine/`):

| Composite | Measures | Reference basis |
|---|---|---|
| **CDI** — Crypto Deprecation Index | TLS version, cipher strength, key algorithm/size, certificate health & validity window, forward secrecy | NIST SP 800-52r2, NIST SP 800-57 Pt.1 Rev.5, RFC 8996, CA/B Forum BR |
| **PED** — Posture Exposure Deficit | SPF, DKIM, DMARC policy **and** enforcement, MTA-STS, TLS-RPT, DANE/TLSA | RFC 7208, 6376, 7489, 8461, 8460, 6698 |
| **ELI** — Exploitation Likelihood Index | Known-vulnerable banner versions (CVE correlation), exposure, asset criticality | NIST NVD |

**Tier 2 — posture risk fusion** (`posture_risk.py`) merges the composites with a Mamdani-style
fuzzy rule base across **six antecedents** — `tls_compliance`, `cipher_strength`,
`certificate_health`, `pqc_readiness`, `email_auth_posture`, `exploitation_likelihood` — into the
Posture Risk Index and a linguistic band:

| Band | Posture Risk | Classification |
|---|:---:|---|
| Excellent | 0–20 | `EXCELLENT` |
| Good | 20–40 | `GOOD` |
| Acceptable | 40–60 | `ACCEPTABLE` |
| Poor | 60–80 | `POOR` |
| Critical | 80–100 | `CRITICAL` |

**The non-dilution OR rule:** if *any* single composite is High (expired certificate, TLS 1.0,
unenforced DMARC), the CRITICAL tier is forced regardless of the others. One severe weakness can
never be averaged away — which is exactly the `gmail.com` (50, ACCEPTABLE) vs `rcciit.edu.in`
(12, CRITICAL) contrast in Step 2.

**Explainability:** every response carries `antecedent_scores`, the exact `activated_rules` trace
with activation strengths, and `defuzzification_confidence`. The reasoning is auditable evidence,
not a model's opinion.

### 4.2 Deterministic NIST/FIPS compliance layer

Fuzzy inference decides *how bad*; a deterministic rule layer decides *what is compliant*. These
are deliberately separated so a regulatory question always has a binary, citable answer:

| Control | Deterministic rule | Source |
|---|---|---|
| Protocol version | TLS 1.2 acceptable, TLS 1.3 preferred, 1.0/1.1 deprecated | NIST SP 800-52r2, RFC 8996 |
| Key strength | ECC ≥ 256-bit, RSA ≥ 2048-bit (≥ 3072 recommended) | NIST SP 800-57 Pt.1 Rev.5 |
| Certificate policy | Validity window, chain validation to a public root, signature algorithm (SHA-1/MD5 rejected) | CA/B Forum BR, NIST SP 800-52r2 |
| PQC readiness | Classical KEX ⇒ SNDL exposure; hybrid X25519+ML-KEM-768 recommended | NIST FIPS 203 (ML-KEM) |
| Remediation output | Generated Postfix/Exim/Sendmail/BIND config | RFC 8461, NIST SP 800-52r2 |

### 4.3 AI telemetry and the analyst console

The findings above are translated into operator language by the remediation layer
(`backend/app/ai_engine.py`): prioritised findings with severity, CVSS v3.1 vector and score, a
provider-ready remediation playbook, session anomaly detection, and (for `gmail.com`) an
`ai_risk_score` with the contributing signals. On the dashboard this renders as the Threat Center
speedometer, the CVSS explainability grid and the live inference telemetry strip — the numbers on
screen are the numbers in the JSON, with the same rounding.

---

## 5. Interactive API Testing (Swagger)

Every capability in this guide is reachable from the live OpenAPI console:

**→ http://localhost:8000/docs**

*(Requires the backend to be running — see §2.0. The same link is one click away inside the app:
Sidebar → **API Inspector (Swagger)**, and the Certificate Inspector modal → **Inspect Raw API
Schema**.)*

Click **Authorize**, paste the `AEGIS_API_KEY` value, and you can drive:

| Method | Path | What to demo |
|---|---|---|
| `POST` | `/api/scan` | The full domain audit behind Steps 1–3 |
| `POST` | `/api/crypto/probe` | A single STARTTLS probe against one host/port/protocol |
| `POST` | `/api/analyze-pcap` | Upload `samples/aegis_demo_smtp.pcap` directly from Swagger |
| `POST` | `/api/export-pdf` | Print-ready dossier for a scanned domain |
| `POST` | `/api/scan/html` | Self-contained HTML report |
| `POST` | `/api/scan/forensic` | Forensic bundle for the security team |
| `GET` | `/health` | Liveness probe (unauthenticated) |

---

## 6. Two-minute closing summary

> "Mail is where trust is asserted and, too often, where it breaks. AegisCrypta replaces the
> checklist with a reasoning engine: it discovers the real mail path, speaks STARTTLS to every
> gateway, fuses six antecedents through a fuzzy rule base that cannot be diluted, pins every
> verdict to a NIST or FIPS reference, and hands the analyst a packet capture as ground truth. It
> reports 50 and ACCEPTABLE for a hardened provider with a monitoring-only DMARC policy, 12 and
> CRITICAL for a university with no DMARC policy at all, and it refuses to invent a number for a
> domain it cannot resolve. Every value you have seen came from a live probe or a real packet."

---

## 7. Verification evidence (reproduce in ~3 minutes)

```bash
# 1. Backend test suite — the full check matrix
cd backend && .venv/bin/python -m pytest -q                    # → 102 passed

# 2. Frontend production build
cd frontend && npx tsc -b && npm run build                     # → 0 TS errors, dist/ emitted

# 3. Deterministic PCAP sample + analyzer self-check
backend/.venv/bin/python samples/generate_demo_pcap.py --check  # → SMTP, STARTTLS=true, 1 stream

# 4. Auth gate
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' -d '{"domain":"gmail.com"}'   # → 401 without X-API-Key

# 5. Unresolvable target fails closed
curl -s -X POST http://localhost:8000/api/scan -H 'Content-Type: application/json' \
  -H 'X-API-Key: sih-demo-key' -d '{"domain":"defense.gov.in"}'     # → 400 sanitised detail
```

---

## 8. Likely judge questions

**"Your PCAP sample says CRITICAL — is that a false positive?"**
No: it is a *conservative* fusion, disclosed in the findings list. The per-stream row shows the
session was correctly detected as STARTTLS-protected TLS 1.2 with a modern cipher. The aggregate
assumes worst-case DNS authentication because a passive capture cannot observe DNS. The finding
tells the analyst to read the stream row for what the capture proves — §3.3.

**"Did you decrypt the traffic?"**
No decryption, no key material, no MITM. We read unencrypted control plane (SMTP handshake, TLS
record headers, certificate messages when present) and report a HIGH finding when credentials
appear *before* STARTTLS — which is exactly the failure we are trying to detect.

**"How is this different from SSL Labs or a DMARC lookup tool?"**
Those answer one question each. This fuses transport crypto, DNS authentication posture,
exploitation likelihood and post-quantum readiness into a single non-dilutable verdict, ties every
rule to a NIST/FIPS citation, generates the fix, and proves the finding against captured traffic.

**"Why does a perfect TLS setup still score 50?"**
Because classical key exchange is harvestable today and decryptable by a future CRQC. PQC readiness
is an explicit antecedent, so "perfect 2020 crypto" is honestly scored as *not yet future-proof*.

**"What happens if the target is offline or unreachable?"**
Fail-closed, always: a sanitised `400 Domain resolution failed or unreachable.` The reason is logged
server-side only; no partial or inferred score is ever returned — Step 3.

---

*Prepared for SIH evaluation. All live values in this document were observed on 2026-09-29 against
the running stack; re-run §2–§3 on the day of judging and quote what you see.*
