# AegisCrypta Forensics Engine
## Comprehensive Security & Quality Audit Report
### Audit Delta: Post-Fuzzy Logic Integration Review

---

| Field | Value |
|---|---|
| **Audit Date** | September 25, 2026 |
| **Audit Type** | Read-Only Code Review & Architecture Analysis |
| **System Version** | AegisCrypta v2.4.0 (SIH2026159 / NTRO Architecture Standards) |
| **Scope** | Full-stack: Backend (Python/FastAPI) + Frontend (React/TypeScript) |
| **Focus** | Hierarchical Fuzzy Logic Risk Scoring Engine — Tier 1 & Tier 2 FIS |
| **Auditor Role** | Senior Software Auditor & Security Analyst |
| **Classification** | INTERNAL — AUDIT REPORT |

---

## Executive Summary

The addition of the four-module hierarchical fuzzy inference system (CDI → PED → ELI → Posture Risk fusion) represents a meaningful architectural upgrade from the prior penalty-subtraction scoring model. The design is well-referenced, technically coherent, and appropriately documented. Rule bases correctly implement non-dilution semantics for critical findings via OR-fusion in the Tier 2 system.

However, the audit identifies **one Critical-severity vulnerability** (unauthenticated SSRF) and **four High-severity issues** that existed in or were compounded by the fuzzy logic addition. These require remediation before any internet-accessible deployment. Three architectural gaps in the fuzzy engine itself limit its statistical validity and will produce misleading scores under specific edge-case inputs.

---

## Table of Contents

1. [Backend Implementation — Fuzzy Logic Quality Assessment](#1-backend-implementation--fuzzy-logic-quality-assessment)
2. [Frontend Configuration & Integration Assessment](#2-frontend-configuration--integration-assessment)
3. [Vulnerability & Security Assessment](#3-vulnerability--security-assessment)
4. [Audit Delta — Comparison Against Previous Baseline](#4-audit-delta--comparison-against-previous-baseline)
5. [Finding Summary Table](#5-finding-summary-table)
6. [Remediation Priority Order](#6-remediation-priority-order)

---

## 1. Backend Implementation — Fuzzy Logic Quality Assessment

### 1.1 Architecture Overview

The fuzzy risk engine is structured as a two-tier Mamdani inference hierarchy:

```
Tier 1 (parallel):
  CDI  — Crypto Deprecation Index       (tls_version, cipher, key_length, cert_validity, forward_secrecy)
  PED  — Posture Exposure Deficit       (spf, dkim, dmarc_policy, dnssec)
  ELI  — Exploitation Likelihood Index  (reachability, software_vulnerability, asset_criticality)

Tier 2 (fusion):
  Posture Risk Index ← f(CDI, PED, ELI) → [0–100] + 5-tier linguistic classification
```

The choice of Mamdani inference (versus Takagi-Sugeno) is appropriate for this domain: it produces interpretable linguistic output sets and supports the human-readable rule-firing explanations surfaced in the frontend.

---

### 1.2 Strengths

**Standard Alignment.**
Cipher classifications are sourced from Mozilla TLS v5.7; key length thresholds from NIST SP 800-57 Rev. 5; TLS version deprecation from RFC 8996 and NIST SP 800-52r2. This is accurate and audit-defensible.

**Membership Function Design.**
The use of trapezoidal MFs for plateau/boundary sets (Old, Weak, Strong) and triangular MFs for transitional states (Moderate) is the canonical design for this type of classification problem. Overlapping regions in the `[0.4–0.9]` and `[1.1–1.6]` ranges for 3-label antecedents are well-calibrated for smooth gradients.

**Non-Dilution Principle (Rule 12 in Tier 2).**
The OR rule `CDI High | PED High | ELI High → CRITICAL` correctly prevents a single catastrophic weakness (e.g., TLS 1.0, `p=none` DMARC) from being diluted by unrelated strong results. This is a sound security-domain design choice, explicitly documented in the source.

**Explainability Layer.**
Computing manual membership degrees before running `sim.compute()` serves two purposes: it enables the explainability output (firing strengths returned to the frontend), and it avoids sole dependency on scikit-fuzzy's internal state for diagnostics. This is good engineering.

**Graceful Fallback.**
All four FIS modules wrap `sim.compute()` in a `try/except` that returns a mid-range default (CDI: 50.0, PED: 50.0, ELI: 30.0, Posture Risk: 50.0). The varying default values reflect domain-appropriate conservatism (ELI defaults lower because *unknown* does not imply *exploitable*).

---

### 1.3 Deficiencies & Risks

#### DEF-01 — Empirical Rescaling Constants Are Hard-Coded Without Justification

| | |
|---|---|
| **Severity** | MEDIUM |
| **Location** | `backend/app/risk_engine/posture_risk.py` |

The raw centroid output of the Mamdani system is rescaled to `[0, 100]` using hard-coded boundary values:

```python
RAW_MIN = 7.7778
RAW_MAX = 92.3525
```

These constants are labeled as derived from "actual rule base centroid defuzzification limits," but there is no accompanying derivation, unit test fixture, or calibration script to verify or regenerate them. If any rule, MF shape, or universe resolution changes, these constants silently become incorrect, producing scores that are systematically off without any error signal.

**Recommendation:** Add a calibration test (`test_fuzzy_rescaling.py`) that programmatically verifies `RAW_MIN` and `RAW_MAX` by running the FIS with all-low inputs and all-high inputs respectively. The constants should be either computed at startup or tested to match expected bounds within a small tolerance.

---

#### DEF-02 — DNSSEC Detection Is Incorrect

| | |
|---|---|
| **Severity** | MEDIUM |
| **Location** | `backend/app/scoring.py` |

DNSSEC status is inferred from the DANE/TLSA check's `details["dnssec"]` field:

```python
if dane and dane.status == CheckStatus.PASS:
    details = dane.details if isinstance(dane.details, dict) else {}
    dnssec_enabled = "enabled" in str(details.get("dnssec", "")).lower()
```

A domain can have TLSA records without DNSSEC, and a DANE check PASS does not guarantee the `"dnssec"` key is populated. In practice, if the active scanner does not explicitly query for `DNSKEY`/`RRSIG`, `dnssec_enabled` will always be `False`. This renders the DNSSEC antecedent in the PED FIS inoperational.

**Recommendation:** The active scanner (`active_scanner.py`) should set a dedicated `dnssec_validated` flag when a DNSKEY/RRSIG chain is confirmed. The `scoring.py` extractor should read from this explicit field.

---

#### DEF-03 — PQC Readiness Is a Hardcoded Placeholder

| | |
|---|---|
| **Severity** | LOW *(documented as known future work)* |
| **Location** | `backend/app/scoring.py` |

```python
pqc_readiness = 0.5
```

The `pqc_readiness` antecedent score is unconditionally set to `0.5` for every domain. The `cipher_evaluator.py` module correctly detects PQC hybrid key exchange (`c.pqc_hybrid = True`) but this flag is never wired into the fuzzy antecedent. Every domain receives an identical PQC score and the PQC bar in the frontend always displays 50%.

**Recommendation:** Wire `has_pqc` (already computed in `calculate_posture_score`) into `pqc_readiness`: `1.0` if PQC hybrid detected, `0.1` if classical-only.

---

#### DEF-04 — ELI's Static CVE Table Has No TTL or Version Gate

| | |
|---|---|
| **Severity** | HIGH |
| **Location** | `backend/app/risk_engine/exploitation_likelihood.py` |

The `VULNERABLE_SERVERS` lookup table's newest entry is `CVE-2020-28007` (Exim 21Nails, 2020). Six years of CVEs are absent — including Exim CVE-2023-42115 (CRITICAL, CVSS 9.8) and Exchange ProxyLogon/ProxyShell. A server running Exim 4.96 will return `vuln_ordinal=0` (Safe) and contribute a low ELI score, producing false security assurance.

**Recommendation:**
- Add a `LAST_UPDATED` date constant and emit a log warning if it exceeds 90 days from the current date.
- Expand the table with post-2020 CVE entries at minimum.
- Long-term: integrate NVD API or a maintained CVE feed as already documented in the source.

---

#### DEF-05 — Rule Coverage Gap in CDI for Mixed Moderate/No-FS State

| | |
|---|---|
| **Severity** | LOW |
| **Location** | `backend/app/risk_engine/crypto_deprecation.py` |

The standalone rule `fs_input['no'] → CDI high` means that any domain without forward secrecy — including one running TLS 1.2 with a strong RSA cipher and a valid certificate — triggers `CDI high`. Combined with Rule 12 in Tier 2 (`CDI high → CRITICAL`), a TLS 1.2 + ECDHE-less + valid cert + full DMARC reject domain receives a CRITICAL classification, overstating risk relative to NIST SP 800-52r2 definitions for transitional environments. No rule path exists from `fs_no + moderate/strong other inputs` to `CDI moderate`.

**Recommendation:** Add a rule: `tls_input['strong'] & cipher_input['strong'] & key_input['strong'] & cert_input['strong'] & fs_input['no'] → CDI moderate`.

---

#### DEF-06 — `defuzzification_confidence` Is Unconditionally Hardcoded

| | |
|---|---|
| **Severity** | LOW |
| **Location** | `backend/app/scoring.py` |

```python
defuzzification_confidence = 0.88
```

Every scan returns confidence `0.88` regardless of whether the fuzzy simulation fell back to a default value due to an exception, or produced a full multi-rule activation. This number is displayed in the frontend and creates a false impression of consistent high confidence.

**Recommendation:** Compute confidence from activated rule firing strengths (e.g., `max(firing_strengths)` or normalized sum of activations). Return `0.0` or `None` when the fallback default is used.

---

### 1.4 Performance

The four control systems are compiled once at module load time via module-level singleton initialization (`_CDI_SYSTEM`, `_PED_SYSTEM`, `_ELI_SYSTEM`, `_RISK_SYSTEM`). This is the correct pattern — scikit-fuzzy `ControlSystem` compilation is expensive (MF evaluation across universe grids) and should not be repeated per request. Each request creates a new `ControlSystemSimulation`, which is also correct as simulations are not thread-safe for concurrent input assignment.

The manual membership degree pre-computation adds approximately 4× the membership evaluations per request, but all operations are vectorized via NumPy and the overhead is negligible relative to DNS resolution and socket I/O.

> **No performance concerns identified for current expected load.**

---

## 2. Frontend Configuration & Integration Assessment

### 2.1 Fuzzy Score Consumption — Correct

`ThreatCenter.tsx` correctly prefers the fuzzy score over the legacy score:

```typescript
const effectiveScore = fuzzyScore ?? score;
```

The gauge needle, color zones, and risk label all update from this value. The six antecedent bars (`tls_compliance`, `cipher_strength`, `certificate_health`, `pqc_readiness`, `email_auth_posture`, `exploitation_likelihood`) are mapped from `antecedent_scores` with inversion applied correctly for ELI (`1 - eli` so that `1.0 = safe`). Activated rules are displayed in an expandable panel with raw strings from the backend.

---

### 2.2 Type Contract Alignment

`frontend/src/types.ts` defines `ScanResponse` with the six fuzzy extension fields as optional:

```typescript
fuzzy_score?: number;
linguistic_classification?: 'EXCELLENT' | 'GOOD' | 'ACCEPTABLE' | 'POOR' | 'CRITICAL';
antecedent_scores?: {
  tls_compliance: number;
  cipher_strength: number;
  certificate_health: number;
  pqc_readiness: number;
  email_auth_posture: number;
  exploitation_likelihood: number;
};
activated_rules?: string[];
defuzzification_confidence?: number;
```

These match the backend `ScanResponse` Pydantic model fields exactly. The `PcapAnalysisResponse` TypeScript type also includes fuzzy extension fields consistent with the backend model.

> **No type misalignment found.**

---

### 2.3 Missing Integration: `cvss_metrics` and `remediation_playbook`

`ScanResponse` in `types.ts` includes `cvss_metrics` and `remediation_playbook`, and the backend always returns them. However, neither field is consumed in `ThreatCenter.tsx` or any component reviewed during this audit. The CVSS vector string and base score are present in the data but not rendered in the UI.

| | |
|---|---|
| **Severity** | LOW *(functional gap, not a security issue)* |
| **Recommendation** | Confirm whether a dedicated CVSS component exists among unreviewed components. If not, add a CVSS metrics card alongside the remediation playbook display. |

---

### 2.4 `scanDomain()` Does Not Send `is_customer_facing`

| | |
|---|---|
| **Severity** | MEDIUM |
| **Location** | `frontend/src/api.ts` |

```typescript
// Current implementation — missing is_customer_facing
const res = await apiClient.post<ScanResponse>('/api/scan', { domain }, ...);
```

The `ScanRequest` Pydantic model has `is_customer_facing: bool = False` which directly gates the ELI criticality antecedent (`customer-facing → crit_num = 1.0` vs. neutral `0.5`). The frontend API call never passes this parameter — every scan runs with the default `False`, which maps to `crit_num = 0.0` (internal), not the documented neutral `0.5`. This means the ELI antecedent systematically underestimates criticality for internet-facing assets.

**Recommendation:** Update `scanDomain(domain: string, isCustomerFacing: boolean = false)` to pass `{ domain, is_customer_facing: isCustomerFacing }`. Expose a checkbox in the scan input UI to allow the user to flag customer-facing assets.

---

### 2.5 Error Detail Exposure in Frontend

| | |
|---|---|
| **Severity** | MEDIUM |
| **Location** | `frontend/src/App.tsx`, `backend/app/main.py` |

`App.tsx` surfaces backend error details from `err.response.data?.detail` directly in toast notifications and the terminal log. Because the global exception handler in `main.py` returns raw Python exception messages in `"detail"`, internal stack traces or filesystem paths can appear in the user-facing terminal.

**Recommendation:** In `App.tsx`, use a generic user-facing message and log the raw detail to `console.error` only. In `main.py`, sanitize `"detail"` to exclude stack frames and internal paths before including in the HTTP response.

---

## 3. Vulnerability & Security Assessment

### VULN-01 — Server-Side Request Forgery (SSRF) via `/api/crypto/probe`

| | |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Location** | `backend/app/main.py`, `backend/app/models.py`, `backend/app/crypto/tls_probe.py` |
| **CVSS v3.1 Estimate** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N — **9.3** |

The `CryptoProbeRequest` model accepts a `host` field with **no validation**. Any string — including `127.0.0.1`, `10.0.0.1`, `192.168.x.x`, `169.254.169.254` (AWS/GCP/Azure metadata endpoint), or `localhost` — is accepted and results in a real TCP socket connection from the server. The probe performs a full SMTP/IMAP/POP3 handshake and returns the server banner and TLS telemetry to the caller.

**Attack Surface:**
- Enumerate internal network services by probing private IP ranges on arbitrary ports (1–65535)
- Read cloud instance metadata (port 80, `169.254.169.254`) via banner extraction
- Probe internal admin panels, databases, and services not exposed to the internet
- Exfiltrate partial response content through banner fields in the JSON response

> **No authentication is required to trigger this endpoint.**

**Recommendation:**
1. Validate `host` against a strict FQDN-only pattern: `r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"`
2. Reject RFC 1918, loopback, link-local, and metadata service addresses before socket creation
3. Validate `protocol` against an allowlist: `{"smtp", "imap", "pop3"}`
4. Add authentication (API key or session token) to this endpoint

---

### VULN-02 — No Authentication on Any Endpoint

| | |
|---|---|
| **Severity** | 🔴 HIGH |
| **Location** | `backend/app/main.py` — all routes |

Every endpoint — including the SSRF-capable probe, PCAP upload, PDF export, and full forensic scan — is publicly accessible with zero authentication or authorization. The CORS policy (`allow_origins=["*"]`) compounds this: any web page can make cross-origin requests to the API on behalf of a visiting user's browser.

**Recommendation:** Implement API key authentication as a minimum. For deployment scenarios, add rate limiting per IP. At minimum, bind the service to `127.0.0.1` in non-production environments and document the requirement explicitly.

---

### VULN-03 — Internal Exception Leakage via Global Error Handler

| | |
|---|---|
| **Severity** | 🔴 HIGH |
| **Location** | `backend/app/main.py → global_exception_handler` |

```python
content={
    "error": "Internal Server Error",
    "detail": str(exc)   # ← raw Python exception string returned to client
}
```

Raw Python exception messages are returned to HTTP clients. These can contain filesystem paths (e.g., `/app/backend/app/risk_engine/crypto_deprecation.py`), internal hostnames, module names, and in some cases partial variable values. This is information disclosure that aids reconnaissance.

**Recommendation:** Return a generic error reference ID to the client; log the full exception server-side with a correlation ID. Never serialize `str(exc)` into HTTP responses in production.

---

### VULN-04 — Domain Interpolation into Shell Scripts Without Escaping + Incorrect TLSA Placeholder

| | |
|---|---|
| **Severity** | 🔴 HIGH |
| **Location** | `backend/app/ai_engine.py → generate_syntax_checked_remediations()` |

The validated domain string is interpolated directly into a bash script without shell escaping:

```python
shell_script = f"""...
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/{domain}.crt"
...
systemctl reload postfix"""
```

While the domain is validated against a strict regex, the security posture of the generated playbook depends entirely on the upstream validator remaining correct in perpetuity. Applying `shlex.quote()` provides defense-in-depth.

Additionally, the `bind_dns_zone` template includes a **hardcoded SHA-256 TLSA fingerprint** (`5a7f328b...`) — a non-functional placeholder. Using it verbatim would configure an **incorrect DANE record on production servers**, actively breaking DANE validation for real deployments. This is a correctness failure in a security-critical configuration artifact.

**Recommendation:**
1. Apply `shlex.quote(domain)` to all shell script interpolation points
2. Replace the hardcoded TLSA fingerprint with an explicit `<REPLACE_WITH_ACTUAL_CERT_FINGERPRINT>` placeholder and add a prominent warning comment

---

### VULN-05 — Untrusted Gemini AI Response Parsed Without Sanitization

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Location** | `backend/app/ai_engine.py` |

The Gemini API response is parsed with naive JSON extraction and the resulting config strings are inserted directly into the `RemediationPlaybook` object:

```python
json_str = cleaned_text[cleaned_text.find("{"):cleaned_text.rfind("}") + 1]
parsed = json.loads(json_str)
playbook = RemediationPlaybook(
    postfix_main_cf=parsed.get("postfix_main_cf", playbook.postfix_main_cf),
    ...
)
```

The findings passed to Gemini include `f.description` values derived from external DNS records (e.g., raw SPF or DMARC record content), which could contain injected strings. If the Gemini model is manipulated via prompt injection, adversarial configuration directives could be returned to the user as legitimate remediation steps.

**Recommendation:**
1. Sanitize all values extracted from external DNS records before inserting into the Gemini prompt
2. Apply length limits and character allowlists to Gemini-returned config strings
3. Mark AI-generated configs visually distinct from verified static configs in the frontend

---

### VULN-06 — PCAP Temporary File Cleanup Not Guaranteed

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Location** | `backend/app/pcap_analyzer.py` |

```python
with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
    tmp.write(contents)
    tmp_path = tmp.name
```

PCAP files containing cleartext credentials and mail content are written to disk with `delete=False`. If the server process crashes between write and delete, or if the filesystem is shared (e.g., a container with mounted volumes), the PCAP may persist indefinitely. Cleanup depends on the code path reaching the `os.unlink()` call.

**Recommendation:** Use a `try/finally` block guaranteeing cleanup. For small captures, consider `tempfile.SpooledTemporaryFile` to keep data in memory and only spill to disk when size exceeds a threshold.

---

### VULN-07 — No Dependency Version Pinning (Supply Chain Risk)

| | |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Location** | `backend/requirements.txt`, `frontend/package.json` |

All backend dependencies use open `>=` lower bounds. All frontend dependencies use `"latest"`. This means both a developer `pip install` and a container build can silently resolve to a newer, potentially breaking or vulnerable version of any dependency. `scikit-fuzzy>=0.4.2` is of particular concern — it is a low-activity library and any future breaking change would silently break all four FIS modules with no version pin to roll back to.

**Recommendation:** Pin all dependencies to exact versions or use a lock file (`pip freeze > requirements.lock`, committed `package-lock.json`). At minimum, pin `scikit-fuzzy==0.4.2` and `numpy` immediately.

---

### VULN-08 — `verify_domain_resolvable()` Provides No Actual Gate

| | |
|---|---|
| **Severity** | 🟢 LOW |
| **Location** | `backend/app/main.py` |

```python
except Exception:
    return True   # always proceeds regardless of DNS failure
```

The function is called as a pre-scan gate but catches all exceptions and unconditionally returns `True`. NXDOMAIN errors are also silently continued (a previously correct rejection was commented out). The function cannot block any domain from being scanned, making the call a no-op with misleading naming.

**Recommendation:** If domain validation is not required (a valid design choice for a scanner tool), remove the function and its call sites. If it is required, restore the NXDOMAIN rejection and document the decision.

---

## 4. Audit Delta — Comparison Against Previous Baseline

| Area | Previous State | Current State | Net Impact |
|---|---|---|---|
| **Primary Scoring** | Deterministic penalty-subtraction (`calculate_posture_score`) | Hierarchical Mamdani FIS with legacy fallback | ✅ **Positive** — richer, more nuanced scoring; legacy score preserved for continuity |
| **Score Semantics** | Single integer score (0–100) | Dual: `legacy_score` (int) + `fuzzy_score` (float) + `linguistic_classification` (5-tier) | ✅ **Positive** — explainability significantly improved |
| **New Model Fields** | N/A | `ScanResponse` extended with 5 optional fields; `PcapAnalysisResponse` extended with 3 optional fields | ✅ **Neutral** — backward-compatible optional fields; no breaking changes |
| **SSRF Exposure** | Existed pre-fuzzy (inherent to `/api/crypto/probe`) | Unchanged; not introduced by fuzzy addition | ⛔ **Pre-existing Critical** |
| **Attack Surface (new deps)** | numpy, scikit-learn present | scikit-fuzzy added (pure computation library, no network calls) | ✅ **Neutral** — no new network-facing attack surface |
| **ELI CVE Table** | Did not exist | Static table with entries through 2020 | ⚠️ **New gap** — creates false confidence for post-2020 CVEs |
| **PQC Readiness** | `has_pqc` used in legacy scoring | Hardcoded to 0.5 in fuzzy antecedents | ⚠️ **Regression** — fuzzy engine ignores PQC detection that legacy engine uses |
| **DNSSEC** | Not scored | Wired into PED FIS but extraction is broken | ⚠️ **Regression** — new capability that does not function correctly |
| **Defuzzification Confidence** | N/A | Always returns 0.88 | ⚠️ **New misleading field** |
| **Frontend Fuzzy Display** | N/A | `ThreatCenter.tsx` renders gauge, antecedent bars, fired rules | ✅ **Positive** — well-integrated |
| **`is_customer_facing` → ELI** | Not used in scoring | ELI antecedent uses it but frontend never sends it | ⚠️ **New gap** — ELI systematically underestimates criticality |
| **Hardcoded TLSA fingerprint in playbook** | Static playbook templates | Static playbook templates with incorrect placeholder fingerprint | ⚠️ **Regression** — misleading security configuration artifact |
| **System Stability** | Stable | Stable — FIS modules isolated, exception-safe, startup-compiled | ✅ **Neutral/Positive** |

### Overall Delta Assessment

The fuzzy logic addition is a **net positive** to system quality and scoring accuracy. It introduces no new critical security vulnerabilities. The pre-existing SSRF remains the dominant risk. Three functional regressions (DNSSEC extraction, PQC hardcoding, `is_customer_facing` propagation) reduce the fidelity of the new scoring system below its designed capability and should be corrected before the system is used to derive compliance conclusions.

---

## 5. Finding Summary Table

| ID | Title | Severity | Category | Location |
|---|---|---|---|---|
| VULN-01 | SSRF via `/api/crypto/probe` — no host validation | 🔴 **CRITICAL** | Security | `models.py`, `main.py`, `tls_probe.py` |
| VULN-02 | No authentication on any endpoint | 🔴 **HIGH** | Security | `main.py` (all routes) |
| VULN-03 | Raw Python exception messages returned to clients | 🔴 **HIGH** | Security | `main.py` |
| VULN-04 | Shell script domain interpolation + incorrect TLSA placeholder | 🔴 **HIGH** | Security / Correctness | `ai_engine.py` |
| DEF-04 | ELI CVE table ends at 2020 — false-safe for modern vulnerabilities | 🔴 **HIGH** | Correctness | `exploitation_likelihood.py` |
| VULN-05 | Gemini response inserted into playbook without sanitization | 🟡 **MEDIUM** | Security | `ai_engine.py` |
| VULN-06 | PCAP temp file cleanup not guaranteed; sensitive data may persist | 🟡 **MEDIUM** | Security | `pcap_analyzer.py` |
| VULN-07 | No dependency version pinning (supply chain risk) | 🟡 **MEDIUM** | Security | `requirements.txt`, `package.json` |
| DEF-01 | Hard-coded rescaling constants without calibration test | 🟡 **MEDIUM** | Correctness | `posture_risk.py` |
| DEF-02 | DNSSEC detection broken — always returns False | 🟡 **MEDIUM** | Correctness | `scoring.py` |
| INT-01 | `is_customer_facing` never sent by frontend | 🟡 **MEDIUM** | Integration | `api.ts`, `App.tsx` |
| INT-02 | Error detail from backend surfaced in frontend terminal | 🟡 **MEDIUM** | Security / UX | `App.tsx`, `main.py` |
| VULN-08 | `verify_domain_resolvable()` always returns True | 🟢 **LOW** | Security | `main.py` |
| DEF-03 | PQC readiness hardcoded 0.5 — ignores live detection | 🟢 **LOW** | Correctness | `scoring.py` |
| DEF-05 | CDI has no moderate path for TLS 1.3 + no-FS scenario | 🟢 **LOW** | Correctness | `crypto_deprecation.py` |
| DEF-06 | Defuzzification confidence unconditionally 0.88 | 🟢 **LOW** | Correctness | `scoring.py` |
| INT-03 | `cvss_metrics` / `remediation_playbook` not rendered in UI | 🟢 **LOW** | Integration | Frontend components |

---

## 6. Remediation Priority Order

### Immediate — Pre-Deployment Blockers

| Priority | Finding | Action |
|---|---|---|
| P1 | VULN-01 | Add FQDN-only validation to `CryptoProbeRequest.host`; block RFC 1918 / metadata IPs |
| P2 | VULN-02 | Implement API key authentication on all routes |
| P3 | VULN-03 | Replace `str(exc)` in global error handler with correlation ID |
| P4 | VULN-04 | Apply `shlex.quote(domain)` to shell script; replace hardcoded TLSA fingerprint |

### Short-Term — Sprint 1

| Priority | Finding | Action |
|---|---|---|
| P5 | DEF-04 | Expand CVE table with post-2020 entries; add staleness warning |
| P6 | VULN-05 | Sanitize DNS record content before Gemini prompt; validate Gemini output fields |
| P7 | VULN-06 | Wrap PCAP temp file in `try/finally`; use `delete=True` |
| P8 | VULN-07 | Pin all dependency versions; add lock files |
| P9 | DEF-02 | Fix DNSSEC extraction to use explicit `dnssec_validated` flag from active scanner |

### Short-Term — Sprint 2

| Priority | Finding | Action |
|---|---|---|
| P10 | INT-01 | Pass `is_customer_facing` from frontend; add UI checkbox |
| P11 | INT-02 | Sanitize error display in `App.tsx` terminal |
| P12 | DEF-01 | Add `test_fuzzy_rescaling.py` calibration test |

### Backlog

| Priority | Finding | Action |
|---|---|---|
| P13 | DEF-03 | Wire `has_pqc` boolean into `pqc_readiness` antecedent |
| P14 | DEF-05 | Add CDI moderate rule for TLS 1.3 + no-FS edge case |
| P15 | DEF-06 | Compute `defuzzification_confidence` from actual firing strengths |
| P16 | INT-03 | Render `cvss_metrics` and `remediation_playbook` in frontend UI |
| P17 | VULN-08 | Remove or restore `verify_domain_resolvable()` gate |

---

## Appendix — Referenced Standards

| Standard | Description |
|---|---|
| Mozilla Server Side TLS v5.7 | Cipher suite classification and TLS configuration guidance |
| NIST SP 800-52r2 | Guidelines for selection, configuration, and use of TLS implementations |
| NIST SP 800-57 Part 1 Rev. 5 | Recommendation for key management — key length thresholds |
| RFC 8996 | Deprecating TLS 1.0 and TLS 1.1 |
| RFC 7208 | Sender Policy Framework (SPF) |
| RFC 6376 | DomainKeys Identified Mail (DKIM) Signatures |
| RFC 7489 | Domain-based Message Authentication, Reporting, and Conformance (DMARC) |
| RFC 8461 | SMTP MTA Strict Transport Security (MTA-STS) |
| RFC 4033–4035 | DNS Security Extensions (DNSSEC) |
| CVSS v3.1 | Common Vulnerability Scoring System specification |
| NIST FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) |

---

*End of Audit Report — AegisCrypta v2.4.0*

*This report is read-only. No modifications were made to the codebase during this audit.*

---

> **Document:** `audit_fuzzy_updated.md`  
> **Version:** 1.0  
> **Last Updated:** September 25, 2026
