from datetime import datetime, timezone
from typing import Tuple, List, Optional
import logging
import hmac
import os
import uuid
import dns.resolver
import dns.exception
from fastapi import FastAPI, HTTPException, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse

from app.models import (
    ScanRequest,
    ScanResponse,
    CheckResult,
    CheckStatus,
    CryptoProbeRequest,
    ProtocolAuditResult,
    CryptographicPosture,
    SecurityFinding,
    FindingSeverity,
    AiRiskScore,
    TlsAnomalyDetectionResult,
    PcapAnalysisResponse,
    CvssMetrics,
    RemediationPlaybook
)
from app.resolver import get_dns_resolver
from app.checks.spf import check_spf
from app.checks.dmarc import check_dmarc
from app.checks.dkim import check_dkim
from app.checks.mx_starttls import check_mx_starttls
from app.crypto.tls_probe import probe_protocol_tls
from app.crypto.mail_discovery import evaluate_domain_crypto_posture
from app.ai.risk_scorer import compute_ai_cryptographic_risk
from app.ai.anomaly_detector import get_anomaly_detector
from app.reports.html_report import generate_html_forensic_report
from app.pcap.stream_reconstructor import analyze_pcap_data
from app.scoring import calculate_overall_score
from app.pdf_report import generate_pdf_report
from app.active_scanner import run_active_domain_scan
from app.pcap_analyzer import analyze_pcap_stream
from app.ai_engine import evaluate_ai_remediation

app = FastAPI(
    title="AegisCrypta Forensics Engine API",
    description="Dual-Paradigm Email Security & Cryptographic Posture Platform (SIH2026159 / NTRO Architecture Standards)",
    version="2.4.0"
)

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if not request.url.path.startswith("/api/") or request.method == "OPTIONS":
        return await call_next(request)

    expected_key = os.getenv("AEGIS_API_KEY", "")
    if not expected_key:
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is not configured."},
        )

    provided_key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided_key.encode("utf-8"), expected_key.encode("utf-8")):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing or invalid API key."},
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return await call_next(request)

_logger = logging.getLogger("aegiscrypta")

# Enable CORS for frontend clients.
# Set CORS_ORIGINS to a comma-separated allowlist of the deployed origins, e.g.
#   CORS_ORIGINS=https://aegiscrypta.example.com,https://admin.example.com
# CORS_ALLOWED_ORIGINS is still honoured as a legacy alias.
_cors_origins_raw = os.getenv("CORS_ORIGINS", "").strip()
_cors_var_used = "CORS_ORIGINS"
if not _cors_origins_raw:
    _cors_origins_raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    if _cors_origins_raw:
        _cors_var_used = "CORS_ALLOWED_ORIGINS"

# Zero-config origins for local development. A production deployment MUST set
# CORS_ORIGINS explicitly.
_DEV_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]

if _cors_origins_raw:
    _cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
else:
    _cors_origins = list(_DEV_CORS_ORIGINS)

# VULN-07: "*" combined with allow_credentials=True lets any origin drive the API
# with ambient browser credentials. Authentication here is an explicit header
# (X-API-Key), so credentialed CORS is never required — drop it for wildcards.
_cors_wildcard = "*" in _cors_origins
_allow_credentials = not _cors_wildcard

if _cors_wildcard:
    _logger.warning(
        "%s is '*': every origin may call this API from a browser, so credentialed "
        "CORS is disabled. Set an explicit comma-separated allowlist before deploying.",
        _cors_var_used,
    )
elif not _cors_origins_raw:
    _logger.warning(
        "CORS_ORIGINS is not set; defaulting to local development origins %s.",
        _cors_origins,
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    VULN-03: Global exception fallback — redacts internal stack traces.
    A unique correlation_id is generated, the full exception is logged
    server-side (never serialised into the HTTP response), and the client
    receives only a sanitised envelope with the correlation_id for support
    traceability.
    """
    # Re-raise HTTPExceptions so FastAPI handles them with their own status code
    if isinstance(exc, HTTPException):
        raise exc

    correlation_id = uuid.uuid4().hex[:12]
    _logger.exception(
        "Unhandled exception [correlation_id=%s] on %s %s",
        correlation_id,
        request.method,
        request.url.path,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred while processing the forensic payload.",
            "correlation_id": correlation_id,
        },
    )


# def verify_domain_resolvable(domain: str, timeout: float = 3.0) -> bool:
#     """
#     Verifies domain reachability with fallbacks to public DNS resolvers.
#     Prevents local network/ISP timeouts from blocking scans.
#     """
#     resolver = get_dns_resolver(timeout=timeout)
    
#     # Configure public DNS fallback servers (Google / Cloudflare)
#     resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

#     try:
#         # Check primary DNS record types
#         for record_type in ["SOA", "NS", "A", "MX"]:
#             try:
#                 resolver.resolve(domain, record_type)
#                 return True
#             except (dns.resolver.NoAnswer, dns.exception.Timeout):
#                 continue

#         return True

#     except dns.resolver.NXDOMAIN:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Domain '{domain}' does not exist or could not be resolved (NXDOMAIN)."
#         )
#     except Exception:
#         # Gracefully proceed with scan even if local DNS lookup times out
#         return True

# Client-facing text for a failed domain resolution. The specific cause (NXDOMAIN,
# no published records, resolver error) is written to the server log only, so no
# raw resolver detail is ever serialised into an HTTP response body.
_DOMAIN_RESOLUTION_ERROR = "Domain resolution failed or unreachable."


def verify_domain_resolvable(domain: str, timeout: float = 3.0) -> bool:
    """
    Require at least one public DNS answer before starting an active scan.

    Raises HTTPException(400) with a generic, sanitised detail when the domain
    cannot be resolved. The diagnostic reason is logged server-side, never
    returned to the caller.
    """
    resolver = get_dns_resolver(timeout=timeout)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    last_error = None

    for record_type in ["A", "AAAA", "MX", "SOA"]:
        try:
            resolver.resolve(domain, record_type)
            return True
        except dns.resolver.NXDOMAIN:
            # Logged at WARNING so the diagnostic survives even when the application
            # has no logging configuration (this app does not call basicConfig, and
            # the root logger defaults to WARNING, which would drop an INFO line).
            _logger.warning(
                "Scan rejected for %s: NXDOMAIN (the domain does not exist in public DNS).",
                domain,
            )
            raise HTTPException(status_code=400, detail=_DOMAIN_RESOLUTION_ERROR)
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            last_error = exc
            continue

    if last_error is not None:
        _logger.warning("Scan rejected for %s: DNS resolution error: %s", domain, last_error)
        raise HTTPException(
            status_code=503,
            detail="Public DNS resolution failed; retry the scan when DNS is available.",
        )

    _logger.warning(
        "Scan rejected for %s: no A, AAAA, MX, or SOA records are published.", domain
    )
    raise HTTPException(status_code=400, detail=_DOMAIN_RESOLUTION_ERROR)

def execute_security_scan(domain: str, is_customer_facing: bool = False) -> Tuple[int, List[CheckResult], Optional[CryptographicPosture], List[SecurityFinding], AiRiskScore, TlsAnomalyDetectionResult, CvssMetrics, RemediationPlaybook, str, Optional[str]]:
    """
    Orchestrates full dual-paradigm active domain security scan:
    - DNSSEC, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA
    - Deep SMTP/TLS socket probe and Post-Quantum Cryptography (PQC) handshake evaluation
    - AI Risk synthesis, CVSS v3.1 metrics, SNDL quantum threat tagging, and automated configuration playbooks
    - Session anomaly detection
    - Banner extraction for software vulnerability detection
    """
    banner = None
    
    try:
        checks, crypto_posture, prioritized_findings = run_active_domain_scan(domain)
        # Extract banner from crypto_posture for software vulnerability check
        if crypto_posture and crypto_posture.protocols_audited:
            banner = crypto_posture.protocols_audited[0].banner if crypto_posture.protocols_audited[0].banner else None
    except Exception:
        # Graceful fallback to legacy checks if socket error occurs. The raw
        # exception is logged server-side only — never serialised into a finding.
        _logger.exception("Active domain scan degraded for %s; falling back to DNS checks.", domain)
        checks = [check_spf(domain), check_dmarc(domain), check_dkim(domain), check_mx_starttls(domain)]
        crypto_posture = None
        prioritized_findings = [
            SecurityFinding(
                title="Active Scan Degraded",
                severity=FindingSeverity.LOW,
                category="System",
                description="The active TLS/SMTP probe could not complete for this domain, so only DNS authentication checks were evaluated.",
                recommendation="Verify network connectivity and domain reachability, then re-run the scan."
            )
        ]

    # Run AI remediation, CVSS metrics, and playbook generation
    score, grade, ai_risk, cvss, playbook = evaluate_ai_remediation(
        domain=domain,
        checks=checks,
        crypto_posture=crypto_posture,
        findings=prioritized_findings
    )

    # Session anomaly detection
    anomaly = get_anomaly_detector().detect_anomalies_in_posture(crypto_posture)
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return score, checks, crypto_posture, prioritized_findings, ai_risk, anomaly, cvss, playbook, scanned_at, banner


@app.get("/")
def root():
    return {
        "service": "aegiscrypta-api",
        "version": "2.4.0",
        "standard": "NTRO / SIH2026159",
        "status": "healthy",
        "endpoints": {
            "scan": "POST /api/scan",
            "crypto_probe": "POST /api/crypto/probe",
            "analyze_pcap": "POST /api/analyze-pcap",
            "export_pdf": "POST /api/export-pdf",
            "html_report": "POST /api/scan/html",
            "forensic": "POST /api/scan/forensic",
            "health": "GET /health"
        }
    }


@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/scan", response_model=ScanResponse)
def scan_domain(payload: ScanRequest):
    """
    Comprehensive Security Posture Scan:
    - DNS Authentication: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DANE/TLSA, DNSSEC
    - Protocol & Cryptographic Inspection: MX routing, opportunistic STARTTLS, TLS version, cipher suite, Forward Secrecy, X.509 certificate chain
    - Post-Quantum Cryptography (PQC) & SNDL Evaluation
    - AI-based Cryptographic Risk Scoring, CVSS v3.1 metrics, and syntax-checked configuration playbooks
    - Session Anomaly Detection.
    - Hierarchical Fuzzy Logic Risk Scoring (NEW)
    """
    domain = payload.domain
    is_customer_facing = payload.is_customer_facing
    try:
        verify_domain_resolvable(domain)
        score, checks, crypto_posture, prioritized_findings, ai_risk, anomaly, cvss, playbook, scanned_at, banner = execute_security_scan(domain, is_customer_facing)
    except HTTPException:
        # Validation failures (400 unreachable/NXDOMAIN domain, 503 DNS unavailable)
        # propagate with their own status code. Swallowing them here previously turned
        # every resolution failure into a 200 whose user-visible check details leaked
        # the raw "400: ..." exception string.
        raise
    except Exception:
        _logger.exception("Automated probe failed unexpectedly for %s.", domain)
        degraded_detail = "Automated probe could not complete for this domain."
        checks = [
            CheckResult(name="SPF", status=CheckStatus.FAIL, details={"record_value": "Resolution failed", "message": degraded_detail}),
            CheckResult(name="DMARC", status=CheckStatus.FAIL, details={"dmarc_present": False, "policy": "none", "message": degraded_detail}),
            CheckResult(name="DKIM", status=CheckStatus.WARN, details={"message": "Unverified"}),
            CheckResult(name="MTA-STS", status=CheckStatus.WARN, details={"message": "Unverified"}),
            CheckResult(name="TLS-RPT", status=CheckStatus.WARN, details={"message": "Unverified"}),
            CheckResult(name="DANE/TLSA", status=CheckStatus.WARN, details={"message": "Unverified"})
        ]
        prioritized_findings = [
            SecurityFinding(
                title="Active Scan Degraded",
                severity=FindingSeverity.LOW,
                category="System",
                description="The automated probe encountered an unexpected error and could not assess this domain.",
                recommendation="Verify zone nameserver responsiveness and domain format."
            )
        ]
        crypto_posture = CryptographicPosture(
            crypto_score=40,
            grade="F",
            protocols_audited=[],
            forward_secrecy_supported=False,
            weak_ciphers_found=False,
            deprecated_tls_found=False,
            certificate_issues_found=False,
            prioritized_findings=prioritized_findings
        )
        score = 40
        ai_risk = AiRiskScore(
            risk_score=60,
            risk_level="MEDIUM",
            confidence=0.85,
            risk_factors=["External nameserver query degraded"],
            mitigation_priority=["Ensure target domain exists in authoritative DNS"]
        )
        anomaly = get_anomaly_detector().detect_anomalies_in_posture(crypto_posture)
        cvss = CvssMetrics(
            base_score=4.0,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            severity="MEDIUM",
            exploitability_score=3.9,
            impact_score=1.4
        )
        playbook = RemediationPlaybook(
            postfix_main_cf="",
            exim_conf="",
            sendmail_mc="",
            bind_dns_zone="",
            shell_script=""
        )
        scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        banner = None

    # Use fuzzy logic scoring
    from app.scoring import calculate_overall_score
    (
        legacy_score,
        fuzzy_score,
        linguistic_classification,
        antecedent_scores,
        activated_rules,
        defuzzification_confidence,
        recommendations,
        findings
    ) = calculate_overall_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture,
        banner=banner,
        is_customer_facing=is_customer_facing
    )

    # Use fuzzy score as primary score, but keep legacy for comparison
    primary_score = int(fuzzy_score) if fuzzy_score is not None else legacy_score

    return ScanResponse(
        domain=domain,
        score=primary_score,
        checks=checks,
        crypto_posture=crypto_posture,
        ai_risk_score=ai_risk,
        anomaly_detection=anomaly,
        prioritized_findings=findings,
        cvss_metrics=cvss,
        remediation_playbook=playbook,
        scanned_at=scanned_at,
        fuzzy_score=fuzzy_score,
        linguistic_classification=linguistic_classification,
        antecedent_scores=antecedent_scores,
        activated_rules=activated_rules,
        defuzzification_confidence=defuzzification_confidence
    )


@app.post("/api/crypto/probe", response_model=ProtocolAuditResult)
def probe_host(payload: CryptoProbeRequest):
    """
    Direct active TLS probe on a specific mail host, port, and protocol (SMTP, IMAP, POP3).
    Performs STARTTLS/direct TLS handshake and extracts complete cryptographic telemetry.

    SSRF Prevention (VULN-01):
    - Host must be a valid public FQDN (validated by CryptoProbeRequest.validate_fqdn_host).
    - Protocol must be smtp | imap | pop3 (validated by CryptoProbeRequest.validate_protocol_allowlist).
    - The resolved IP is checked against private/loopback/metadata ranges inside probe_protocol_tls
      via _assert_public_host(); an HTTPException(403) is raised before any socket is opened if
      the target resolves to a prohibited address.

    Pydantic validation errors (422) and SSRF blocks (400/403) propagate directly to the caller
    without being masked by the global exception handler.
    """
    # HTTPException from _assert_public_host (400/403) propagates automatically
    return probe_protocol_tls(
        host=payload.host,
        port=payload.port,
        protocol=payload.protocol,
        use_starttls=payload.use_starttls
    )


@app.post("/api/analyze-pcap", response_model=PcapAnalysisResponse)
@app.post("/api/scan/pcap", response_model=PcapAnalysisResponse)
async def analyze_pcap_endpoint(file: UploadFile = File(...)):
    """
    Uploads a .pcap or .pcapng network capture file for passive forensic analysis:
    - Complete TCP stream reconstruction across SMTP, IMAP, POP3
    - Plaintext credential exposure detection (AUTH LOGIN, AUTH PLAIN, PASS)
    - STARTTLS stripping and downgrade attack detection
    - Passive TLS handshake reconstruction and X.509 certificate extraction with SHA-256 fingerprints.
    """
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty PCAP file provided.")
    return analyze_pcap_stream(contents, filename=file.filename or "capture.pcap")


@app.post("/api/export-pdf")
@app.post("/api/scan/pdf")
def export_pdf_endpoint(payload: ScanRequest):
    """
    Scans domain and returns a downloadable binary PDF forensic audit report.
    """
    domain = payload.domain
    verify_domain_resolvable(domain)

    score, checks, crypto_posture, prioritized_findings, ai_risk, anomaly, cvss, playbook, scanned_at, banner = execute_security_scan(domain)
    recommendations = [f.recommendation for f in prioritized_findings if f.recommendation]

    # Calculate fuzzy risk score for explainability inclusion
    (
        legacy_score,
        fuzzy_score,
        linguistic_classification,
        antecedent_scores,
        activated_rules,
        defuzzification_confidence,
        _,
        _
    ) = calculate_overall_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture,
        banner=banner
    )

    display_score = int(fuzzy_score) if fuzzy_score is not None else score

    pdf_buffer = generate_pdf_report(
        domain=domain,
        score=display_score,
        checks=checks,
        recommendations=recommendations,
        scanned_at=scanned_at,
        fuzzy_score=fuzzy_score,
        linguistic_classification=linguistic_classification,
        antecedent_scores=antecedent_scores,
        playbook=playbook
    )

    filename = f"aegiscrypta_audit_{domain.replace('.', '_')}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@app.post("/api/export-html")
@app.post("/api/scan/html", response_class=HTMLResponse)
def scan_domain_html(payload: ScanRequest):
    """
    Generates an executive-ready standalone HTML forensic report with dark styling,
    metrics cards, prioritized findings, certificate hierarchy, fuzzy breakdown, and print CSS.
    """
    domain = payload.domain
    verify_domain_resolvable(domain)

    score, checks, crypto_posture, prioritized_findings, ai_risk, anomaly, cvss, playbook, scanned_at, banner = execute_security_scan(domain)

    (
        legacy_score,
        fuzzy_score,
        linguistic_classification,
        antecedent_scores,
        activated_rules,
        defuzzification_confidence,
        _,
        _
    ) = calculate_overall_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture,
        banner=banner
    )

    display_score = int(fuzzy_score) if fuzzy_score is not None else score

    html_content = generate_html_forensic_report(
        domain=domain,
        score=display_score,
        checks=checks,
        crypto_posture=crypto_posture,
        ai_risk=ai_risk,
        anomaly=anomaly,
        scanned_at=scanned_at,
        fuzzy_score=fuzzy_score,
        linguistic_classification=linguistic_classification,
        antecedent_scores=antecedent_scores,
        activated_rules=activated_rules,
        playbook=playbook,
        cvss_metrics=cvss
    )
    return HTMLResponse(content=html_content)


@app.post("/api/scan/forensic")
def scan_domain_forensic(payload: ScanRequest):
    """
    Returns full cryptographic and forensic JSON telemetry including raw handshakes,
    AI risk scoring, anomaly detection, certificate parameters, and prioritized findings.
    """
    domain = payload.domain
    verify_domain_resolvable(domain)

    score, checks, crypto_posture, prioritized_findings, ai_risk, anomaly, cvss, playbook, scanned_at, banner = execute_security_scan(domain)
    recommendations = [f.recommendation for f in prioritized_findings if f.recommendation]

    return {
        "domain": domain,
        "score": score,
        "scanned_at": scanned_at,
        "dns_authentication": [c.model_dump() for c in checks],
        "cryptographic_posture": crypto_posture.model_dump() if crypto_posture else None,
        "ai_risk_assessment": ai_risk.model_dump(),
        "cvss_metrics": cvss.model_dump(),
        "remediation_playbook": playbook.model_dump(),
        "anomaly_detection": anomaly.model_dump(),
        "prioritized_findings": [f.model_dump() for f in prioritized_findings],
        "mitigation_actions": recommendations
    }