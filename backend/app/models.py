from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import re


class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityFinding(BaseModel):
    title: str = Field(..., description="Short title of the finding")
    severity: FindingSeverity = Field(..., description="Finding severity level")
    category: str = Field(..., description="Category e.g. TLS, Certificate, Cipher, Protocol, DNS, AI-Anomaly")
    description: str = Field(..., description="Detailed explanation of the risk or finding")
    recommendation: Optional[str] = Field(None, description="Actionable mitigation guidance")


class CertificateInfo(BaseModel):
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    subject_dn: str
    issuer_dn: str
    serial_number: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    is_expired: bool
    is_self_signed: bool
    public_key_algorithm: str
    key_size_bits: Optional[int] = None
    signature_algorithm: str
    sha256_fingerprint: Optional[str] = None
    san_list: List[str] = Field(default_factory=list)
    matches_domain: Optional[bool] = None
    warnings: List[str] = Field(default_factory=list)
    chain_valid: Optional[bool] = None
    chain_error: Optional[str] = None


class CipherSuiteInfo(BaseModel):
    name: str
    tls_version: str
    key_exchange: str
    forward_secrecy: bool
    encryption: str
    mac: Optional[str] = None
    bits: Optional[int] = None
    is_weak: bool = False
    weak_reasons: List[str] = Field(default_factory=list)
    pqc_hybrid: bool = False
    sndl_vulnerable: bool = False
    pqc_details: Optional[str] = None


class TlsHandshakeResult(BaseModel):
    success: bool
    negotiated_version: Optional[str] = None
    cipher: Optional[CipherSuiteInfo] = None
    certificate: Optional[CertificateInfo] = None
    alpn_selected: Optional[str] = None
    error_message: Optional[str] = None


class ProtocolAuditResult(BaseModel):
    protocol: str = Field(..., description="SMTP, IMAP, or POP3")
    host: str
    port: int
    service_type: str = Field(..., description="STARTTLS or Direct TLS")
    banner: Optional[str] = None
    starttls_advertised: Optional[bool] = None
    starttls_negotiated: Optional[bool] = None
    tls_handshake: Optional[TlsHandshakeResult] = None
    findings: List[SecurityFinding] = Field(default_factory=list)
    status: CheckStatus = CheckStatus.UNKNOWN


class CryptographicPosture(BaseModel):
    crypto_score: int = Field(..., ge=0, le=100, description="Cryptographic posture score (0-100)")
    grade: str = Field(..., description="A+, A, B, C, D, or F")
    protocols_audited: List[ProtocolAuditResult] = Field(default_factory=list)
    forward_secrecy_supported: bool = False
    weak_ciphers_found: bool = False
    deprecated_tls_found: bool = False
    certificate_issues_found: bool = False
    prioritized_findings: List[SecurityFinding] = Field(default_factory=list)
    pqc_indicators_evaluated: bool = Field(
        False,
        description=(
            "True only when a completed handshake supplied cipher/key-exchange "
            "telemetry that was classified for post-quantum (hybrid KEM) indicators. "
            "False means no PQC compliance claim can be made for this scan."
        ),
    )
    telemetry_observed: bool = Field(
        True,
        description=(
            "True when at least one TLS handshake completed, so the transport "
            "layer was genuinely observed. False means port 25 was unreachable, "
            "STARTTLS was blocked, or the scan ran degraded: the Crypto "
            "Deprecation Index carries no information for this target and is "
            "excluded from the fused posture score, which is renormalised over "
            "the observed dimensions (email authentication + exploitation "
            "likelihood). Clients must render the transport layer as "
            "UNAUDITED rather than reporting a fabricated crypto grade."
        ),
    )


class AiRiskScore(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="AI Cryptographic Risk Score (0-100, where 0 is safest and 100 is critical risk)")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    confidence: float = Field(..., description="Model confidence level (0.0 - 1.0)")
    risk_factors: List[str] = Field(default_factory=list)
    mitigation_priority: List[str] = Field(default_factory=list)


class TlsAnomalyDetectionResult(BaseModel):
    anomaly_detected: bool
    anomaly_score: float = Field(..., description="Anomaly score (-1.0 to 1.0)")
    confidence: float
    detected_anomalies: List[str] = Field(default_factory=list)
    suspicious_indicators: List[str] = Field(default_factory=list)


class TcpStreamSummary(BaseModel):
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    packet_count: int
    client_bytes: int
    server_bytes: int
    starttls_detected: bool = False
    tls_handshake_detected: bool = False
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_extracted: bool = False
    certificate_info: Optional[CertificateInfo] = None
    findings: List[SecurityFinding] = Field(default_factory=list)


class PcapAnalysisResponse(BaseModel):
    filename: str
    total_packets: int
    total_tcp_streams: int
    identified_protocols: List[str]
    streams: List[TcpStreamSummary]
    summary_findings: List[SecurityFinding]
    processed_at: str
    # Fuzzy logic extension fields for PCAP analysis
    fuzzy_score: Optional[float] = Field(None, ge=0, le=100, description="Fuzzy logic defuzzified score (0-100)")
    linguistic_classification: Optional[str] = Field(None, description="EXCELLENT | GOOD | ACCEPTABLE | POOR | CRITICAL")
    antecedent_scores: Optional[Dict[str, float]] = Field(None, description="Individual antecedent scores (0-1)")


class CheckResult(BaseModel):
    name: str = Field(..., description="Name of the check (e.g., SPF, DMARC, DKIM, MX & STARTTLS)")
    status: CheckStatus = Field(..., description="pass, warn, fail, or unknown")
    details: Any = Field(..., description="Detailed diagnostic data or raw findings for this check")
    recommendation: Optional[str] = Field(None, description="Actionable plain-English mitigation advice if warned or failed")


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Domain name to scan (e.g. google.com)")
    is_customer_facing: bool = Field(False, description="Whether the asset is customer-facing (affects exploitation likelihood)")

    @field_validator("domain")
    @classmethod
    def clean_and_validate_domain(cls, v: str) -> str:
        domain = v.strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0].split("?")[0].split(":")[0]
        if "@" in domain:
            domain = domain.split("@")[-1]

        domain_pattern = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if not re.match(domain_pattern, domain):
            raise ValueError(f"Invalid domain name format: '{v}'")
        return domain


class CryptoProbeRequest(BaseModel):
    host: str = Field(..., description="FQDN of the mail host to probe (e.g. smtp.gmail.com). IP addresses and internal hostnames are not accepted.")
    port: int = Field(25, ge=1, le=65535, description="Port number (e.g. 25, 465, 587, 993, 995, 143, 110)")
    protocol: str = Field("smtp", description="smtp, imap, or pop3")
    use_starttls: bool = Field(True, description="Whether to perform STARTTLS or direct TLS")

    @field_validator("host")
    @classmethod
    def validate_fqdn_host(cls, v: str) -> str:
        """
        SSRF Prevention (VULN-01): Enforce strict FQDN-only validation on the probe host.
        Rejects raw IP addresses, localhost, and any non-public hostnames at the model layer
        before any network I/O is attempted.
        """
        host = v.strip().lower()
        # Strip any accidental scheme prefix
        host = re.sub(r"^https?://", "", host)
        host = host.split("/")[0].split("?")[0].split(":")[0]

        fqdn_pattern = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if not re.match(fqdn_pattern, host, re.IGNORECASE):
            raise ValueError(
                f"Invalid host '{v}': only fully-qualified domain names are accepted. "
                "IP addresses, localhost, and bare hostnames are not permitted."
            )
        return host

    @field_validator("protocol")
    @classmethod
    def validate_protocol_allowlist(cls, v: str) -> str:
        """
        SSRF Prevention (VULN-01): Restrict protocol to an explicit allowlist to prevent
        unexpected protocol handlers from being invoked via crafted inputs.
        """
        allowed = {"smtp", "imap", "pop3"}
        normalized = v.strip().lower()
        if normalized not in allowed:
            raise ValueError(
                f"Invalid protocol '{v}': must be one of {sorted(allowed)}."
            )
        return normalized


class CvssMetrics(BaseModel):
    base_score: float = Field(..., description="CVSS v3.1 Base Score (0.0 - 10.0)")
    vector_string: str = Field(..., description="CVSS v3.1 Vector String")
    severity: str = Field(..., description="NONE, LOW, MEDIUM, HIGH, or CRITICAL")
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None


class RemediationPlaybook(BaseModel):
    postfix_main_cf: Optional[str] = None
    exim_conf: Optional[str] = None
    sendmail_mc: Optional[str] = None
    bind_dns_zone: Optional[str] = None
    shell_script: Optional[str] = None


class ScanResponse(BaseModel):
    domain: str
    score: int = Field(..., ge=0, le=100, description="Overall email security posture score (0-100)")
    checks: List[CheckResult]
    crypto_posture: Optional[CryptographicPosture] = None
    ai_risk_score: Optional[AiRiskScore] = None
    anomaly_detection: Optional[TlsAnomalyDetectionResult] = None
    prioritized_findings: List[SecurityFinding] = Field(default_factory=list)
    cvss_metrics: Optional[CvssMetrics] = None
    remediation_playbook: Optional[RemediationPlaybook] = None
    scanned_at: str
    # Fuzzy logic extension fields (added for hierarchical risk scoring)
    fuzzy_score: Optional[float] = Field(None, ge=0, le=100, description="Fuzzy logic defuzzified score (0-100)")
    linguistic_classification: Optional[str] = Field(None, description="EXCELLENT | GOOD | ACCEPTABLE | POOR | CRITICAL")
    antecedent_scores: Optional[Dict[str, float]] = Field(None, description="Individual antecedent scores (0-1)")
    activated_rules: Optional[List[str]] = Field(None, description="Human-readable fired-rule descriptions")
    defuzzification_confidence: Optional[float] = Field(None, ge=0, le=1, description="Confidence in defuzzification (0-1)")
