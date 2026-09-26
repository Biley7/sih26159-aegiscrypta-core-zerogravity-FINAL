import dns.resolver
from typing import List, Dict, Any, Optional
from app.models import (
    CryptographicPosture,
    ProtocolAuditResult,
    SecurityFinding,
    FindingSeverity,
    CheckStatus
)
from app.resolver import get_dns_resolver
from app.crypto.tls_probe import probe_protocol_tls


def discover_mail_endpoints(domain: str, timeout: float = 3.0) -> List[Dict[str, Any]]:
    """
    Discovers mail service hosts for a domain via DNS MX, SRV records, and fallback subdomains.
    Returns candidate endpoints: [{"protocol": "SMTP", "host": ..., "port": ..., "use_starttls": ...}]
    """
    resolver = get_dns_resolver(timeout=timeout)
    candidates: List[Dict[str, Any]] = []
    seen = set()

    # 1. MX Records (SMTP port 25 & 587)
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_sorted = sorted(mx_answers, key=lambda r: r.preference)
        for rdata in mx_sorted[:2]:  # Check top 2 MX hosts max
            host = str(rdata.exchange).rstrip(".")
            if host and host != ".":
                key = (host, 25, "SMTP")
                if key not in seen:
                    candidates.append({"protocol": "SMTP", "host": host, "port": 25, "use_starttls": True})
                    seen.add(key)
    except Exception:
        pass

    # 2. SRV Records for IMAPS and POP3S
    srv_queries = [
        ("_imaps._tcp." + domain, "IMAP", 993, False),
        ("_pop3s._tcp." + domain, "POP3", 995, False),
        ("_submission._tcp." + domain, "SMTP", 587, True),
    ]

    for qname, proto, default_port, starttls in srv_queries:
        try:
            srv_answers = resolver.resolve(qname, "SRV")
            for rdata in srv_answers:
                target_host = str(rdata.target).rstrip(".")
                port = rdata.port or default_port
                key = (target_host, port, proto)
                if key not in seen:
                    candidates.append({"protocol": proto, "host": target_host, "port": port, "use_starttls": starttls})
                    seen.add(key)
                break
        except Exception:
            pass

    # 3. If no IMAP/POP3 found via SRV, check standard subdomains
    subdomain_fallbacks = [
        ("imap." + domain, "IMAP", 993, False),
        ("mail." + domain, "IMAP", 993, False),
        ("pop." + domain, "POP3", 995, False),
    ]

    for host_candidate, proto, port, starttls in subdomain_fallbacks:
        # Check if hostname resolves to avoid wasted connection timeouts
        try:
            resolver.resolve(host_candidate, "A")
            key = (host_candidate, port, proto)
            if key not in seen:
                candidates.append({"protocol": proto, "host": host_candidate, "port": port, "use_starttls": starttls})
                seen.add(key)
        except Exception:
            pass

    return candidates


def evaluate_domain_crypto_posture(
    domain: str,
    probe_timeout: float = 3.5,
    max_endpoints: int = 4
) -> CryptographicPosture:
    """
    Discovers mail servers and conducts deep cryptographic posture evaluation across protocols:
    - Performs TLS handshakes on discovered endpoints (SMTP, IMAP, POP3).
    - Aggregates prioritized security findings.
    - Computes 0-100 Cryptographic Security Score and letter grade.
    """
    candidates = discover_mail_endpoints(domain)
    audits: List[ProtocolAuditResult] = []
    prioritized_findings: List[SecurityFinding] = []

    forward_secrecy_supported = False
    weak_ciphers_found = False
    deprecated_tls_found = False
    certificate_issues_found = False

    # Limit total probes to keep scan latency under 8 seconds
    for item in candidates[:max_endpoints]:
        audit = probe_protocol_tls(
            host=item["host"],
            port=item["port"],
            protocol=item["protocol"].lower(),
            use_starttls=item["use_starttls"],
            target_domain=domain,
            timeout=probe_timeout
        )
        audits.append(audit)
        prioritized_findings.extend(audit.findings)

        # Telemetry flags
        if audit.tls_handshake and audit.tls_handshake.success:
            if audit.tls_handshake.cipher:
                if audit.tls_handshake.cipher.forward_secrecy:
                    forward_secrecy_supported = True
                if audit.tls_handshake.cipher.is_weak:
                    weak_ciphers_found = True
            if audit.tls_handshake.negotiated_version in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
                deprecated_tls_found = True
            if audit.tls_handshake.certificate:
                cert = audit.tls_handshake.certificate
                if cert.is_expired or cert.is_self_signed or len(cert.warnings) > 0:
                    certificate_issues_found = True

    # Deduplicate findings by title
    unique_findings = []
    seen_titles = set()
    for f in prioritized_findings:
        if f.title not in seen_titles:
            unique_findings.append(f)
            seen_titles.add(f.title)

    # Sort findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4
    }
    unique_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    # Calculate Cryptographic Posture Score (0-100)
    # Baseline 100 with deductions
    base_score = 100

    has_successful_tls = any(a.tls_handshake and a.tls_handshake.success for a in audits)

    if not audits or not has_successful_tls:
        # Check if all timed out due to network port restrictions
        all_timeout = all(a.status == CheckStatus.UNKNOWN for a in audits)
        if all_timeout and audits:
            base_score = 75  # Graceful partial score when network blocks outbound ports
        else:
            base_score = 40
    else:
        for f in unique_findings:
            if f.severity == FindingSeverity.CRITICAL:
                base_score -= 25
            elif f.severity == FindingSeverity.HIGH:
                base_score -= 15
            elif f.severity == FindingSeverity.MEDIUM:
                base_score -= 8
            elif f.severity == FindingSeverity.LOW:
                base_score -= 3

        if not forward_secrecy_supported and has_successful_tls:
            base_score -= 10

    crypto_score = max(0, min(100, base_score))

    # Determine Letter Grade
    if crypto_score >= 95:
        grade = "A+"
    elif crypto_score >= 85:
        grade = "A"
    elif crypto_score >= 70:
        grade = "B"
    elif crypto_score >= 55:
        grade = "C"
    elif crypto_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return CryptographicPosture(
        crypto_score=crypto_score,
        grade=grade,
        protocols_audited=audits,
        forward_secrecy_supported=forward_secrecy_supported,
        weak_ciphers_found=weak_ciphers_found,
        deprecated_tls_found=deprecated_tls_found,
        certificate_issues_found=certificate_issues_found,
        prioritized_findings=unique_findings
    )
