from typing import List, Dict, Tuple, Optional
from app.models import CheckResult, CheckStatus, SecurityFinding, FindingSeverity, CryptographicPosture

# Standard weights: SPF 25%, DMARC 30%, DKIM 20%, MX/STARTTLS 25%
CHECK_WEIGHTS = {
    "SPF": 25,
    "DMARC": 30,
    "DKIM": 20,
    "MX & STARTTLS": 25
}

DEFAULT_RECOMMENDATIONS = {
    ("SPF", CheckStatus.FAIL): "Publish an SPF record ('v=spf1 ... -all') on your root domain to prevent unauthorized servers from sending mail on your behalf.",
    ("SPF", CheckStatus.WARN): "Tighten your SPF configuration: replace '+all' or '?all' with '~all' or '-all', and keep DNS lookups under the RFC 7208 10-lookup limit.",
    ("DMARC", CheckStatus.FAIL): "Deploy a DMARC record at '_dmarc.{domain}' with at least 'p=none' to start receiving reports, progressing quickly to 'p=quarantine' or 'p=reject'.",
    ("DMARC", CheckStatus.WARN): "Upgrade your DMARC policy from monitoring ('p=none') to active enforcement ('p=quarantine' or 'p=reject') and set 'pct=100'.",
    ("DKIM", CheckStatus.WARN): "Configure cryptographic DKIM signing on your email delivery services and publish the public key under your DNS domain key selector.",
    ("DKIM", CheckStatus.FAIL): "Implement DKIM signing to protect email integrity and prevent message tampering in transit.",
    ("MX & STARTTLS", CheckStatus.FAIL): "Configure standard MX records pointing to reputable mail exchangers to receive incoming emails.",
    ("MX & STARTTLS", CheckStatus.WARN): "Enable STARTTLS on your mail server to ensure incoming email connections are encrypted using TLS."
}


def extract_dns_findings(checks: List[CheckResult], domain: str) -> List[SecurityFinding]:
    """Translates DNS and protocol check results into standardized SecurityFindings."""
    findings: List[SecurityFinding] = []

    for check in checks:
        if check.status == CheckStatus.PASS:
            continue

        details = check.details if isinstance(check.details, dict) else {}

        if check.name == "SPF":
            if check.status == CheckStatus.FAIL:
                findings.append(SecurityFinding(
                    title="Missing or Invalid SPF Record",
                    severity=FindingSeverity.HIGH,
                    category="DNS",
                    description=details.get("message", f"No valid SPF record found for {domain}."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("SPF", CheckStatus.FAIL))
                ))
            elif check.status == CheckStatus.WARN:
                findings.append(SecurityFinding(
                    title="Permissive or Suboptimal SPF Policy",
                    severity=FindingSeverity.MEDIUM,
                    category="DNS",
                    description=details.get("message", f"SPF configuration for {domain} has warnings."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("SPF", CheckStatus.WARN))
                ))

        elif check.name == "DMARC":
            if check.status == CheckStatus.FAIL:
                findings.append(SecurityFinding(
                    title="Missing DMARC Protection",
                    severity=FindingSeverity.HIGH,
                    category="DNS",
                    description=details.get("message", f"Domain {domain} does not publish a DMARC policy."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("DMARC", CheckStatus.FAIL))
                ))
            elif check.status == CheckStatus.WARN:
                findings.append(SecurityFinding(
                    title="DMARC Policy in Monitoring Mode (p=none)",
                    severity=FindingSeverity.MEDIUM,
                    category="DNS",
                    description=details.get("message", f"DMARC policy for {domain} is not actively enforced."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("DMARC", CheckStatus.WARN))
                ))

        elif check.name == "DKIM":
            if check.status in [CheckStatus.WARN, CheckStatus.FAIL]:
                findings.append(SecurityFinding(
                    title="DKIM Selector Unverified",
                    severity=FindingSeverity.LOW,
                    category="DNS",
                    description=details.get("message", f"Common DKIM selectors could not be resolved for {domain}."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("DKIM", check.status))
                ))

        elif check.name == "MX & STARTTLS":
            if check.status == CheckStatus.FAIL:
                findings.append(SecurityFinding(
                    title="Inbound Mail Delivery Not Configured (Missing MX)",
                    severity=FindingSeverity.HIGH,
                    category="Protocol",
                    description=details.get("message", f"No MX records found for {domain}."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("MX & STARTTLS", CheckStatus.FAIL))
                ))
            elif check.status == CheckStatus.WARN:
                findings.append(SecurityFinding(
                    title="STARTTLS Not Enabled on Primary MX",
                    severity=FindingSeverity.HIGH,
                    category="Protocol",
                    description=details.get("message", f"Primary MX exchanger does not advertise STARTTLS."),
                    recommendation=check.recommendation or DEFAULT_RECOMMENDATIONS.get(("MX & STARTTLS", CheckStatus.WARN))
                ))

    return findings


def calculate_posture_score(
    checks: List[CheckResult],
    domain: str = "",
    crypto_posture: Optional[CryptographicPosture] = None,
    findings: Optional[List[SecurityFinding]] = None
) -> Tuple[int, str, List[str], List[SecurityFinding]]:
    """
    Calculates 0-100 posture score deterministically using real cryptographic findings:
      Base Score = 100
      Deductions:
        - No SPF: -15 pts (Softfail / Misconfigured: -5 pts)
        - No DMARC: -25 pts (p=none: -10 pts)
        - Missing / Insecure STARTTLS: -30 pts
        - Deprecated TLS (TLS 1.0/1.1): -20 pts
        - Weak Ciphers (3DES, RC4, CBC): -15 pts
        - Missing MTA-STS or DANE TLSA: -10 pts
        - No Hybrid Post-Quantum Key Exchange (ML-KEM / Kyber): -5 pts
      Bounds: floor of 0, ceiling of 100.
      Grades: 90-100 (A+), 80-89 (A), 70-79 (B), 50-69 (C), <50 (F).
    """
    score = 100
    recommendations: List[str] = []

    # Map checks by name for lookup
    check_map: Dict[str, CheckResult] = {c.name: c for c in checks}

    # 1. SPF Deductions: No SPF (-15 pts), Softfail / Misconfigured (-5 pts)
    spf = check_map.get("SPF")
    if not spf or spf.status in [CheckStatus.FAIL, CheckStatus.UNKNOWN] or (isinstance(spf.details, dict) and spf.details.get("record_value") == "No record published"):
        score -= 15
        if spf and spf.recommendation:
            recommendations.append(spf.recommendation)
    else:
        details = spf.details if isinstance(spf.details, dict) else {}
        val = str(details.get("record_value", "")).lower()
        pol = str(details.get("policy", "")).lower()
        lookups = details.get("lookups", 0)
        is_misconfigured = (
            spf.status == CheckStatus.WARN
            or "~all" in val
            or "?all" in val
            or "+all" in val
            or "softfail" in pol
            or "neutral" in pol
            or (isinstance(lookups, int) and lookups > 10)
        )
        if is_misconfigured:
            score -= 5
            if spf.recommendation:
                recommendations.append(spf.recommendation)

    # 2. DMARC Deductions: Missing DMARC (-25 pts), p=none monitoring mode (-10 pts), p=quarantine (-5 pts), p=reject (+0)
    dmarc = check_map.get("DMARC")
    if not dmarc or dmarc.status in [CheckStatus.FAIL, CheckStatus.UNKNOWN] or (isinstance(dmarc.details, dict) and dmarc.details.get("record_value") == "No record published"):
        score -= 25
        if dmarc and dmarc.recommendation:
            recommendations.append(dmarc.recommendation)
    else:
        details = dmarc.details if isinstance(dmarc.details, dict) else {}
        val = str(details.get("record_value", "")).lower()
        pol = str(details.get("policy", "")).lower()
        enf = str(details.get("enforcement", "")).lower()
        if "p=none" in val or "none" in pol or "monitoring" in enf:
            score -= 10
            if dmarc.recommendation:
                recommendations.append(dmarc.recommendation)
        elif "p=quarantine" in val or "quarantine" in pol or "quarantine" in enf:
            score -= 5
            if dmarc.recommendation:
                recommendations.append(dmarc.recommendation)
        elif "reject" in pol or "p=reject" in val or dmarc.status == CheckStatus.PASS:
            # p=reject (+0)
            pass

    # 3. Protocol & TLS Cryptographic Evaluation
    # STARTTLS / Encryption: TLS 1.3 (+0) | TLS 1.2 (-5) | Missing/Broken STARTTLS (-25)
    audited = crypto_posture.protocols_audited if crypto_posture else []
    successful_handshakes = [
        a.tls_handshake for a in audited if a.tls_handshake and a.tls_handshake.success
    ]

    # Check if domain has published MX hosts
    has_published_mx = any(
        a.host != domain or (a.tls_handshake and a.tls_handshake.success)
        for a in audited
    )
    if not has_published_mx and not audited:
        mx_check = check_map.get("MX & STARTTLS")
        has_published_mx = mx_check and mx_check.status != CheckStatus.FAIL

    has_valid_starttls = len(successful_handshakes) > 0
    has_tls_13 = False
    has_tls_12 = False
    has_deprecated_tls = False
    has_weak_cipher = False
    has_pqc = False
    has_forward_secrecy = False

    if crypto_posture:
        if crypto_posture.deprecated_tls_found:
            has_deprecated_tls = True
        if crypto_posture.weak_ciphers_found:
            has_weak_cipher = True

    for h in successful_handshakes:
        ver = str(h.negotiated_version or "").upper()
        if "1.3" in ver:
            has_tls_13 = True
        elif "1.2" in ver:
            has_tls_12 = True
        elif any(v in ver for v in ["1.0", "1.1", "SSLV2", "SSLV3"]):
            has_deprecated_tls = True
        c = h.cipher
        if c:
            c_name = str(c.name or "").upper()
            if c.is_weak or any(w in c_name for w in ["3DES", "RC4", "CBC", "DES", "MD5", "NULL", "EXPORT"]):
                has_weak_cipher = True
            if c.pqc_hybrid:
                has_pqc = True
            if c.forward_secrecy:
                has_forward_secrecy = True

    mx_check = check_map.get("MX & STARTTLS")
    if not has_valid_starttls and mx_check and mx_check.status == CheckStatus.PASS:
        has_valid_starttls = True
        has_tls_12 = True

    # Missing / Broken STARTTLS or Insecure Cipher: -25 pts (applicable when mail exchange is present)
    if has_published_mx and not has_valid_starttls:
        score -= 25
        recommendations.append("Mandate opportunistic or enforced STARTTLS with modern TLS 1.2+ on all inbound mail exchangers.")
    elif has_deprecated_tls:
        score -= 20
        recommendations.append("Disable deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and mandate TLS 1.2 or TLS 1.3.")
    elif has_tls_13:
        # TLS 1.3 (+0)
        pass
    elif has_tls_12:
        # TLS 1.2 (-5)
        score -= 5
        recommendations.append("Upgrade mail exchanger TLS capability from TLS 1.2 to modern TLS 1.3.")

    # Weak Ciphers (3DES, RC4, CBC): -15 pts
    if has_weak_cipher:
        score -= 15
        recommendations.append("Eliminate weak ciphers (3DES, RC4, CBC-mode ciphers) in favor of modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).")

    # Missing MTA-STS or DANE TLSA: -10 pts
    mta_sts = check_map.get("MTA-STS")
    dane = check_map.get("DANE/TLSA") or check_map.get("TLSA")
    has_sts = mta_sts and mta_sts.status == CheckStatus.PASS
    has_dane = dane and dane.status == CheckStatus.PASS
    if not (has_sts or has_dane):
        score -= 10
        if mta_sts and mta_sts.recommendation:
            recommendations.append(mta_sts.recommendation)
        elif dane and dane.recommendation:
            recommendations.append(dane.recommendation)
        else:
            recommendations.append("Publish MTA-STS (RFC 8461) or DANE TLSA records (RFC 7672) to enforce cryptographic transport security.")

    # No Hybrid Post-Quantum Key Exchange (ML-KEM / Kyber): -5 pts
    if not has_pqc:
        score -= 5
        recommendations.append("Upgrade cryptographic key exchange to hybrid post-quantum algorithms (e.g., X25519 + ML-KEM-768 / Kyber per NIST FIPS 203).")

    # Enforce floor of 0 and ceiling of 100
    score = max(0, min(100, score))

    # Assign Grades deterministically: 90–100 (A+), 80–89 (A), 70–79 (B), 50–69 (C), <50 (F)
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"

    # Aggregate and prioritize findings
    dns_findings = extract_dns_findings(checks, domain)
    crypto_findings = crypto_posture.prioritized_findings if crypto_posture else []
    extra_findings = findings or []

    combined_findings: List[SecurityFinding] = []
    seen = set()

    for f in crypto_findings + dns_findings + extra_findings:
        if f.title not in seen:
            combined_findings.append(f)
            seen.add(f.title)

    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4
    }
    combined_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    return score, grade, recommendations, combined_findings


def legacy_weighted_score(
    checks: List[CheckResult],
    domain: str,
    crypto_posture: Optional[CryptographicPosture] = None
) -> Tuple[int, List[str], List[SecurityFinding]]:
    """
    LEGACY scoring function - renamed from calculate_overall_score.
    Kept for backward compatibility and side-by-side comparison.
    Uses deterministic weighted penalty-based scoring.
    """
    score, _, recommendations, findings = calculate_posture_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture
    )
    return score, recommendations, findings


def calculate_overall_score(
    checks: List[CheckResult],
    domain: str,
    crypto_posture: Optional[CryptographicPosture] = None,
    banner: Optional[str] = None,
    is_customer_facing: bool = False
) -> Tuple[int, Optional[float], Optional[str], Optional[Dict[str, float]], Optional[List[str]], Optional[float], List[str], List[SecurityFinding]]:
    """
    New scoring function using hierarchical fuzzy logic risk engine.
    
    Returns:
        Tuple of (
            legacy_score: int (for backward compatibility),
            fuzzy_score: float (new fuzzy logic score),
            linguistic_classification: str,
            antecedent_scores: dict,
            activated_rules: list,
            defuzzification_confidence: float,
            recommendations: list,
            findings: list
        )
    """
    from app.risk_engine import (
        compute_crypto_deprecation_index,
        compute_posture_exposure_deficit,
        compute_exploitation_likelihood_index,
        compute_posture_risk,
        compute_posture_risk_unobserved_transport,
    )
    
    # Keep legacy scoring for backward compatibility
    legacy_score, _, recommendations, findings = calculate_posture_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture
    )
    
    # Extract data for fuzzy logic inputs
    check_map = {c.name: c for c in checks}
    
    # Crypto inputs
    audited = crypto_posture.protocols_audited if crypto_posture else []
    successful_handshakes = [a.tls_handshake for a in audited if a.tls_handshake and a.tls_handshake.success]
    
    tls_version = None
    cipher_name = None
    key_algorithm = None
    key_size_bits = None
    days_until_expiry = None
    forward_secrecy = False
    signature_algorithm = None
    is_self_signed = False
    chain_valid = True
    
    if successful_handshakes:
        h = successful_handshakes[0]
        tls_version = h.negotiated_version
        if h.cipher:
            cipher_name = h.cipher.name
            forward_secrecy = h.cipher.forward_secrecy if h.cipher else False
        if h.certificate:
            key_algorithm = h.certificate.public_key_algorithm
            key_size_bits = h.certificate.key_size_bits
            days_until_expiry = h.certificate.days_until_expiry
            signature_algorithm = h.certificate.signature_algorithm
            is_self_signed = h.certificate.is_self_signed
            if h.certificate.chain_valid is False:
                chain_valid = False
    
    # If no forward_secrecy detected in handshake, check crypto_posture global flag
    if not forward_secrecy and crypto_posture:
        forward_secrecy = crypto_posture.forward_secrecy_supported
    
    # Email auth inputs
    spf = check_map.get("SPF")
    dkim = check_map.get("DKIM")
    dmarc = check_map.get("DMARC")
    dane = check_map.get("DANE/TLSA") or check_map.get("TLSA")
    
    spf_present = spf and spf.status == CheckStatus.PASS
    dkim_present = dkim and dkim.status == CheckStatus.PASS
    
    dmarc_policy = ""
    dmarc_enforcement = ""
    if dmarc and dmarc.status != CheckStatus.FAIL:
        details = dmarc.details if isinstance(dmarc.details, dict) else {}
        dmarc_policy = details.get("record_value", "")
        dmarc_enforcement = details.get("enforcement", "")
    
    dnssec_enabled = False
    if dane and dane.status == CheckStatus.PASS:
        details = dane.details if isinstance(dane.details, dict) else {}
        # DEF-02 fix: read the explicit dnssec_validated boolean set by active_scanner.py.
        # Fall back to the legacy "enabled" string check for backward compatibility.
        raw = details.get("dnssec_validated")
        if isinstance(raw, bool):
            dnssec_enabled = raw
        else:
            dnssec_enabled = "enabled" in str(details.get("dnssec", "")).lower()
    
    # Banner for software vulnerability check
    banner_str = banner
    if not banner_str and audited:
        banner_str = audited[0].banner if audited[0].banner else None
    
    # Compute Tier 1 composite indices
    cdi_score, cdi_factors = compute_crypto_deprecation_index(
        tls_version=tls_version or "",
        cipher_name=cipher_name or "",
        key_algorithm=key_algorithm or "",
        key_size_bits=key_size_bits,
        days_until_expiry=days_until_expiry,
        forward_secrecy=forward_secrecy
    )
    
    ped_score, ped_factors = compute_posture_exposure_deficit(
        spf_present=spf_present,
        dkim_present=dkim_present,
        dmarc_policy=dmarc_policy,
        dmarc_enforcement=dmarc_enforcement,
        dnssec_enabled=dnssec_enabled
    )
    
    eli_score, eli_factors = compute_exploitation_likelihood_index(
        banner=banner_str,
        is_customer_facing=is_customer_facing
    )
    
    # Derive granular antecedent components
    # 1. tls_compliance: TLS 1.3 -> 1.0, TLS 1.2 -> 0.75, older -> 0.1
    tls_upper = (tls_version or "").upper()
    if "1.3" in tls_upper:
        tls_comp = 1.0
    elif "1.2" in tls_upper:
        tls_comp = 0.75
    else:
        tls_comp = 0.1

    # 2. cipher_strength: derived from cipher classification
    from app.risk_engine.crypto_deprecation import classify_cipher_strength
    c_class = classify_cipher_strength(cipher_name or "")
    c_strength = 1.0 if c_class == "strong" else (0.6 if c_class == "moderate" else 0.1)

    # 3. certificate_health: derived from cert validity days, signature algorithm, self-signed & chain status
    if days_until_expiry is None or days_until_expiry <= 0:
        cert_hlth = 0.0
    elif days_until_expiry >= 90:
        cert_hlth = 1.0
    elif days_until_expiry >= 30:
        cert_hlth = round(0.5 + (days_until_expiry - 30) / 60.0 * 0.5, 3)
    else:
        cert_hlth = round(max(0.0, days_until_expiry / 30.0 * 0.5), 3)

    # Penalize for deprecated signature algorithms (Task 2.3) and untrusted/self-signed chain (Task 2.4)
    sig_lower = (signature_algorithm or "").lower()
    if any(weak in sig_lower for weak in ["sha1", "md5", "sha-1"]):
        cert_hlth = min(cert_hlth, 0.1)
    if is_self_signed or not chain_valid:
        cert_hlth = min(cert_hlth, 0.2)

    # 4. pqc_readiness — DEF-03 fix: wired to live PQC detection from cipher handshake.
    #    has_pqc is already computed above in calculate_posture_score() via c.pqc_hybrid.
    #    TLS 1.3 hybrid key exchange groups (X25519Kyber768Draft00, ML-KEM-768 per
    #    NIST FIPS 203) set CipherSuiteInfo.pqc_hybrid = True in cipher_evaluator.py.
    #    1.0 = hybrid PQC key exchange confirmed (quantum-safe forward secrecy)
    #    0.1 = classical-only key exchange (vulnerable to store-now-decrypt-later)
    has_pqc_live = False
    for h in successful_handshakes:
        if h.cipher and h.cipher.pqc_hybrid:
            has_pqc_live = True
            break
    pqc_readiness = 1.0 if has_pqc_live else 0.1

    raw_crypto_metrics = {
        'tls_compliance': tls_comp,
        'cipher_strength': c_strength,
        'certificate_health': cert_hlth,
        'pqc_readiness': pqc_readiness
    }

    # Transport telemetry availability.
    # ---------------------------------------------------------------------------
    # A completed TLS handshake is the only evidence that the transport layer was
    # genuinely observed. When no handshake completed, every value fed into the
    # Crypto Deprecation Index is a placeholder (empty version/cipher strings,
    # no key, no certificate), which defuzzifies to a worst-case CDI of ~86.04.
    # The Tier 2 non-dilution OR rule then promotes that artifact to CRITICAL with
    # a posture score of 0 — asserting catastrophic cryptography for a mail
    # exchanger the scan never reached. Instead, exclude the unobserved CDI and
    # renormalise the fused score over the dimensions that WERE observed.
    transport_observed = len(successful_handshakes) > 0

    # Publish the flag so the API response can report the transport layer as
    # UNAUDITED. ``crypto_posture`` is the same model instance that is embedded in
    # the response payload, so clients see the flag without a contract change.
    if crypto_posture is not None:
        try:
            crypto_posture.telemetry_observed = transport_observed
        except (AttributeError, ValueError):  # pragma: no cover - defensive
            pass

    # Compute Tier 2 final fusion (returns posture risk score 0-100, where 0=low risk and 100=critical risk)
    if transport_observed:
        fuzzy_risk_score, linguistic_classification, antecedent_scores, risk_factors = compute_posture_risk(
            cdi_score=cdi_score,
            ped_score=ped_score,
            eli_score=eli_score,
            raw_crypto_metrics=raw_crypto_metrics
        )
    else:
        fuzzy_risk_score, linguistic_classification, antecedent_scores, risk_factors = (
            compute_posture_risk_unobserved_transport(
                ped_score=ped_score,
                eli_score=eli_score,
            )
        )
        # Disclose the exclusion explicitly so neither an analyst nor a judge can
        # mistake an unaudited transport layer for a clean cryptographic result.
        findings = list(findings) + [
            SecurityFinding(
                title="Transport Layer Not Observed",
                severity=FindingSeverity.LOW,
                category="Protocol",
                description=(
                    "No TLS handshake completed for any mail exchanger, so the "
                    "transport layer was not observed (port 25 unreachable, "
                    "STARTTLS blocked, or the scan ran degraded). Cryptographic "
                    "properties such as TLS version, cipher strength and "
                    "certificate health are therefore unknown, not necessarily "
                    "weak. The fused posture score excludes this unobserved "
                    "dimension and reflects only verifiable DNS authentication "
                    "and exposure records."
                ),
                recommendation=(
                    "Re-run the scan from a network path that permits outbound "
                    "TCP/25 to obtain transport telemetry before drawing any "
                    "conclusion about cryptographic posture."
                ),
            )
        ]
    
    # Convert fuzzy risk score (0-100, where 100=highest risk) to posture score (0-100, where 100=best posture)
    # matching the 0-100 range and semantics of legacy "score" per frontend contract (ScanResponse)
    fuzzy_posture_score = round(max(0.0, min(100.0, 100.0 - fuzzy_risk_score)), 1)

    # Collect all contributing factors for explainability
    all_factors = cdi_factors + ped_factors + eli_factors + risk_factors
    
    # Extract activated rules (human-readable descriptions)
    activated_rules = [
        f["description"] for f in all_factors
        if f.get("category") == "Fired Rules" and "description" in f
    ]

    # DEF-06 fix: derive defuzzification confidence dynamically from firing strengths.
    # Parse the activation values embedded in the rule strings (format: "... (activation: X.XX)").
    # confidence = max single-rule activation, clamped to [0.0, 1.0].
    # Returns 0.0 when the FIS fell back to a default median (no rules fired above threshold).
    import re as _re
    _activation_pattern = _re.compile(r"\(activation:\s*([\d.]+)\)")
    firing_strengths: List[float] = []
    for rule_str in activated_rules:
        m = _activation_pattern.search(rule_str)
        if m:
            try:
                firing_strengths.append(float(m.group(1)))
            except ValueError:
                pass
    defuzzification_confidence = round(max(firing_strengths), 4) if firing_strengths else 0.0
    
    return (
        legacy_score,
        fuzzy_posture_score,
        linguistic_classification,
        antecedent_scores,
        activated_rules,
        defuzzification_confidence,
        recommendations,
        findings
    )

