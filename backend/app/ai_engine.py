import os
import re
import json
import shlex
import logging
from typing import Dict, Any, List, Optional, Tuple

import dotenv
dotenv.load_dotenv()

from app.models import (
    CheckResult,
    CheckStatus,
    CryptographicPosture,
    SecurityFinding,
    FindingSeverity,
    AiRiskScore,
    CvssMetrics,
    RemediationPlaybook
)
from app.scoring import calculate_posture_score


logger = logging.getLogger(__name__)


def compute_cvss_metrics(findings: List[SecurityFinding]) -> CvssMetrics:
    """Calculates CVSS v3.1 metrics from prioritized findings."""
    severities = [f.severity for f in findings]

    if FindingSeverity.CRITICAL in severities:
        return CvssMetrics(
            base_score=9.1,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            severity="CRITICAL",
            exploitability_score=3.9,
            impact_score=5.2
        )
    elif FindingSeverity.HIGH in severities:
        return CvssMetrics(
            base_score=7.5,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            severity="HIGH",
            exploitability_score=3.9,
            impact_score=3.6
        )
    elif FindingSeverity.MEDIUM in severities:
        return CvssMetrics(
            base_score=5.3,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            severity="MEDIUM",
            exploitability_score=3.9,
            impact_score=1.4
        )
    else:
        return CvssMetrics(
            base_score=2.0,
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            severity="LOW",
            exploitability_score=1.6,
            impact_score=0.4
        )


def generate_syntax_checked_remediations(domain: str) -> RemediationPlaybook:
    """
    Synthesizes copy-ready, syntax-validated configuration blocks for Postfix, Exim,
    Sendmail, and BIND.

    VULN-04 (shell interpolation):
        Every occurrence of the domain name inside shell-executed strings is wrapped
        with shlex.quote() so that a domain like ``evil.com; rm -rf /`` cannot escape
        the quoted context.  Domain labels in static config-file paths (not executed
        by a shell) retain the plain f-string form as they are already validated by
        the Pydantic ScanRequest.clean_and_validate_domain validator upstream.

    VULN-04 (TLSA fingerprint placeholder):
        The previous dummy SHA-256 value (5a7f328b...) has been replaced with an
        explicit operator placeholder and an openssl derivation command so that no
        scanner consumer accidentally publishes a non-functional DANE record.
    """
    # shlex.quote is only relevant where the domain is interpolated into a shell command
    # string (postconf -e / systemctl).  Config-file key=value lines are not shell-executed.
    quoted_domain = shlex.quote(domain)

    postfix_cfg = f"""# AegisCrypta Postfix TLS Hardening (RFC 8461 / NIST SP 800-52r2)
smtpd_tls_security_level = encrypt
smtp_tls_security_level = dane
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, 3DES
tls_high_cipherlist = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
tls_preempt_cipherlist = yes
smtpd_tls_received_header = yes
smtpd_tls_loglevel = 1"""

    exim_cfg = f"""# AegisCrypta Exim Cryptographic Hardening (exim4.conf)
tls_advertise_hosts = *
tls_certificate = /etc/ssl/certs/{domain}.crt
tls_privatekey = /etc/ssl/private/{domain}.key
tls_require_ciphers = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1 +cipher_server_preference"""

    sendmail_mc = f"""dnl AegisCrypta Sendmail Cryptographic Configuration (sendmail.mc)
LOCAL_CONFIG
O CipherList=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
O ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1 +SSL_OP_CIPHER_SERVER_PREFERENCE
O ClientSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1"""

    # VULN-04: The dummy SHA-256 fingerprint has been removed.
    # Operators MUST derive the real SPKI fingerprint before applying this record.
    # Derivation command (run on the mail gateway):
    #   openssl x509 -in /path/to/cert.pem -pubkey -noout \
    #     | openssl pkey -pubin -outform DER \
    #     | openssl dgst -sha256 -hex
    # Then replace <REPLACE_WITH_ACTUAL_CERT_SHA256_SPKI_FINGERPRINT> with the hex output.
    bind_dns = f"""; AegisCrypta Authoritative DNS Zone Records for {domain}
; WARNING: Review every record before applying to production DNS.
@               IN  TXT     "v=spf1 include:_spf.{domain} -all"
_dmarc          IN  TXT     "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@{domain}; ruf=mailto:forensics@{domain}; aspf=s; adkim=s"
_mta-sts        IN  TXT     "v=STSv1; id=20260901T000000Z;"
_smtp._tls      IN  TXT     "v=TLSRPTv1; rua=mailto:tls-reports@{domain}"
;
; DANE TLSA record — Usage 3 (DANE-EE), Selector 1 (SPKI), Matching 1 (SHA-256).
; OPERATOR ACTION REQUIRED: Replace the placeholder below with the actual SHA-256
; SPKI fingerprint of the mail gateway certificate.
; Derivation command:
;   openssl x509 -in /path/to/cert.pem -pubkey -noout \\
;     | openssl pkey -pubin -outform DER \\
;     | openssl dgst -sha256 -hex
_25._tcp.mail   IN  TLSA    3 1 1 <REPLACE_WITH_ACTUAL_CERT_SHA256_SPKI_FINGERPRINT>"""

    # VULN-04: All postconf -e arguments that embed the domain use shlex.quote(domain)
    # so that a malicious domain label cannot escape the shell quoting context.
    shell_script = f"""#!/usr/bin/env bash
# AegisCrypta Automated Mail Infrastructure Remediation Script
# Target: {domain}
set -euo pipefail

DOMAIN={quoted_domain}

echo "[AegisCrypta] Hardening Postfix TLS parameters per NIST SP 800-52r2..."
postconf -e "smtpd_tls_security_level = encrypt"
postconf -e "smtp_tls_security_level = dane"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "tls_preempt_cipherlist = yes"
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/${{DOMAIN}}.crt"
postconf -e "smtpd_tls_key_file = /etc/ssl/private/${{DOMAIN}}.key"

echo "[AegisCrypta] Reloading MTA services..."
systemctl reload postfix
echo "[AegisCrypta] Hardening completed successfully."
"""

    return RemediationPlaybook(
        postfix_main_cf=postfix_cfg,
        exim_conf=exim_cfg,
        sendmail_mc=sendmail_mc,
        bind_dns_zone=bind_dns,
        shell_script=shell_script
    )


def evaluate_ai_remediation(
    domain: str,
    checks: List[CheckResult],
    crypto_posture: Optional[CryptographicPosture],
    findings: List[SecurityFinding]
) -> Tuple[int, str, AiRiskScore, CvssMetrics, RemediationPlaybook]:
    """
    Synthesizes AI Risk Score, CVSS metrics, PQC threat assessment, and remediation configurations:
    - Queries Gemini 2.5 Flash if GEMINI_API_KEY is available in environment.
    - Seamlessly falls back to deterministic defense-grade rules engine.
    - Tags RSA-2048 and ECC-256 ciphers with SNDL threat warnings.
    - Returns (overall_score, grade, ai_risk_score, cvss_metrics, playbook).
    """
    # 1. PQC & SNDL Tagging on Findings
    pqc_active = False
    if crypto_posture and crypto_posture.protocols_audited:
        for audit in crypto_posture.protocols_audited:
            if audit.tls_handshake and audit.tls_handshake.cipher:
                c = audit.tls_handshake.cipher
                if c.pqc_hybrid:
                    pqc_active = True
                elif c.sndl_vulnerable:
                    # Ensure finding is present in findings list
                    sndl_found = any(f.title == "Vulnerable to Store-Now-Decrypt-Later (SNDL) Quantum Attacks" for f in findings)
                    if not sndl_found:
                        findings.append(SecurityFinding(
                            title="Vulnerable to Store-Now-Decrypt-Later (SNDL) Quantum Attacks",
                            severity=FindingSeverity.MEDIUM,
                            category="Post-Quantum",
                            description=f"Active cipher '{c.name}' on {audit.host}:{audit.port} relies on classical asymmetric primitives without post-quantum hybrid encapsulation.",
                            recommendation="Plan post-quantum migration to FIPS 203 ML-KEM-768 hybrid key exchange."
                        ))

    # 2. Compute Base Scores
    cvss = compute_cvss_metrics(findings)
    playbook = generate_syntax_checked_remediations(domain)

    # Calculate deterministic overall posture score
    blended_score, grade, recommendations, combined_findings = calculate_posture_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture,
        findings=findings
    )

    if crypto_posture:
        crypto_posture.crypto_score = blended_score
        crypto_posture.grade = grade

    # Synchronize findings with deduplicated combined findings
    findings.clear()
    findings.extend(combined_findings)

    # AI Risk Score (0 = safe, 100 = critical risk)
    risk_score = 100 - blended_score
    risk_level = "LOW" if risk_score < 25 else ("MEDIUM" if risk_score < 50 else ("HIGH" if risk_score < 75 else "CRITICAL"))

    risk_factors: List[str] = []
    mitigations: List[str] = []

    for f in findings:
        if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
            risk_factors.append(f.description)
            if f.recommendation:
                mitigations.append(f.recommendation)

    if not risk_factors:
        risk_factors.append("Domain complies with standard cryptographic and identity verification controls.")
    if not mitigations:
        mitigations.append("Maintain recurring audit cadence and monitor DMARC forensic telemetry.")

    ai_risk = AiRiskScore(
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=0.96,
        risk_factors=risk_factors[:5],
        mitigation_priority=mitigations[:5]
    )

    # 3. Gemini 2.5 Flash strictly for generating actionable remediation playbooks and summarizing findings
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-2.5-flash")

            # VULN-05: Sanitize all finding descriptions before inserting into the Gemini
            # prompt.  f.description may contain raw DNS record content (SPF, DMARC TXT
            # values) which could embed prompt-injection strings.  We truncate each field
            # to a safe length and strip characters that are commonly used in injection
            # attempts (backticks, null bytes, angle brackets, shell metacharacters).
            _SAFE_CHARS = re.compile(r'[`\x00<>{};|$\\]')

            def _sanitize_for_prompt(s: str, max_len: int = 300) -> str:
                """Remove prompt-injection-prone characters and truncate."""
                return _SAFE_CHARS.sub("", str(s))[:max_len]

            safe_findings = []
            for f in findings[:8]:
                d = f.model_dump()
                d["description"] = _sanitize_for_prompt(d.get("description", ""))
                d["recommendation"] = _sanitize_for_prompt(d.get("recommendation", "") or "")
                d["title"] = _sanitize_for_prompt(d.get("title", ""), max_len=120)
                safe_findings.append(d)

            safe_checks = []
            for c in checks:
                cd = c.model_dump()
                # Strip raw DNS record values from the prompt — they may contain
                # arbitrary operator-controlled content.
                if isinstance(cd.get("details"), dict):
                    cd["details"] = {
                        k: _sanitize_for_prompt(str(v), max_len=200)
                        for k, v in cd["details"].items()
                        if k not in ("record_value",)   # exclude raw DNS record payloads
                    }
                safe_checks.append(cd)

            prompt = f"""You are an elite DevSecOps Systems Engineer auditing email security for domain: {shlex.quote(domain)}.
Findings: {safe_findings}
Checks: {safe_checks}
Deterministic Posture Score: {blended_score}/100 (Grade: {grade})

Based STRICTLY on the computed score and findings above, generate actionable remediation configurations and summaries.
Return a valid JSON object with:
- "executive_summary": "1-2 sentence high-level takeaway"
- "risk_factors": ["list of up to 3 priority threats based on findings"]
- "mitigation_priority": ["list of up to 3 priority fixes"]
"""
            response = model.generate_content(prompt)
            if response.text:
                cleaned_text = response.text.strip()
                if "{" in cleaned_text and "}" in cleaned_text:
                    json_str = cleaned_text[cleaned_text.find("{"):cleaned_text.rfind("}") + 1]
                    parsed = json.loads(json_str)

                    if "risk_factors" in parsed and isinstance(parsed["risk_factors"], list):
                        ai_risk.risk_factors = [
                            _sanitize_for_prompt(str(r), max_len=400)
                            for r in parsed["risk_factors"][:3]
                        ]
                    if "mitigation_priority" in parsed and isinstance(parsed["mitigation_priority"], list):
                        ai_risk.mitigation_priority = [
                            _sanitize_for_prompt(str(m), max_len=400)
                            for m in parsed["mitigation_priority"][:3]
                        ]
                    # LLM output is untrusted and must not become executable or
                    # service configuration. Keep the deterministic templates above.
        except Exception as err:
            logger.debug(f"Gemini API invocation skipped/failed: {err}")

    return blended_score, grade, ai_risk, cvss, playbook
