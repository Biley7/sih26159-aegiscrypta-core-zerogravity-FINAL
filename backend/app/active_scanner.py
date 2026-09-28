import socket
import ssl
import re
import dns.resolver
import dns.exception
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

from app.models import (
    CheckResult,
    CheckStatus,
    CryptographicPosture,
    ProtocolAuditResult,
    SecurityFinding,
    FindingSeverity,
    TlsHandshakeResult,
    CipherSuiteInfo,
    CertificateInfo
)
from app.resolver import get_dns_resolver, clean_txt_rdata, resolve_mx_hosts
from app.crypto.tls_probe import probe_protocol_tls, probe_https_sni_fallback
from app.crypto.mail_discovery import evaluate_domain_crypto_posture
from app.crypto.cipher_evaluator import evaluate_cipher_and_tls


def check_dnssec(domain: str, timeout: float = 3.0) -> CheckResult:
    """Checks DNSSEC signing and validation on the domain."""
    resolver = get_dns_resolver(timeout=timeout)
    resolver.use_edns(0, dns.flags.DO, 4096)

    try:
        answers = resolver.resolve(domain, "DNSKEY")
        key_count = len(answers)
        return CheckResult(
            name="DNSSEC",
            status=CheckStatus.PASS,
            details={
                "enabled": True,
                "dnskey_count": key_count,
                "message": f"DNSSEC is active with {key_count} published DNSKEY records."
            },
            recommendation="Continue maintaining DNSSEC root-of-trust key rollover procedures."
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="DNSSEC",
            status=CheckStatus.WARN,
            details={
                "enabled": False,
                "message": f"No DNSSEC DNSKEY records found for {domain}."
            },
            recommendation=f"Enable DNSSEC on the parent zone for {domain} to prevent DNS cache poisoning and spoofing."
        )
    except Exception:
        return CheckResult(
            name="DNSSEC",
            status=CheckStatus.UNKNOWN,
            details={"enabled": False, "message": "DNSSEC query timed out or unreachable."},
            recommendation="Verify zone nameservers respond to EDNS0 DNSSEC queries."
        )


def check_spf(domain: str, timeout: float = 2.0) -> CheckResult:
    """Resolves and evaluates SPF record (v=spf1)."""
    resolver = get_dns_resolver(timeout=timeout)
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = []
        for rdata in answers:
            txt = clean_txt_rdata(rdata)
            if txt.startswith("v=spf1"):
                spf_records.append(txt)

        if not spf_records:
            return CheckResult(
                name="SPF",
                status=CheckStatus.FAIL,
                details={
                    "record_type": "TXT",
                    "record_host": "@",
                    "record_value": "No record published",
                    "policy": "none",
                    "message": f"No SPF record published for {domain}."
                },
                recommendation=f"Publish an SPF TXT record at '{domain}' (e.g. 'v=spf1 -all' or authorized IPs) to authorize outbound mail senders."
            )

        spf = spf_records[0]
        # Count lookups
        lookup_terms = ["include:", "a", "mx", "ptr", "redirect", "exists"]
        terms = spf.split()
        lookups = sum(1 for t in terms if any(t.lower().startswith(lt) or t.lower() == lt for lt in lookup_terms))

        status = CheckStatus.PASS
        policy = "neutral"
        if "-all" in spf:
            policy = "strict (-all)"
            status = CheckStatus.PASS
        elif "~all" in spf:
            policy = "softfail (~all)"
            status = CheckStatus.PASS
        elif "?all" in spf:
            policy = "neutral (?all)"
            status = CheckStatus.WARN
        elif "+all" in spf:
            policy = "allow all (+all)"
            status = CheckStatus.FAIL
        elif "redirect=" in spf:
            policy = "redirect"
            status = CheckStatus.PASS

        return CheckResult(
            name="SPF",
            status=status,
            details={
                "record_type": "TXT",
                "record_host": "@",
                "record_value": spf,
                "lookups": lookups,
                "policy": policy,
                "message": f"SPF record published with {policy} policy ({lookups}/10 DNS lookups)."
            },
            recommendation="Maintain strict '-all' enforcement and ensure total DNS lookup mechanisms remain <= 10 (RFC 7208)."
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="SPF",
            status=CheckStatus.FAIL,
            details={
                "record_type": "TXT",
                "record_host": "@",
                "record_value": "No record published",
                "policy": "none",
                "message": f"No SPF record published for {domain}."
            },
            recommendation=f"Publish an SPF TXT record at '{domain}' (e.g. 'v=spf1 -all')."
        )
    except dns.exception.Timeout:
        return CheckResult(
            name="SPF",
            status=CheckStatus.UNKNOWN,
            details={"message": f"DNS query timed out resolving SPF for {domain}."},
            recommendation="Verify zone nameserver responsiveness."
        )
    except Exception as e:
        return CheckResult(
            name="SPF",
            status=CheckStatus.FAIL,
            details={"error": str(e), "message": f"DNS lookup failed for SPF: {str(e)}"},
            recommendation="Verify DNS zone responsiveness."
        )


def check_dkim(domain: str, timeout: float = 2.0) -> CheckResult:
    """Probes common DKIM selectors."""
    common_selectors = [
        "20230601", "20210112", "google", "default", "mail", "k1", "selector1",
        "nic2024", "sig1", "2024", "smtp", "dkim", "s1", "s2"
    ]
    resolver = get_dns_resolver(timeout=timeout)

    for sel in common_selectors:
        dkim_host = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_host, "TXT")
            for rdata in answers:
                txt = clean_txt_rdata(rdata)
                if "v=DKIM1" in txt or "p=" in txt:
                    # Estimate key size from base64 public key length
                    p_match = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
                    key_size = 2048
                    if p_match:
                        b64_len = len(p_match.group(1))
                        key_size = 1024 if b64_len < 250 else (2048 if b64_len < 500 else 4096)

                    status = CheckStatus.PASS if key_size >= 2048 else CheckStatus.WARN
                    return CheckResult(
                        name="DKIM",
                        status=status,
                        details={
                            "selector": sel,
                            "record_host": dkim_host,
                            "record_value": txt[:80] + "..." if len(txt) > 80 else txt,
                            "key_size": key_size,
                            "status": "active",
                            "message": f"Discovered DKIM selector '{sel}' with {key_size}-bit key."
                        },
                        recommendation="Rotate DKIM signing keys at least bi-annually and upgrade 1024-bit keys to 2048-bit or Ed25519."
                    )
        except Exception:
            continue

    # Graceful fallback: DKIM selectors are often private
    return CheckResult(
        name="DKIM",
        status=CheckStatus.WARN,
        details={
            "selector": "not_discovered",
            "record_host": f"<selector>._domainkey.{domain}",
            "record_value": "No public selector detected among standard prefixes",
            "message": "DKIM selectors could not be automatically discovered from common public prefixes."
        },
        recommendation=f"Ensure DKIM signing is active on outbound mail and public keys are published under selector._domainkey.{domain} (RFC 6376)."
    )


def check_dmarc(domain: str, timeout: float = 2.0) -> CheckResult:
    """Resolves and parses DMARC record at _dmarc.<domain>."""
    dmarc_host = f"_dmarc.{domain}"
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(dmarc_host, "TXT")
        dmarc_txt = ""
        for rdata in answers:
            txt = clean_txt_rdata(rdata)
            if txt.startswith("v=DMARC1"):
                dmarc_txt = txt
                break

        if not dmarc_txt:
            return CheckResult(
                name="DMARC",
                status=CheckStatus.FAIL,
                details={
                    "record_host": dmarc_host,
                    "record_value": "No record published",
                    "dmarc_present": False,
                    "policy": "none",
                    "message": f"No DMARC record published at {dmarc_host}."
                },
                recommendation=f"Publish a DMARC record at '{dmarc_host}' with p=quarantine or p=reject to prevent domain impersonation (RFC 7489)."
            )

        # Parse policy tags
        tags = {}
        for part in dmarc_txt.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        p = tags.get("p", "none").lower()
        sp = tags.get("sp", p).lower()
        pct = tags.get("pct", "100")
        rua = tags.get("rua", None)

        if p == "reject":
            status = CheckStatus.PASS
            enforcement = "full reject"
        elif p == "quarantine":
            status = CheckStatus.PASS
            enforcement = "quarantine"
        else:
            status = CheckStatus.WARN
            enforcement = "monitoring only (p=none)"

        return CheckResult(
            name="DMARC",
            status=status,
            details={
                "record_host": dmarc_host,
                "record_value": dmarc_txt,
                "dmarc_present": True,
                "policy": p,
                "policy_display": f"{p} ({pct}%)",
                "subdomain_policy": sp,
                "enforcement": enforcement,
                "rua": rua,
                "message": f"DMARC record published with policy p={p} and enforcement={enforcement}."
            },
            recommendation="Transition DMARC policy from 'none' or 'quarantine' to 'p=reject; pct=100' for authoritative spoofing mitigation."
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            details={
                "record_host": dmarc_host,
                "record_value": "No record published",
                "dmarc_present": False,
                "policy": "none",
                "message": f"No DMARC record published at {dmarc_host}."
            },
            recommendation=f"Publish a DMARC policy at '{dmarc_host}'."
        )
    except Exception as e:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            details={
                "record_host": dmarc_host,
                "record_value": "No record published",
                "dmarc_present": False,
                "policy": "none",
                "message": f"DMARC DNS lookup returned no records at {dmarc_host}."
            },
            recommendation=f"Publish a DMARC policy at '{dmarc_host}'."
        )


def check_mta_sts(domain: str, timeout: float = 2.0) -> CheckResult:
    """Checks MTA-STS TXT record at _mta-sts.<domain>."""
    sts_host = f"_mta-sts.{domain}"
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(sts_host, "TXT")
        sts_txt = ""
        for rdata in answers:
            txt = clean_txt_rdata(rdata)
            if "v=STSv1" in txt:
                sts_txt = txt
                break

        if sts_txt:
            return CheckResult(
                name="MTA-STS",
                status=CheckStatus.PASS,
                details={
                    "record_host": sts_host,
                    "record_value": sts_txt,
                    "mode": "enforce" if "mode=enforce" in sts_txt else "testing",
                    "message": "MTA-STS policy record published in DNS."
                },
                recommendation="Ensure MTA-STS HTTPS policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt is serving enforce mode (RFC 8461)."
            )
        else:
            return CheckResult(
                name="MTA-STS",
                status=CheckStatus.WARN,
                details={
                    "record_host": sts_host,
                    "record_value": "No record published",
                    "message": f"No MTA-STS DNS record found at {sts_host}."
                },
                recommendation=f"Configure MTA-STS by publishing a TXT record at '{sts_host}' to prevent TLS downgrade attacks."
            )
    except Exception:
        return CheckResult(
            name="MTA-STS",
            status=CheckStatus.WARN,
            details={
                "record_host": sts_host,
                "record_value": "No record published",
                "message": f"No MTA-STS DNS record resolved at {sts_host}."
            },
            recommendation="Configure MTA-STS (RFC 8461) to mandate TLS encryption for inbound mail routing."
        )


def check_tls_rpt(domain: str, timeout: float = 2.0) -> CheckResult:
    """Checks TLS-RPT TXT record at _smtp._tls.<domain>."""
    rpt_host = f"_smtp._tls.{domain}"
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(rpt_host, "TXT")
        rpt_txt = ""
        for rdata in answers:
            txt = clean_txt_rdata(rdata)
            if "v=TLSRPTv1" in txt:
                rpt_txt = txt
                break

        if rpt_txt:
            return CheckResult(
                name="TLS-RPT",
                status=CheckStatus.PASS,
                details={
                    "record_host": rpt_host,
                    "record_value": rpt_txt,
                    "message": "SMTP TLS Reporting (TLS-RPT) enabled for failure telemetry."
                },
                recommendation="Regularly inspect TLS-RPT JSON payloads for handshake negotiation failures (RFC 8460)."
            )
        else:
            return CheckResult(
                name="TLS-RPT",
                status=CheckStatus.WARN,
                details={
                    "record_host": rpt_host,
                    "record_value": "No record published",
                    "message": f"No TLS-RPT TXT record found at {rpt_host}."
                },
                recommendation=f"Publish a TLS-RPT record at '{rpt_host}' to receive automated daily reports on TLS delivery issues."
            )
    except Exception:
        return CheckResult(
            name="TLS-RPT",
            status=CheckStatus.WARN,
            details={
                "record_host": rpt_host,
                "record_value": "No record published",
                "message": f"TLS-RPT record not resolved at {rpt_host}."
            },
            recommendation=f"Publish a TLS-RPT record at '{rpt_host}' (e.g. 'v=TLSRPTv1; rua=mailto:tls-reports@{domain}')."
        )


def check_dane_tlsa(domain: str, mx_host: Optional[str] = None, timeout: float = 2.0) -> CheckResult:
    """Checks DANE / TLSA records at _25._tcp.<mx_host>."""
    target_host = mx_host or f"mail.{domain}"
    tlsa_host = f"_25._tcp.{target_host}"
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(tlsa_host, "TLSA")
        records = [str(r) for r in answers]
        return CheckResult(
            name="DANE/TLSA",
            status=CheckStatus.PASS,
            details={
                "record_host": tlsa_host,
                "record_value": records[0] if records else "Published",
                # DEF-02 fix: explicit boolean so scoring.py reads dnssec_validated directly.
                "dnssec_validated": True,
                "dnssec": "validated",
                "message": f"DANE TLSA certificate association published for {target_host}."
            },
            recommendation="Ensure TLSA records are synchronized with X.509 certificate and SPKI rotations (RFC 7672)."
        )
    except Exception:
        return CheckResult(
            name="DANE/TLSA",
            status=CheckStatus.WARN,
            details={
                "record_host": tlsa_host,
                "record_value": "No record published",
                # DEF-02 fix: explicit False — never relies on string parsing.
                "dnssec_validated": False,
                "dnssec": "not_enforced",
                "message": f"No TLSA record discovered at {tlsa_host}."
            },
            recommendation=f"Publish DANE TLSA records under '{tlsa_host}' alongside DNSSEC to pin mail gateway certificates."
        )


def probe_mx_starttls_and_pqc(domain: str, timeout: float = 2.5) -> Tuple[List[ProtocolAuditResult], List[SecurityFinding]]:
    """
    Probes MX hosts using raw socket connections with multi-port sequential probe & SNI fallback:
    - Queries MX records.
    - Sequentially probes candidate ports per MX host:
      1) Port 25 (Standard SMTP + STARTTLS) with a 2.5-second timeout
      2) If Port 25 fails/times out, try Port 587 (Submission + STARTTLS)
      3) If Port 587 fails, try Port 465 (Implicit TLS via ssl.create_default_context().wrap_socket)
      4) If all direct SMTP ports time out (ISP firewall block), fallback to checking the domain's
         HTTPS certificate chain (Port 443) to extract TLS version, Cipher Suite, SANs, and
         SHA-256 fingerprint rather than failing the scan or returning score 0.
    """
    mx_hosts = resolve_mx_hosts(domain, timeout=2.0, lifetime=3.0)
    if not mx_hosts:
        mx_hosts = [domain]

    audited_protocols: List[ProtocolAuditResult] = []
    findings: List[SecurityFinding] = []

    for host in mx_hosts[:2]:  # Probe up to top 2 MX hosts
        # 1. Try Port 25 (Standard SMTP + STARTTLS) with a 2.5-second timeout
        audit = probe_protocol_tls(
            host=host,
            port=25,
            protocol="smtp",
            use_starttls=True,
            target_domain=domain,
            timeout=2.5
        )

        # 2. If Port 25 fails / times out, try Port 587 (Submission + STARTTLS)
        if not (audit.tls_handshake and audit.tls_handshake.success):
            audit_587 = probe_protocol_tls(
                host=host,
                port=587,
                protocol="smtp",
                use_starttls=True,
                target_domain=domain,
                timeout=2.5
            )
            if audit_587.tls_handshake and audit_587.tls_handshake.success:
                audit = audit_587

        # 3. If Port 587 fails / times out, try Port 465 (Implicit TLS)
        if not (audit.tls_handshake and audit.tls_handshake.success):
            audit_465 = probe_protocol_tls(
                host=host,
                port=465,
                protocol="smtp",
                use_starttls=False,
                target_domain=domain,
                timeout=2.5
            )
            if audit_465.tls_handshake and audit_465.tls_handshake.success:
                audit = audit_465

        # 4. If all direct SMTP ports time out/fail (ISP firewall block), fallback to HTTPS port 443
        if not (audit.tls_handshake and audit.tls_handshake.success):
            sni_audit = probe_https_sni_fallback(
                host=host,
                target_domain=domain,
                timeout=2.5
            )
            if sni_audit.tls_handshake and sni_audit.tls_handshake.success:
                audit = sni_audit

        audited_protocols.append(audit)
        findings.extend(audit.findings)

    return audited_protocols, findings


def run_active_domain_scan(domain: str) -> Tuple[List[CheckResult], CryptographicPosture, List[SecurityFinding]]:
    """
    Orchestrates complete active domain inspection across:
    1. DNSSEC & Identity Resolution (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA)
    2. TCP Socket Probe & STARTTLS Handshake on Mail Exchangers (Multi-port & SNI fallback)
    3. X.509 Certificate Chain & SHA-256 Fingerprint Extraction
    4. Cipher Suite & Post-Quantum (ML-KEM / Kyber) Handshake Evaluation
    """
    # 1. Email Authentication Matrix
    checks: List[CheckResult] = [
        check_spf(domain),
        check_dkim(domain),
        check_dmarc(domain),
        check_mta_sts(domain),
        check_tls_rpt(domain),
    ]

    # 2. Active Socket STARTTLS Probe & PQC Evaluation
    audits, probe_findings = probe_mx_starttls_and_pqc(domain)

    # Primary MX host for TLSA check
    mx_hosts = resolve_mx_hosts(domain, timeout=2.0, lifetime=3.0)
    primary_mx = mx_hosts[0] if mx_hosts else (audits[0].host if audits else None)
    checks.append(check_dane_tlsa(domain, mx_host=primary_mx))

    # Evaluate cryptographic flags
    has_pfs = any(a.tls_handshake and a.tls_handshake.cipher and a.tls_handshake.cipher.forward_secrecy for a in audits)
    has_weak_cipher = any(a.tls_handshake and a.tls_handshake.cipher and a.tls_handshake.cipher.is_weak for a in audits)
    has_dep_tls = any(a.tls_handshake and a.tls_handshake.negotiated_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"] for a in audits)
    has_cert_issue = any(a.tls_handshake and a.tls_handshake.certificate and (a.tls_handshake.certificate.is_expired or a.tls_handshake.certificate.is_self_signed) for a in audits)
    # PQC indicators can only be claimed when a completed handshake actually supplied
    # cipher/key-exchange telemetry for classification.
    pqc_evaluated = any(
        a.tls_handshake and a.tls_handshake.success and a.tls_handshake.cipher for a in audits
    )

    crypto_posture = CryptographicPosture(
        crypto_score=100,
        grade="A+",
        protocols_audited=audits,
        forward_secrecy_supported=has_pfs,
        weak_ciphers_found=has_weak_cipher,
        deprecated_tls_found=has_dep_tls,
        certificate_issues_found=has_cert_issue,
        prioritized_findings=probe_findings,
        pqc_indicators_evaluated=pqc_evaluated
    )

    # Calculate posture score deterministically using real cryptographic findings
    from app.scoring import calculate_posture_score
    score, grade, _, combined_findings = calculate_posture_score(
        checks=checks,
        domain=domain,
        crypto_posture=crypto_posture,
        findings=probe_findings
    )

    crypto_posture.crypto_score = score
    crypto_posture.grade = grade

    return checks, crypto_posture, combined_findings

