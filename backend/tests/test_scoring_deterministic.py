import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import (
    CheckResult,
    CheckStatus,
    CryptographicPosture,
    ProtocolAuditResult,
    TlsHandshakeResult,
    CipherSuiteInfo
)
from app.scoring import calculate_posture_score


def test_perfect_domain_score_and_grade():
    checks = [
        CheckResult(name="SPF", status=CheckStatus.PASS, details={"policy": "strict (-all)"}),
        CheckResult(name="DMARC", status=CheckStatus.PASS, details={"policy": "p=reject (100%)"}),
        CheckResult(name="MTA-STS", status=CheckStatus.PASS, details={"mode": "enforce"}),
        CheckResult(name="DANE/TLSA", status=CheckStatus.PASS, details={})
    ]
    cipher = CipherSuiteInfo(
        name="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        key_exchange="ML-KEM-768",
        encryption="AES-GCM",
        bits=256,
        forward_secrecy=True,
        is_weak=False,
        pqc_hybrid=True
    )
    handshake = TlsHandshakeResult(
        success=True,
        negotiated_version="TLSv1.3",
        cipher=cipher
    )
    audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.example.com",
        port=25,
        service_type="STARTTLS",
        tls_handshake=handshake
    )
    posture = CryptographicPosture(
        crypto_score=100,
        grade="A+",
        protocols_audited=[audit],
        forward_secrecy_supported=True,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False
    )

    score, grade, _, _ = calculate_posture_score(checks=checks, domain="example.com", crypto_posture=posture)
    assert score == 100
    assert grade == "A+"


def test_deductions_rubric():
    # 1. Broken STARTTLS with published MX:
    # No SPF: -15, No DMARC: -25, Broken STARTTLS: -25, Missing MTA-STS/DANE: -10, No PQC: -5
    # Total score = 100 - 15 - 25 - 25 - 10 - 5 = 20 (Grade F)
    checks = [
        CheckResult(name="SPF", status=CheckStatus.FAIL, details={"record_value": "No record published"}),
        CheckResult(name="DMARC", status=CheckStatus.FAIL, details={"record_value": "No record published"}),
        CheckResult(name="MTA-STS", status=CheckStatus.WARN, details={"record_value": "No record published"}),
        CheckResult(name="DANE/TLSA", status=CheckStatus.WARN, details={"record_value": "No record published"})
    ]
    broken_audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.empty.com",
        port=25,
        service_type="STARTTLS",
        tls_handshake=TlsHandshakeResult(success=False, error="Connection refused")
    )
    posture = CryptographicPosture(
        crypto_score=0,
        grade="F",
        protocols_audited=[broken_audit],
        forward_secrecy_supported=False,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False
    )
    score, grade, _, _ = calculate_posture_score(checks=checks, domain="empty.com", crypto_posture=posture)
    assert score == 20
    assert grade == "F"

    # 2. Apex domain with no published MX (like defense.gov.in):
    # No SPF: -15, No DMARC: -25, No MX/STARTTLS: 0 (not a mail exchanger), Missing MTA-STS: -10, No PQC: -5
    # Total score = 100 - 15 - 25 - 10 - 5 = 45 (Grade F)
    no_mx_posture = CryptographicPosture(
        crypto_score=0,
        grade="F",
        protocols_audited=[],
        forward_secrecy_supported=False,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False
    )
    score_apex, grade_apex, _, _ = calculate_posture_score(checks=checks, domain="defense.gov.in", crypto_posture=no_mx_posture)
    assert score_apex == 45
    assert grade_apex == "F"


def test_softfail_and_pnone_deductions():
    # Softfail SPF: -5, DMARC p=none: -10, Valid TLS 1.3 STARTTLS: 0, MTA-STS PASS: 0, No PQC: -5
    # Total = 100 - 5 - 10 - 5 = 80 (Grade A)
    checks = [
        CheckResult(name="SPF", status=CheckStatus.PASS, details={"policy": "softfail (~all)", "record_value": "v=spf1 ~all"}),
        CheckResult(name="DMARC", status=CheckStatus.WARN, details={"policy": "none (100%)", "record_value": "v=DMARC1; p=none;"}),
        CheckResult(name="MTA-STS", status=CheckStatus.PASS, details={"mode": "enforce"})
    ]
    cipher = CipherSuiteInfo(
        name="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        key_exchange="ECDHE",
        encryption="AES-GCM",
        bits=256,
        forward_secrecy=True,
        is_weak=False,
        pqc_hybrid=False
    )
    handshake = TlsHandshakeResult(
        success=True,
        negotiated_version="TLSv1.3",
        cipher=cipher
    )
    audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.example.com",
        port=25,
        service_type="STARTTLS",
        tls_handshake=handshake
    )
    posture = CryptographicPosture(
        crypto_score=80,
        grade="A",
        protocols_audited=[audit],
        forward_secrecy_supported=True,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False
    )
    score, grade, _, _ = calculate_posture_score(checks=checks, domain="example.com", crypto_posture=posture)
    assert score == 80
    assert grade == "A"


def test_quarantine_and_tls12_deductions():
    # Strict SPF: 0, DMARC p=quarantine: -5, TLS 1.2: -5, MTA-STS PASS: 0, No PQC: -5
    # Total = 100 - 5 - 5 - 5 = 85 (Grade A)
    checks = [
        CheckResult(name="SPF", status=CheckStatus.PASS, details={"policy": "strict (-all)", "record_value": "v=spf1 -all"}),
        CheckResult(name="DMARC", status=CheckStatus.PASS, details={"policy": "quarantine (100%)", "record_value": "v=DMARC1; p=quarantine;"}),
        CheckResult(name="MTA-STS", status=CheckStatus.PASS, details={"mode": "enforce"})
    ]
    cipher = CipherSuiteInfo(
        name="ECDHE-RSA-AES256-GCM-SHA384",
        tls_version="TLSv1.2",
        key_exchange="ECDHE",
        encryption="AES-GCM",
        bits=256,
        forward_secrecy=True,
        is_weak=False,
        pqc_hybrid=False
    )
    handshake = TlsHandshakeResult(
        success=True,
        negotiated_version="TLSv1.2",
        cipher=cipher
    )
    audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.example.com",
        port=25,
        service_type="STARTTLS",
        tls_handshake=handshake
    )
    posture = CryptographicPosture(
        crypto_score=85,
        grade="A",
        protocols_audited=[audit],
        forward_secrecy_supported=True,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False
    )
    score, grade, _, _ = calculate_posture_score(checks=checks, domain="example.com", crypto_posture=posture)
    assert score == 85
    assert grade == "A"


def test_deprecated_tls_and_weak_ciphers():
    # Strict SPF: 0, Reject DMARC: 0, STARTTLS present: 0, Deprecated TLS: -20, Weak cipher (3DES): -15, MTA-STS: -10, No PQC: -5
    # Score = 100 - 20 - 15 - 10 - 5 = 50 (Grade C)
    checks = [
        CheckResult(name="SPF", status=CheckStatus.PASS, details={"policy": "strict (-all)"}),
        CheckResult(name="DMARC", status=CheckStatus.PASS, details={"policy": "reject (100%)"}),
    ]
    cipher = CipherSuiteInfo(
        name="DES-CBC3-SHA",
        tls_version="TLSv1.0",
        key_exchange="RSA",
        encryption="3DES",
        bits=168,
        forward_secrecy=False,
        is_weak=True,
        pqc_hybrid=False
    )
    handshake = TlsHandshakeResult(
        success=True,
        negotiated_version="TLSv1.0",
        cipher=cipher
    )
    audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.legacy.com",
        port=25,
        service_type="STARTTLS",
        tls_handshake=handshake
    )
    posture = CryptographicPosture(
        crypto_score=50,
        grade="C",
        protocols_audited=[audit],
        forward_secrecy_supported=False,
        weak_ciphers_found=True,
        deprecated_tls_found=True,
        certificate_issues_found=False
    )
    score, grade, _, _ = calculate_posture_score(checks=checks, domain="legacy.com", crypto_posture=posture)
    assert score == 50
    assert grade == "C"
