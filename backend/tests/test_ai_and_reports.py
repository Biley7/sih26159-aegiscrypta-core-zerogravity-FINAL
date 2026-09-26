import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.models import (
    CheckResult,
    CheckStatus,
    CryptographicPosture,
    ProtocolAuditResult,
    TlsHandshakeResult,
    CipherSuiteInfo,
    CertificateInfo
)
from app.ai.risk_scorer import compute_ai_cryptographic_risk
from app.ai.anomaly_detector import get_anomaly_detector
from app.reports.html_report import generate_html_forensic_report

client = TestClient(app, headers={"X-API-Key": "test-api-key"})


def test_ai_risk_scorer():
    checks = [
        CheckResult(name="SPF", status=CheckStatus.PASS, details="v=spf1 ... -all"),
        CheckResult(name="DMARC", status=CheckStatus.PASS, details="v=DMARC1; p=reject"),
    ]
    cipher = CipherSuiteInfo(
        name="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        key_exchange="ECDHE",
        forward_secrecy=True,
        encryption="AES-GCM",
        bits=256,
        is_weak=False
    )
    cert = CertificateInfo(
        subject_cn="mail.example.com",
        issuer_cn="DigiCert Global Root G2",
        subject_dn="CN=mail.example.com",
        issuer_dn="CN=DigiCert Global Root G2",
        serial_number="0x1234",
        valid_from="2026-01-01",
        valid_to="2027-01-01",
        days_until_expiry=280,
        is_expired=False,
        is_self_signed=False,
        public_key_algorithm="RSA",
        key_size_bits=2048,
        signature_algorithm="sha256WithRSAEncryption"
    )
    audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.example.com",
        port=25,
        service_type="STARTTLS",
        starttls_negotiated=True,
        tls_handshake=TlsHandshakeResult(
            success=True,
            negotiated_version="TLSv1.3",
            cipher=cipher,
            certificate=cert
        ),
        status=CheckStatus.PASS
    )
    posture = CryptographicPosture(
        crypto_score=95,
        grade="A+",
        protocols_audited=[audit],
        forward_secrecy_supported=True,
        weak_ciphers_found=False,
        deprecated_tls_found=False,
        certificate_issues_found=False,
        prioritized_findings=[]
    )

    ai_risk = compute_ai_cryptographic_risk(checks, posture)
    assert ai_risk.risk_score < 25
    assert ai_risk.risk_level == "LOW"
    assert ai_risk.confidence > 0.8
    print(f"PASS: test_ai_risk_scorer (Risk Score: {ai_risk.risk_score}/100, Level: {ai_risk.risk_level})")


def test_ai_anomaly_detector():
    detector = get_anomaly_detector()

    # Create anomalous session: Self-signed certificate and deprecated TLSv1.0
    bad_cert = CertificateInfo(
        subject_cn="untrusted.local",
        issuer_cn="untrusted.local",
        subject_dn="CN=untrusted.local",
        issuer_dn="CN=untrusted.local",
        serial_number="0x9999",
        valid_from="2020-01-01",
        valid_to="2021-01-01",
        days_until_expiry=-1000,
        is_expired=True,
        is_self_signed=True,
        public_key_algorithm="RSA",
        key_size_bits=1024,
        signature_algorithm="md5WithRSAEncryption"
    )
    bad_cipher = CipherSuiteInfo(
        name="RC4-MD5",
        tls_version="TLSv1.0",
        key_exchange="Static RSA",
        forward_secrecy=False,
        encryption="RC4",
        bits=128,
        is_weak=True
    )
    bad_audit = ProtocolAuditResult(
        protocol="SMTP",
        host="mail.badhost.org",
        port=25,
        service_type="STARTTLS",
        starttls_advertised=False,
        starttls_negotiated=False,
        tls_handshake=TlsHandshakeResult(
            success=True,
            negotiated_version="TLSv1.0",
            cipher=bad_cipher,
            certificate=bad_cert
        ),
        status=CheckStatus.FAIL
    )
    bad_posture = CryptographicPosture(
        crypto_score=20,
        grade="F",
        protocols_audited=[bad_audit],
        forward_secrecy_supported=False,
        weak_ciphers_found=True,
        deprecated_tls_found=True,
        certificate_issues_found=True,
        prioritized_findings=[]
    )

    result = detector.detect_anomalies_in_posture(bad_posture)
    assert result.anomaly_detected is True
    assert len(result.suspicious_indicators) > 0
    print(f"PASS: test_ai_anomaly_detector (Anomalies detected: {len(result.suspicious_indicators)})")


def test_html_forensic_report_endpoint():
    response = client.post("/api/scan/html", json={"domain": "google.com"})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html_text = response.text
    assert "<!DOCTYPE html>" in html_text
    assert "google.com" in html_text
    assert "Security Score" in html_text
    assert "Cryptographic & Email Security Posture Report" in html_text
    print(f"PASS: test_html_forensic_report_endpoint (Generated {len(html_text)} bytes HTML)")


def test_forensic_json_endpoint():
    response = client.post("/api/scan/forensic", json={"domain": "google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "google.com"
    assert "ai_risk_assessment" in data
    assert "anomaly_detection" in data
    assert "dns_authentication" in data
    assert "prioritized_findings" in data
    print("PASS: test_forensic_json_endpoint (POST /api/scan/forensic)")


if __name__ == "__main__":
    test_ai_risk_scorer()
    test_ai_anomaly_detector()
    test_html_forensic_report_endpoint()
    test_forensic_json_endpoint()
    print("\nALL AI & FORENSIC REPORTING TESTS PASSED SUCCESSFULLY!")
