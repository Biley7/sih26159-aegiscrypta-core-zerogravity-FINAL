import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi.testclient import TestClient
from app.main import app
from app.crypto.cert_analyzer import parse_x509_certificate
from app.crypto.cipher_evaluator import evaluate_cipher_and_tls
from app.models import FindingSeverity

client = TestClient(app, headers={"X-API-Key": "test-api-key"})


def _generate_test_certificate(key_size: int = 2048, cn: str = "mail.example.com", days_valid: int = 90):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("*.example.com")]),
            critical=False
        )
    )
    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_cert_analyzer_valid():
    der_bytes = _generate_test_certificate(key_size=2048, cn="mail.example.com", days_valid=60)
    cert_info, findings = parse_x509_certificate(der_bytes, target_domain="mail.example.com")

    assert cert_info.subject_cn == "mail.example.com"
    assert cert_info.public_key_algorithm == "RSA"
    assert cert_info.key_size_bits == 2048
    assert cert_info.is_self_signed is True
    assert cert_info.is_expired is False
    assert cert_info.matches_domain is True
    assert "mail.example.com" in cert_info.san_list
    assert "*.example.com" in cert_info.san_list

    # Should flag self-signed
    assert any(f.title == "Self-Signed Certificate in Use" for f in findings)
    print("PASS: test_cert_analyzer_valid")


def test_cert_analyzer_weak_rsa():
    der_bytes = _generate_test_certificate(key_size=1024, cn="legacy.example.com", days_valid=10)
    cert_info, findings = parse_x509_certificate(der_bytes, target_domain="legacy.example.com")

    assert cert_info.key_size_bits == 1024
    assert any(f.title == "Weak RSA Key Length (< 2048-bit)" for f in findings)
    assert any(f.title == "Certificate Expiring Soon" for f in findings)
    print("PASS: test_cert_analyzer_weak_rsa")


def test_cert_analyzer_flags_sha1_signature(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("legacy.example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    class Sha1MetadataCertificate:
        signature_algorithm_oid = type("SignatureOid", (), {"_name": "sha1WithRSAEncryption"})()
        signature_hash_algorithm = hashes.SHA1()

        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    monkeypatch.setattr(
        "app.crypto.cert_analyzer.x509.load_der_x509_certificate",
        lambda der: Sha1MetadataCertificate(cert),
    )
    cert_info, findings = parse_x509_certificate(
        cert.public_bytes(serialization.Encoding.DER),
        target_domain="legacy.example.com",
    )

    assert "sha1" in cert_info.signature_algorithm.lower()
    assert any(
        finding.title == "Deprecated Digital Signature Algorithm (SHA-1 / MD5)"
        and finding.severity == FindingSeverity.CRITICAL
        for finding in findings
    )


def test_cipher_evaluator_modern_tls13():
    cipher_info, findings = evaluate_cipher_and_tls("TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
    assert cipher_info is not None
    assert cipher_info.forward_secrecy is True
    assert not any(f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH] for f in findings)
    print("PASS: test_cipher_evaluator_modern_tls13")


def test_cipher_evaluator_weak_and_deprecated():
    cipher_info, findings = evaluate_cipher_and_tls("TLSv1.0", ("RC4-MD5", "TLSv1.0", 128))
    assert cipher_info is not None
    assert cipher_info.forward_secrecy is False
    assert cipher_info.is_weak is True

    finding_titles = [f.title for f in findings]
    assert "Deprecated TLS Version (TLSv1.0)" in finding_titles
    assert "Lack of Perfect Forward Secrecy (PFS)" in finding_titles
    assert any("RC4" in t for t in finding_titles)
    print("PASS: test_cipher_evaluator_weak_and_deprecated")


def test_crypto_probe_api_model():
    # -------------------------------------------------------------------
    # SSRF Prevention tests (VULN-01)
    # All of the following inputs must now be rejected at the model layer
    # (422 Unprocessable Entity) or at the IP-guard layer (403 Forbidden).
    # -------------------------------------------------------------------

    # 1. IP address as host — rejected by FQDN validator (422)
    response = client.post("/api/crypto/probe", json={
        "host": "127.0.0.1",
        "port": 25,
        "protocol": "smtp"
    })
    assert response.status_code == 422, (
        f"Expected 422 for raw IPv4 host, got {response.status_code}"
    )

    # 2. Loopback with invalid port — rejected by port validator (422)
    response = client.post("/api/crypto/probe", json={
        "host": "127.0.0.1",
        "port": 99999,
        "protocol": "smtp"
    })
    assert response.status_code == 422, (
        f"Expected 422 for out-of-range port, got {response.status_code}"
    )

    # 3. Internal RFC-1918 address — rejected by FQDN validator (422)
    response = client.post("/api/crypto/probe", json={
        "host": "10.0.0.1",
        "port": 25,
        "protocol": "smtp"
    })
    assert response.status_code == 422, (
        f"Expected 422 for RFC-1918 IP host, got {response.status_code}"
    )

    # 4. Cloud metadata address — rejected by FQDN validator (422)
    response = client.post("/api/crypto/probe", json={
        "host": "169.254.169.254",
        "port": 80,
        "protocol": "smtp"
    })
    assert response.status_code == 422, (
        f"Expected 422 for metadata IP host, got {response.status_code}"
    )

    # 5. Invalid protocol — rejected by protocol allowlist validator (422)
    response = client.post("/api/crypto/probe", json={
        "host": "smtp.example.com",
        "port": 25,
        "protocol": "ftp"
    })
    assert response.status_code == 422, (
        f"Expected 422 for disallowed protocol, got {response.status_code}"
    )

    # 6. Valid FQDN — accepted by validators, probe attempted (network may
    #    timeout or refuse, but must NOT return 422/403 from validation).
    #    We accept any non-validation HTTP status (200, 200 with fail status, etc.)
    response = client.post("/api/crypto/probe", json={
        "host": "smtp.gmail.com",
        "port": 25,
        "protocol": "smtp",
        "use_starttls": True
    })
    assert response.status_code == 200, (
        f"Expected 200 for valid FQDN probe, got {response.status_code}: {response.text[:200]}"
    )
    data = response.json()
    assert data["protocol"] == "SMTP"
    assert data["status"] in ["pass", "warn", "fail", "unknown"]
    print(f"PASS: test_crypto_probe_api_model — SSRF guards verified, valid probe returned status={data['status']}")


def test_scan_domain_with_crypto():
    response = client.post("/api/scan", json={"domain": "google.com"})
    assert response.status_code == 200
    data = response.json()

    assert "score" in data
    assert "crypto_posture" in data
    assert "prioritized_findings" in data

    crypto = data["crypto_posture"]
    if crypto:
        assert "crypto_score" in crypto
        assert "grade" in crypto
        assert isinstance(crypto["protocols_audited"], list)
        print(f"PASS: Domain scan returned crypto score {crypto['crypto_score']}/100 (Grade {crypto['grade']})")


if __name__ == "__main__":
    test_cert_analyzer_valid()
    test_cert_analyzer_weak_rsa()
    test_cipher_evaluator_modern_tls13()
    test_cipher_evaluator_weak_and_deprecated()
    test_crypto_probe_api_model()
    test_scan_domain_with_crypto()
    print("\nALL CRYPTOGRAPHIC TESTS PASSED SUCCESSFULLY!")
