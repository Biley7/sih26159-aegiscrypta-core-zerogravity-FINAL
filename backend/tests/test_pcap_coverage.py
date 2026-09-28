"""
Step 3.2 / Step 3.3 — Expanded PCAP Test Coverage
====================================================

Step 3.1 baseline: existing test_pcap.py has 2 tests:
  - test_pcap_stream_reconstruction: 1 SMTP+STARTTLS synthetic pcap via analyze_pcap_data()
    Checks: packet count, stream count, protocol=SMTP, starttls=True, tls_detected=True,
    tls_version=TLSv1.2. Does NOT check: cipher name, cert, IMAP, POP3, malformed, creds.
  - test_pcap_upload_endpoint: same pcap via POST /api/scan/pcap
    Checks: status 200, filename, 1 stream, starttls=True. No other fields.

Step 3.3 findings (from reading cert_analyzer.py and tls_reconstructor.py):
    - Chain validation: system-root verification with supplied intermediates on both live and
        PCAP paths. PCAP path calls parse_x509_certificate() from tls_reconstructor.py.
  - Signature algorithm: IMPLEMENTED — hash_algo_name extracted from cert.signature_hash_algorithm,
    SHA-1/MD5 triggers a CRITICAL finding. Available in both live and PCAP paths.
  These tests exercise both capabilities end-to-end through synthetic pcap data.

Test matrix added here:
  T1  - IMAP session correctly identified from IMAP port (143)
  T2  - POP3 session correctly identified from POP3 port (110)
  T3  - STARTTLS negotiation detected mid-session (SMTP)
  T4  - STARTTLS stripping detected (client sent STARTTLS, no TLS records followed)
  T5  - Malformed/truncated capture handled without crashing
  T6  - TLS version field extracted from ServerHello in capture
  T7  - TLS cipher suite field extracted from ServerHello in capture
  T8  - Cleartext credential exposure detected (AUTH PLAIN, PASS command)
  T9  - Cert chain validation and signature algorithm flow through PCAP parse path
        (uses a real DER cert embedded in a synthetic TLS Certificate handshake record)
  T10 - Unencrypted SMTP session (no STARTTLS, no TLS) raises HIGH finding
  T11 - Out-of-order packets (shuffled seq numbers) reconstructed without crash

Honest capability status — which tests pass and which reveal real gaps:
  T1-T8, T10-T11: PASS — capabilities implemented in pcap_analyzer.py
  T9: PASS for signature algorithm extraction; chain validation requires a real DER cert
      (self-signed synthetic used — chain validation correctly returns False/self-signed)
"""

import sys
import tempfile
import os
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from scapy.all import IP, TCP, wrpcap
from fastapi.testclient import TestClient
from app.main import app
from app.pcap_analyzer import analyze_pcap_stream

client = TestClient(app, headers={"X-API-Key": "test-api-key"})


# ---------------------------------------------------------------------------
# PCAP builder helpers
# ---------------------------------------------------------------------------

def _make_pcap(packets) -> bytes:
    """Write scapy packets to a temp file and return raw bytes."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        wrpcap(tmp.name, packets)
        path = tmp.name
    with open(path, "rb") as f:
        data = f.read()
    os.remove(path)
    return data


def _smtp_starttls_pcap(include_tls: bool = True) -> bytes:
    """SMTP EHLO → STARTTLS negotiation, optionally followed by a TLS ClientHello."""
    pkts = [
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50000, seq=100) /
            b"220 mail.example.com ESMTP Postfix\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=50000, dport=25, seq=200) /
            b"EHLO client.example.com\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50000, seq=136) /
            b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=50000, dport=25, seq=225) /
            b"STARTTLS\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50000, seq=182) /
            b"220 2.0.0 Ready to start TLS\r\n",
    ]
    if include_tls:
        tls_hello = (
            b"\x16\x03\x03\x00\x2d"      # TLS Record Header (type=22, ver=TLS1.2, len=45)
            b"\x01\x00\x00\x29"           # ClientHello header (type=1, len=41)
            b"\x03\x03"                   # Client version TLS 1.2
            + b"\xab" * 32                # Random
            + b"\x00"                     # Session ID len=0
            + b"\x00\x02\xc0\x2f"         # Cipher: ECDHE-RSA-AES128-GCM-SHA256
            + b"\x01\x00"                 # Compression: NULL
        )
        pkts.append(
            IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=50000, dport=25, seq=234) /
                tls_hello
        )
        # ServerHello — TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)
        # TLS handshake format: type(1) + length(3) + body
        server_hello_body = (
            b"\x03\x03"       # server version TLS 1.2
            + b"\xcd" * 32    # server random
            + b"\x00"         # session id len = 0
            + b"\xc0\x2f"     # selected cipher ECDHE-RSA-AES128-GCM-SHA256
            + b"\x00"         # compression
        )
        sh_body_len = len(server_hello_body)
        # Handshake message: type(1 byte) + 3-byte big-endian length + body
        server_hello_hs = b"\x02" + sh_body_len.to_bytes(3, "big") + server_hello_body
        # TLS record: content_type(1) + version(2) + 2-byte record length + handshake_msg
        server_hello = b"\x16\x03\x03" + len(server_hello_hs).to_bytes(2, "big") + server_hello_hs
        pkts.append(
            IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50000, seq=212) /
                server_hello
        )
    return _make_pcap(pkts)


def _imap_starttls_pcap() -> bytes:
    """IMAP CAPABILITY → STARTTLS."""
    pkts = [
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=143, dport=60001, seq=1000) /
            b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60001, dport=143, seq=2000) /
            b"a001 CAPABILITY\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=143, dport=60001, seq=1052) /
            b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK Capability completed.\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60001, dport=143, seq=2018) /
            b"a002 STARTTLS\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=143, dport=60001, seq=1116) /
            b"a002 OK Begin TLS negotiation now.\r\n",
    ]
    return _make_pcap(pkts)


def _pop3_starttls_pcap() -> bytes:
    """POP3 CAPA → STLS."""
    pkts = [
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=110, dport=60002, seq=3000) /
            b"+OK Dovecot POP3 server ready.\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60002, dport=110, seq=4000) /
            b"CAPA\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=110, dport=60002, seq=3034) /
            b"+OK\r\nCAPA\r\nSTLS\r\nUSER\r\n.\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60002, dport=110, seq=4006) /
            b"STLS\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=110, dport=60002, seq=3067) /
            b"+OK Begin TLS negotiation\r\n",
    ]
    return _make_pcap(pkts)


def _cleartext_credential_pcap() -> bytes:
    """SMTP session with AUTH PLAIN credential exposure (no TLS)."""
    # AUTH PLAIN token = base64("\x00user@example.com\x00password123")
    import base64
    token = base64.b64encode(b"\x00user@example.com\x00password123").decode()
    pkts = [
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60003, seq=5000) /
            b"220 mail.example.com ESMTP\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60003, dport=25, seq=6000) /
            b"EHLO attacker.example.com\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60003, seq=5027) /
            b"250-mail.example.com\r\n250 AUTH PLAIN LOGIN\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60003, dport=25, seq=6028) /
            (f"AUTH PLAIN {token}\r\n").encode(),
    ]
    return _make_pcap(pkts)


def _smtp_auth_login_pcap() -> bytes:
    """SMTP session exposing credentials via the AUTH LOGIN base64 challenge/response.

    This is the regression fixture for the protocol-label bug: the ``LOGIN`` token
    pattern is byte-identical across SMTP and IMAP, so the finding must be labelled
    from the stream protocol actually observed (SMTP here), never hardcoded IMAP.
    """
    import base64
    user_token = base64.b64encode(b"user@example.com").decode()
    pass_token = base64.b64encode(b"password123").decode()
    pkts = [
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60004, seq=7000) /
            b"220 mail.example.com ESMTP\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60004, dport=25, seq=8000) /
            b"EHLO client.example.com\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60004, seq=7027) /
            b"250-mail.example.com\r\n250 AUTH LOGIN PLAIN\r\n",
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60004, dport=25, seq=8067) /
            b"AUTH LOGIN\r\n",
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60004, seq=7079) /
            (f"{user_token}\r\n{pass_token}\r\n").encode(),
    ]
    return _make_pcap(pkts)


def _malformed_pcap() -> bytes:
    """Truncated / random garbage that is not a valid PCAP file."""
    return b"\x00\x01\x02\x03garbage_not_a_pcap_file" * 10


def _out_of_order_smtp_pcap() -> bytes:
    """SMTP packets with deliberately shuffled TCP sequence numbers."""
    # Packets added in reverse sequence order to test reassembly
    pkts = [
        # seq=200 arrives first (out of order)
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=50010, dport=25, seq=200) /
            b"EHLO client.example.com\r\n",
        # seq=100 arrives second (correct order would be first)
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50010, seq=100) /
            b"220 mail.example.com ESMTP\r\n",
        # STARTTLS request
        IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=50010, dport=25, seq=225) /
            b"STARTTLS\r\n",
        # Server 250 (out of order — arrives after client STARTTLS)
        IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=50010, seq=136) /
            b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n",
    ]
    return _make_pcap(pkts)


# ---------------------------------------------------------------------------
# T1 — IMAP session identification
# ---------------------------------------------------------------------------

class TestImapIdentification:
    def test_imap_port_143_identified_as_imap(self):
        """T1: Streams on port 143 must be identified as IMAP."""
        result = analyze_pcap_stream(_imap_starttls_pcap(), filename="imap_test.pcap")
        assert result.total_tcp_streams >= 1
        imap_protocols = [p for p in result.identified_protocols if "IMAP" in p]
        assert imap_protocols, (
            f"T1 FAIL: IMAP not in identified_protocols. Got: {result.identified_protocols}"
        )
        imap_stream = next((s for s in result.streams if "IMAP" in s.protocol), None)
        assert imap_stream is not None, "T1 FAIL: No stream with IMAP protocol found"
        assert imap_stream.starttls_detected is True, (
            "T1 FAIL: STARTTLS should be detected in IMAP stream"
        )


# ---------------------------------------------------------------------------
# T2 — POP3 session identification
# ---------------------------------------------------------------------------

class TestPop3Identification:
    def test_pop3_port_110_identified_as_pop3(self):
        """T2: Streams on port 110 must be identified as POP3."""
        result = analyze_pcap_stream(_pop3_starttls_pcap(), filename="pop3_test.pcap")
        assert result.total_tcp_streams >= 1
        pop3_protocols = [p for p in result.identified_protocols if "POP3" in p]
        assert pop3_protocols, (
            f"T2 FAIL: POP3 not in identified_protocols. Got: {result.identified_protocols}"
        )
        pop3_stream = next((s for s in result.streams if "POP3" in s.protocol), None)
        assert pop3_stream is not None, "T2 FAIL: No stream with POP3 protocol found"
        assert pop3_stream.starttls_detected is True, (
            "T2 FAIL: STLS should be detected in POP3 stream"
        )


# ---------------------------------------------------------------------------
# T3 — STARTTLS negotiation detected mid-session
# ---------------------------------------------------------------------------

class TestStarttlsDetection:
    def test_starttls_detected_after_ehlo(self):
        """T3: STARTTLS advertised and requested in SMTP session must be detected."""
        result = analyze_pcap_stream(_smtp_starttls_pcap(include_tls=True), filename="starttls.pcap")
        smtp_stream = next((s for s in result.streams if "SMTP" in s.protocol), None)
        assert smtp_stream is not None, "T3 FAIL: SMTP stream not found"
        assert smtp_stream.starttls_detected is True, (
            "T3 FAIL: starttls_detected should be True after EHLO+STARTTLS exchange"
        )
        assert smtp_stream.tls_handshake_detected is True, (
            "T3 FAIL: tls_handshake_detected should be True after ClientHello payload"
        )


# ---------------------------------------------------------------------------
# T4 — STARTTLS stripping detection
# ---------------------------------------------------------------------------

class TestStarttlsStripping:
    def test_starttls_stripping_detected(self):
        """
        T4: Client sent STARTTLS but no TLS records followed — must be flagged
        as STARTTLS Stripping / Downgrade Attack (CRITICAL finding).
        """
        result = analyze_pcap_stream(
            _smtp_starttls_pcap(include_tls=False), filename="stripped.pcap"
        )
        smtp_stream = next((s for s in result.streams if "SMTP" in s.protocol), None)
        assert smtp_stream is not None, "T4 FAIL: SMTP stream not found"
        assert smtp_stream.starttls_detected is True, (
            "T4 FAIL: STARTTLS exchange should be detected even without TLS records"
        )
        assert smtp_stream.tls_handshake_detected is False, (
            "T4 FAIL: tls_handshake_detected should be False (no TLS records in stream)"
        )
        stripping_findings = [
            f for f in result.summary_findings
            if "Strip" in f.title or "Downgrade" in f.title or "Stripping" in f.title
        ]
        assert stripping_findings, (
            f"T4 FAIL: No STARTTLS stripping finding raised. "
            f"Summary findings: {[f.title for f in result.summary_findings]}"
        )
        from app.models import FindingSeverity
        assert stripping_findings[0].severity == FindingSeverity.CRITICAL, (
            f"T4 FAIL: Stripping finding should be CRITICAL, got {stripping_findings[0].severity}"
        )


# ---------------------------------------------------------------------------
# T5 — Malformed/truncated capture handled without crashing
# ---------------------------------------------------------------------------

class TestMalformedCapture:
    def test_malformed_pcap_returns_error_response_not_crash(self):
        """
        T5: A garbage byte sequence that is not a valid PCAP file must be handled
        gracefully — return a structured error response, NOT raise an exception.
        """
        result = analyze_pcap_stream(_malformed_pcap(), filename="garbage.pcap")
        # Must return a valid PcapAnalysisResponse (not raise)
        assert result is not None
        assert result.filename == "garbage.pcap"
        # Malformed pcap produces 0 packets or an error finding
        parse_error = any("PCAP" in f.title or "Error" in f.title or "parse" in f.title.lower()
                          for f in result.summary_findings)
        # Either 0 packets (scapy read nothing) or an explicit error finding
        assert result.total_packets == 0 or parse_error, (
            f"T5 FAIL: Expected 0 packets or parse error finding. "
            f"Got {result.total_packets} packets, findings: {[f.title for f in result.summary_findings]}"
        )

    def test_malformed_pcap_via_endpoint_returns_200(self):
        """T5b: Malformed pcap via HTTP endpoint must return 200 with error payload, not 500."""
        response = client.post(
            "/api/scan/pcap",
            files={"file": ("garbage.pcap", _malformed_pcap(), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 200, (
            f"T5b FAIL: Expected 200, got {response.status_code}: {response.text[:300]}"
        )
        data = response.json()
        assert "filename" in data, "T5b FAIL: Response missing 'filename' field"


# ---------------------------------------------------------------------------
# T6 — TLS version extracted from ServerHello
# ---------------------------------------------------------------------------

class TestTlsVersionExtraction:
    def test_tls_version_extracted_from_server_hello(self):
        """
        T6: The negotiated TLS version from ServerHello must be extracted and
        stored on the stream. Requires both ClientHello and ServerHello in the capture.
        """
        result = analyze_pcap_stream(_smtp_starttls_pcap(include_tls=True), filename="tls_ver.pcap")
        smtp_stream = next((s for s in result.streams if "SMTP" in s.protocol), None)
        assert smtp_stream is not None, "T6 FAIL: SMTP stream not found"
        assert smtp_stream.tls_handshake_detected is True, "T6 FAIL: TLS handshake not detected"
        assert smtp_stream.tls_version is not None, (
            "T6 FAIL: tls_version should be extracted from ServerHello, got None"
        )
        assert "TLS" in smtp_stream.tls_version.upper() or "SSL" in smtp_stream.tls_version.upper(), (
            f"T6 FAIL: tls_version '{smtp_stream.tls_version}' does not look like a TLS version"
        )


# ---------------------------------------------------------------------------
# T7 — TLS cipher suite extracted from ServerHello
# ---------------------------------------------------------------------------

class TestTlsCipherExtraction:
    def test_cipher_suite_extracted_from_server_hello(self):
        """
        T7: The selected cipher suite from ServerHello must be extracted.
        Our synthetic ServerHello selects 0xC02F = ECDHE-RSA-AES128-GCM-SHA256.
        """
        result = analyze_pcap_stream(_smtp_starttls_pcap(include_tls=True), filename="cipher.pcap")
        smtp_stream = next((s for s in result.streams if "SMTP" in s.protocol), None)
        assert smtp_stream is not None, "T7 FAIL: SMTP stream not found"
        assert smtp_stream.tls_handshake_detected is True, "T7 FAIL: TLS not detected"
        assert smtp_stream.cipher_suite is not None, (
            "T7 FAIL: cipher_suite should be extracted from ServerHello, got None"
        )
        # 0xC02F maps to ECDHE-RSA-AES128-GCM-SHA256 in CIPHER_SUITE_MAP
        assert "AES128" in smtp_stream.cipher_suite.upper() or "C02F" in smtp_stream.cipher_suite.upper(), (
            f"T7 FAIL: Expected ECDHE-RSA-AES128-GCM cipher, got '{smtp_stream.cipher_suite}'"
        )


# ---------------------------------------------------------------------------
# T8 — Cleartext credential exposure detection
# ---------------------------------------------------------------------------

class TestCredentialDetection:
    def test_auth_plain_cleartext_detected(self):
        """
        T8: SMTP AUTH PLAIN token in cleartext must be detected and flagged as CRITICAL.
        """
        result = analyze_pcap_stream(_cleartext_credential_pcap(), filename="creds.pcap")
        cred_findings = [
            f for f in result.summary_findings
            if "Credential" in f.title or "AUTH" in f.title or "Cleartext" in f.title
        ]
        assert cred_findings, (
            f"T8 FAIL: No credential exposure finding. "
            f"Summary findings: {[f.title for f in result.summary_findings]}"
        )
        from app.models import FindingSeverity
        severities = {f.severity for f in cred_findings}
        assert FindingSeverity.CRITICAL in severities, (
            f"T8 FAIL: Credential finding should be CRITICAL. Got: {severities}"
        )

    def test_auth_login_credential_finding_names_smtp_not_imap(self):
        """
        Regression: an SMTP AUTH LOGIN challenge/response must be labelled with the
        protocol observed on the stream. The LOGIN regex is protocol-agnostic, so a
        hardcoded "IMAP Cleartext Login" label previously mislabelled SMTP captures.
        """
        result = analyze_pcap_stream(_smtp_auth_login_pcap(), filename="auth_login.pcap")
        titles = [f.title for f in result.summary_findings]
        credential_titles = [t for t in titles if "Cleartext Credential Exposure" in t]
        assert credential_titles, (
            f"FAIL: No cleartext credential finding for an SMTP AUTH LOGIN stream. "
            f"Findings: {titles}"
        )
        assert any("SMTP" in t for t in credential_titles), (
            f"FAIL: Credential finding must name the SMTP stream protocol. "
            f"Got: {credential_titles}"
        )
        assert not any("IMAP" in t for t in credential_titles), (
            f"FAIL: SMTP stream mislabelled as IMAP. Got: {credential_titles}"
        )


# ---------------------------------------------------------------------------
# T9 — Cert chain validation and sig algo through PCAP parse path (Step 3.3)
# ---------------------------------------------------------------------------

class TestCertChainAndSigAlgoViaPcap:
    """
    Step 3.3 verification: cert chain validation and signature algorithm extraction
    are confirmed implemented in cert_analyzer.py. These tests verify they are
    reachable via the PCAP analysis path (tls_reconstructor.py → parse_x509_certificate).

    We use a self-signed certificate DER embedded in a synthetic TLS Certificate
    handshake message. A self-signed cert provides deterministic test behavior:
    - chain_valid = False (self-signed → untrusted)
    - signature_algorithm is extractable
    Both properties flow from cert_analyzer.parse_x509_certificate() which
    tls_reconstructor.py calls directly.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def self_signed_der(cls):
        """Generate a minimal self-signed RSA certificate for testing."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # self-signed
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def _build_pcap_with_cert(self, der: bytes, intermediates=None, sni=None) -> bytes:
        """Wrap a DER cert in a TLS Certificate handshake record inside a pcap."""
        chain = [der, *(intermediates or [])]
        entries = b"".join(len(cert).to_bytes(3, "big") + cert for cert in chain)
        hs_body = len(entries).to_bytes(3, "big") + entries
        hs_len = len(hs_body)
        handshake_msg = b"\x0b" + hs_len.to_bytes(3, "big") + hs_body  # type=11

        # Wrap in TLS Record (content_type=22, version=TLS1.2)
        rec = b"\x16\x03\x03" + len(handshake_msg).to_bytes(2, "big") + handshake_msg

        pkts = [
            IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60010, seq=1000) /
                b"220 mail.example.com ESMTP\r\n",
            IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60010, dport=25, seq=2000) /
                b"EHLO test\r\nSTARTTLS\r\n",
        ]
        if sni:
            name = sni.encode("ascii")
            server_name = b"\x00" + len(name).to_bytes(2, "big") + name
            server_name_list = len(server_name).to_bytes(2, "big") + server_name
            sni_extension = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
            extensions = len(sni_extension).to_bytes(2, "big") + sni_extension
            client_hello_body = (
                b"\x03\x03" + (b"\xaa" * 32) + b"\x00\x00\x02\xc0\x2f\x01\x00" + extensions
            )
            client_hello = (
                b"\x16\x03\x03" + (len(client_hello_body) + 4).to_bytes(2, "big")
                + b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
            )
            pkts.append(
                IP(src="5.6.7.8", dst="1.2.3.4")
                / TCP(sport=60010, dport=25, seq=2020)
                / client_hello
            )
        # Inject Certificate record after optional ClientHello.
        pkts.append(
            IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60010, seq=1029) / rec
        )
        return _make_pcap(pkts)

    def test_certificate_extracted_from_pcap_stream(self, self_signed_der):
        """
        T9a: A DER certificate embedded in a TLS Certificate handshake record in a
        pcap must be extracted and stored on the stream summary.
        """
        pcap = self._build_pcap_with_cert(self_signed_der)
        result = analyze_pcap_stream(pcap, filename="cert_test.pcap")
        cert_streams = [s for s in result.streams if s.certificate_extracted]
        assert cert_streams, (
            "T9a FAIL: No stream has certificate_extracted=True. "
            "Certificate record in TLS handshake was not parsed."
        )
        cert = cert_streams[0].certificate_info
        assert cert is not None, "T9a FAIL: certificate_info is None despite extracted=True"
        assert cert.public_key_algorithm.startswith("RSA"), (
            f"T9a FAIL: Expected RSA key algorithm, got '{cert.public_key_algorithm}'"
        )
        assert cert.key_size_bits == 2048, (
            f"T9a FAIL: Expected 2048-bit key, got {cert.key_size_bits}"
        )

    def test_signature_algorithm_extracted_from_pcap_cert(self, self_signed_der):
        """
        T9b: The signature algorithm (SHA-256 in this synthetic cert) must be
        extracted from the certificate and accessible on the stream summary.
        This confirms the sig-algo extraction path works end-to-end through PCAP.
        """
        pcap = self._build_pcap_with_cert(self_signed_der)
        result = analyze_pcap_stream(pcap, filename="sigalgo_test.pcap")
        cert_streams = [s for s in result.streams if s.certificate_extracted]
        assert cert_streams, "T9b FAIL: No cert extracted from pcap"
        cert = cert_streams[0].certificate_info
        assert cert.signature_algorithm is not None, (
            "T9b FAIL: signature_algorithm is None — not extracted from cert"
        )
        assert len(cert.signature_algorithm) > 0, (
            "T9b FAIL: signature_algorithm is an empty string"
        )

    def test_self_signed_cert_detected_as_untrusted_in_pcap(self, self_signed_der):
        """
        T9c: A self-signed cert in a pcap must be flagged with chain_valid=False
        and a 'Self-Signed' or 'Untrusted Chain' finding.
        This confirms chain validation runs end-to-end through the PCAP path.
        """
        pcap = self._build_pcap_with_cert(self_signed_der)
        result = analyze_pcap_stream(pcap, filename="chain_test.pcap")
        cert_streams = [s for s in result.streams if s.certificate_extracted]
        assert cert_streams, "T9c FAIL: No cert extracted from pcap"
        cert = cert_streams[0].certificate_info
        assert cert.is_self_signed is True, (
            "T9c FAIL: Self-signed cert not detected as self-signed"
        )
        assert cert.chain_valid is False, (
            "T9c FAIL: chain_valid should be False for self-signed cert"
        )
        # Security finding should be raised
        all_findings = [f for s in result.streams for f in s.findings]
        chain_findings = [
            f for f in all_findings
            if "Self-Signed" in f.title or "Untrusted" in f.title or "Chain" in f.title
        ]
        assert chain_findings, (
            f"T9c FAIL: No chain/self-signed security finding raised. "
            f"All findings: {[f.title for f in all_findings]}"
        )

    def test_intermediate_chain_validated_in_live_and_pcap_paths(self, monkeypatch):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        from cryptography.x509.verification import Store
        from app.crypto.cert_analyzer import parse_x509_certificate

        now = datetime.now(timezone.utc)

        def issue(subject, issuer, public_key, signer_key, is_ca, add_server_identity=False):
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(public_key),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=not is_ca,
                        content_commitment=False,
                        key_encipherment=not is_ca,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=is_ca,
                        crl_sign=is_ca,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
            )
            if add_server_identity:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("mail.example.com")]),
                    critical=False,
                ).add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
            return builder.sign(signer_key, hashes.SHA256())

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Test Root")])
        root = issue(root_name, root_name, root_key.public_key(), root_key, is_ca=True)

        intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Test Intermediate")
        ])
        intermediate = issue(
            intermediate_name, root_name, intermediate_key.public_key(), root_key, is_ca=True
        )

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com")])
        leaf = issue(
            leaf_name,
            intermediate_name,
            leaf_key.public_key(),
            intermediate_key,
            is_ca=False,
            add_server_identity=True,
        )
        root_store = Store([root])
        monkeypatch.setattr("app.crypto.cert_analyzer._get_trust_store", lambda: root_store)
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
        intermediate_der = intermediate.public_bytes(serialization.Encoding.DER)

        direct_info, _ = parse_x509_certificate(
            leaf_der,
            target_domain="mail.example.com",
            intermediate_certificates=[intermediate_der],
        )
        assert direct_info.chain_valid is True
        assert "sha256" in direct_info.signature_algorithm.lower()

        capture = self._build_pcap_with_cert(
            leaf_der,
            intermediates=[intermediate_der],
            sni="mail.example.com",
        )
        result = analyze_pcap_stream(capture, filename="intermediate-chain.pcap")
        cert = next(stream.certificate_info for stream in result.streams if stream.certificate_extracted)
        assert cert is not None
        assert cert.chain_valid is True


# ---------------------------------------------------------------------------
# T10 — Unencrypted SMTP session raises HIGH finding
# ---------------------------------------------------------------------------

class TestUnencryptedSession:
    def test_unencrypted_smtp_raises_high_finding(self):
        """
        T10: An SMTP session with no STARTTLS and no TLS must produce a HIGH
        'Unencrypted Session' finding.
        """
        pkts = [
            IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60020, seq=100) /
                b"220 mail.example.com ESMTP\r\n",
            IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60020, dport=25, seq=200) /
                b"EHLO client.example.com\r\n",
            IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=25, dport=60020, seq=127) /
                b"250 OK\r\n",
            IP(src="5.6.7.8", dst="1.2.3.4") / TCP(sport=60020, dport=25, seq=225) /
                b"MAIL FROM:<sender@example.com>\r\n",
        ]
        pcap = _make_pcap(pkts)
        result = analyze_pcap_stream(pcap, filename="unencrypted.pcap")
        unencrypted_findings = [
            f for f in result.summary_findings
            if "Unencrypted" in f.title or "Cleartext" in f.title or "Plain" in f.title
        ]
        assert unencrypted_findings, (
            f"T10 FAIL: No unencrypted session finding. "
            f"Findings: {[f.title for f in result.summary_findings]}"
        )
        from app.models import FindingSeverity
        assert any(f.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
                   for f in unencrypted_findings), (
            "T10 FAIL: Unencrypted SMTP finding should be HIGH or CRITICAL"
        )


# ---------------------------------------------------------------------------
# T11 — Out-of-order packets handled without crash
# ---------------------------------------------------------------------------

class TestOutOfOrderPackets:
    def test_out_of_order_packets_no_crash(self):
        """
        T11: Packets with shuffled TCP sequence numbers must not cause a crash.
        The engine sorts segments by sequence number before reassembly.
        """
        result = analyze_pcap_stream(_out_of_order_smtp_pcap(), filename="ooo.pcap")
        assert result is not None, "T11 FAIL: analyze_pcap_stream raised an exception"
        assert result.total_tcp_streams >= 1, "T11 FAIL: Expected at least 1 stream"
        # SMTP should still be identified from port
        smtp_protocols = [p for p in result.identified_protocols if "SMTP" in p]
        assert smtp_protocols, (
            f"T11 FAIL: SMTP not identified. Got: {result.identified_protocols}"
        )
