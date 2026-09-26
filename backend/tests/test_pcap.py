import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import IP, TCP, wrpcap
from fastapi.testclient import TestClient
from app.main import app
from app.pcap.stream_reconstructor import analyze_pcap_data
from app.pcap_analyzer import analyze_pcap_stream

client = TestClient(app, headers={"X-API-Key": "test-api-key"})


def _capture_bytes(pkts) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        wrpcap(tmp_path, pkts)
        return Path(tmp_path).read_bytes()
    finally:
        os.remove(tmp_path)


def _build_synthetic_smtp_tls_pcap(include_server_hello: bool = False) -> bytes:
    """Constructs synthetic packets simulating SMTP STARTTLS and TLS ClientHello."""
    pkts = []

    # 1. Server Banner
    p1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=25, dport=45000, seq=1000) / b"220 mail.corp.net ESMTP Postfix\r\n"
    pkts.append(p1)

    # 2. Client EHLO
    p2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=45000, dport=25, seq=2000) / b"EHLO client.corp.net\r\n"
    pkts.append(p2)

    # 3. Server 250 with STARTTLS
    p3 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=25, dport=45000, seq=1032) / b"250-mail.corp.net\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(p3)

    # 4. Client STARTTLS
    p4 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=45000, dport=25, seq=2023) / b"STARTTLS\r\n"
    pkts.append(p4)

    # 5. Server 220 Ready to start TLS
    p5 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=25, dport=45000, seq=1080) / b"220 2.0.0 Ready to start TLS\r\n"
    pkts.append(p5)

    # 6. TLS ClientHello Record:
    # ContentType=22 (Handshake), Version=0x0303 (TLS 1.2), Length=45
    # Handshake: Type=1 (ClientHello), Length=41, Version=0x0303, Random (32B), SessIdLen=0, CiphersLen=2 (0xc02f), CompLen=1 (0)
    tls_payload = (
        b"\x16\x03\x03\x00\x2d"                     # Record Header
        b"\x01\x00\x00\x29"                         # ClientHello Header
        b"\x03\x03"                                 # TLS 1.2
        + (b"\xaa" * 32)                            # Random
        + b"\x00"                                   # Session ID Len = 0
        + b"\x00\x02\xc0\x2f"                       # Cipher Suite: ECDHE-RSA-AES128-GCM-SHA256
        + b"\x01\x00"                               # Compression: NULL
    )
    p6 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=45000, dport=25, seq=2033) / tls_payload
    pkts.append(p6)

    if include_server_hello:
        server_hello = (
            b"\x16\x03\x03\x00\x2c"
            b"\x02\x00\x00\x28"
            b"\x03\x03"
            + (b"\xbb" * 32)
            + b"\x00\xc0\x2f\x00\x00\x00"
        )
        pkts.append(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=25, dport=45000, seq=1080 + len(b"220 2.0.0 Ready to start TLS\r\n"))
            / server_hello
        )

    return _capture_bytes(pkts)


def _build_protocol_capture(server_port: int, server_payload: bytes, client_payload: bytes) -> bytes:
    return _capture_bytes([
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=server_port, dport=45000, seq=1000) / server_payload,
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=45000, dport=server_port, seq=2000) / client_payload,
    ])


def test_pcap_stream_reconstruction():
    pcap_data = _build_synthetic_smtp_tls_pcap()
    result = analyze_pcap_data(pcap_data, filename="synthetic_test.pcap")

    assert result.total_packets == 6
    assert result.total_tcp_streams == 1
    assert "SMTP" in result.identified_protocols

    stream = result.streams[0]
    assert stream.protocol == "SMTP"
    assert stream.starttls_detected is True
    assert stream.tls_handshake_detected is True
    assert stream.tls_version == "TLSv1.2"
    print(f"PASS: test_pcap_stream_reconstruction (Stream ID: {stream.stream_id}, Protocol: {stream.protocol}, STARTTLS: {stream.starttls_detected})")


def test_pcap_upload_endpoint():
    pcap_data = _build_synthetic_smtp_tls_pcap()
    response = client.post(
        "/api/scan/pcap",
        files={"file": ("test_mail.pcap", pcap_data, "application/vnd.tcpdump.pcap")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_mail.pcap"
    assert data["total_tcp_streams"] == 1
    assert data["streams"][0]["starttls_detected"] is True
    print("PASS: test_pcap_upload_endpoint (POST /api/scan/pcap)")


def test_smtp_session_identified_from_capture():
    capture = _build_protocol_capture(25, b"220 mx.example ESMTP\r\n", b"EHLO client.example\r\n")
    result = analyze_pcap_stream(capture)
    assert result.identified_protocols == ["SMTP"]
    assert result.streams[0].protocol == "SMTP"


def test_imap_session_identified_from_capture():
    capture = _build_protocol_capture(143, b"* OK IMAP4rev1 ready\r\n", b"a001 CAPABILITY\r\n")
    result = analyze_pcap_stream(capture)
    assert result.identified_protocols == ["IMAP"]
    assert result.streams[0].protocol == "IMAP"


def test_pop3_session_identified_from_capture():
    capture = _build_protocol_capture(110, b"+OK POP3 server ready\r\n", b"CAPA\r\n")
    result = analyze_pcap_stream(capture)
    assert result.identified_protocols == ["POP3"]
    assert result.streams[0].protocol == "POP3"


def test_starttls_negotiation_requires_server_acceptance():
    completed = analyze_pcap_stream(_build_synthetic_smtp_tls_pcap())
    assert completed.streams[0].starttls_detected is True

    rejected_capture = _build_protocol_capture(
        25,
        b"220 mx.example ESMTP\r\n250-STARTTLS\r\n250 OK\r\n454 TLS not available\r\n",
        b"EHLO client.example\r\nSTARTTLS\r\n",
    )
    rejected = analyze_pcap_stream(rejected_capture)
    assert rejected.streams[0].starttls_detected is False


def test_malformed_and_truncated_captures_do_not_crash():
    malformed = analyze_pcap_stream(b"not a pcap file")
    assert malformed.total_packets == 0
    assert malformed.summary_findings

    truncated_stream = _build_protocol_capture(
        143,
        b"* OK IMAP4rev1 ready\r\n",
        b"a001 CAPAB",
    )
    result = analyze_pcap_stream(truncated_stream)
    assert result.total_tcp_streams == 1
    assert result.streams[0].protocol == "IMAP"

    out_of_order = _capture_bytes([
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=143, dport=45000, seq=1009)
        / b"4rev1 ready\r\n",
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=143, dport=45000, seq=1000)
        / b"* OK IMAP",
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=45000, dport=143, seq=2000)
        / b"a001 CAPABILITY\r\n",
    ])
    reordered = analyze_pcap_stream(out_of_order)
    assert reordered.total_tcp_streams == 1
    assert reordered.streams[0].protocol == "IMAP"


def test_tls_version_and_cipher_extracted_from_capture():
    result = analyze_pcap_stream(_build_synthetic_smtp_tls_pcap(include_server_hello=True))
    stream = result.streams[0]
    assert stream.tls_version == "TLSv1.2"
    assert stream.cipher_suite == "ECDHE-RSA-AES128-GCM-SHA256"


if __name__ == "__main__":
    test_pcap_stream_reconstruction()
    test_pcap_upload_endpoint()
    print("\nALL PCAP STREAM RECONSTRUCTION TESTS PASSED!")
