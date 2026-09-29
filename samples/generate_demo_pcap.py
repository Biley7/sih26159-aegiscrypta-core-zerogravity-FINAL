#!/usr/bin/env python3
"""
Generate the AegisCrypta evaluation capture: samples/aegis_demo_smtp.pcap

The capture is a single SMTP conversation that performs a *clean* STARTTLS
negotiation, so evaluators can exercise the Passive PCAP Forensics tab without
hunting for their own traffic:

    S> 220 mail.aegis-demo.test ESMTP Postfix
    C> EHLO client.aegis-demo.test
    S> 250-mail.aegis-demo.test ... 250-STARTTLS ... 250 OK
    C> STARTTLS
    S> 220 2.0.0 Ready to start TLS
    C> TLS ClientHello  (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256)
    S< TLS ServerHello  (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256)

Expected verdict: SMTP identified, STARTTLS upgrade detected, no cleartext
credential exposure. All addresses come from the RFC 5737 documentation ranges
(203.0.113.0/24 and 198.51.100.0/24), so nothing here references real hosts.

Usage (from the repository root, using the backend virtualenv):

    backend/.venv/bin/python samples/generate_demo_pcap.py

    # regenerate into a custom location
    backend/.venv/bin/python samples/generate_demo_pcap.py --out /tmp/demo.pcap

    # generate and immediately run the backend analyzer over the result
    backend/.venv/bin/python samples/generate_demo_pcap.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

# ---------------------------------------------------------------------------
# Capture parameters (RFC 5737 documentation ranges — no real infrastructure)
# ---------------------------------------------------------------------------

SERVER_IP = "203.0.113.25"
CLIENT_IP = "198.51.100.24"
SERVER_PORT = 25
CLIENT_PORT = 41234

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "aegis_demo_smtp.pcap"


def _tls_client_hello() -> bytes:
    """TLS 1.2 ClientHello offering ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)."""
    return (
        b"\x16\x03\x03\x00\x2d"          # TLS record header: handshake, TLS 1.2, 45 bytes
        b"\x01\x00\x00\x29"              # ClientHello, 41 bytes
        b"\x03\x03"                      # client_version = TLS 1.2
        + b"\xab" * 32                   # client random
        + b"\x00"                        # session_id length = 0
        + b"\x00\x02\xc0\x2f"            # cipher_suites: ECDHE-RSA-AES128-GCM-SHA256
        + b"\x01\x00"                    # compression: null
    )


def _tls_server_hello() -> bytes:
    """TLS 1.2 ServerHello selecting ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)."""
    body = (
        b"\x03\x03"                      # server_version = TLS 1.2
        + b"\xcd" * 32                   # server random
        + b"\x00"                        # session_id length = 0
        + b"\xc0\x2f"                    # selected cipher suite
        + b"\x00"                        # selected compression
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def build_packets() -> list:
    """Return the ordered packet list for one STARTTLS-protected SMTP session."""
    c2s = dict(src=CLIENT_IP, dst=SERVER_IP, sport=CLIENT_PORT, dport=SERVER_PORT)
    s2c = dict(src=SERVER_IP, dst=CLIENT_IP, sport=SERVER_PORT, dport=CLIENT_PORT)

    def pkt(direction: dict, seq: int, payload: bytes = b"", flags: str = "PA"):
        return (
            Ether()
            / IP(src=direction["src"], dst=direction["dst"])
            / TCP(sport=direction["sport"], dport=direction["dport"], seq=seq, flags=flags)
            / payload
        )

    return [
        # --- TCP three-way handshake -------------------------------------
        pkt(c2s, 1000, b"", "S"),
        pkt(s2c, 5000, b"", "SA"),
        pkt(c2s, 1001, b"", "A"),

        # --- SMTP banner + EHLO + STARTTLS advertisement -----------------
        pkt(s2c, 5001, b"220 mail.aegis-demo.test ESMTP Postfix\r\n"),
        pkt(c2s, 1001, b"EHLO client.aegis-demo.test\r\n"),
        pkt(
            s2c,
            5041,
            b"250-mail.aegis-demo.test\r\n"
            b"250-PIPELINING\r\n"
            b"250-SIZE 10240000\r\n"
            b"250-STARTTLS\r\n"
            b"250 8BITMIME\r\n",
        ),

        # --- STARTTLS negotiation ---------------------------------------
        pkt(c2s, 1036, b"STARTTLS\r\n"),
        pkt(s2c, 5141, b"220 2.0.0 Ready to start TLS\r\n"),

        # --- TLS handshake records after the upgrade --------------------
        pkt(c2s, 1049, _tls_client_hello()),
        pkt(s2c, 5165, _tls_server_hello()),

        # --- Clean teardown --------------------------------------------
        pkt(c2s, 1100, b"", "FA"),
        pkt(s2c, 5220, b"", "FA"),
    ]


def generate(output: Path) -> Path:
    """Write the demo capture to `output` and return the resolved path."""
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(output), packets)
    return output.resolve()


def _run_backend_check(path: Path) -> int:
    """Run the real backend analyzer over the generated capture."""
    backend_dir = Path(__file__).resolve().parent.parent / "backend"
    sys.path.insert(0, str(backend_dir))
    try:
        from app.pcap_analyzer import analyze_pcap_stream
    except ImportError as exc:  # pragma: no cover - only hit outside the venv
        print(f"[check] skipped: backend package not importable ({exc})")
        return 0

    result = analyze_pcap_stream(path.read_bytes(), filename=path.name)
    print("[check] backend analyzer verdict")
    print(f"        packets         : {result.total_packets}")
    print(f"        tcp streams     : {result.total_tcp_streams}")
    print(f"        protocols       : {', '.join(result.identified_protocols) or 'none'}")
    for finding in result.summary_findings:
        print(f"        finding         : [{finding.severity.value}] {finding.title}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT, help="output .pcap path")
    parser.add_argument("--check", action="store_true", help="run the backend analyzer over the result")
    args = parser.parse_args()

    written = generate(args.out)
    print(f"wrote {written} ({written.stat().st_size} bytes, {len(build_packets())} packets)")

    if args.check:
        return _run_backend_check(written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
