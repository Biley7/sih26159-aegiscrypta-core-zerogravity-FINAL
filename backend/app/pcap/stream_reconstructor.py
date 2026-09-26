import io
import tempfile
import os
import logging
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional

# Suppress scapy runtime warnings when WinPcap/Npcap is not installed
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", module="scapy")

from scapy.all import rdpcap, TCP, IP, IPv6
from app.models import (
    PcapAnalysisResponse,
    TcpStreamSummary,
    SecurityFinding,
    FindingSeverity
)
from app.pcap.tls_reconstructor import parse_tls_records_from_stream


def _identify_protocol_from_ports_and_payload(sport: int, dport: int, payload: bytes) -> str:
    """Identifies protocol based on well-known mail ports or initial text signatures."""
    ports = {sport, dport}
    if 25 in ports or 587 in ports:
        return "SMTP"
    if 465 in ports:
        return "SMTP (SMTPS)"
    if 143 in ports:
        return "IMAP"
    if 993 in ports:
        return "IMAP (IMAPS)"
    if 110 in ports:
        return "POP3"
    if 995 in ports:
        return "POP3 (POP3S)"

    # Payload signature heuristics
    upper_sample = payload[:256].decode("utf-8", errors="ignore").upper()
    if "220 " in upper_sample and ("SMTP" in upper_sample or "ESMTP" in upper_sample):
        return "SMTP"
    if "* OK" in upper_sample and ("IMAP" in upper_sample or "CAPABILITY" in upper_sample):
        return "IMAP"
    if "+OK" in upper_sample:
        return "POP3"
    if payload.startswith(b"\x16\x03"):
        return "TLS"

    return "TCP/Unknown"


def analyze_pcap_data(pcap_bytes: bytes, filename: str = "capture.pcap") -> PcapAnalysisResponse:
    """
    Reconstructs TCP streams and passive TLS handshakes from a PCAP / PCAPNG byte stream:
    - Reassembles bidirectional TCP flows.
    - Identifies mail protocols (SMTP, IMAP, POP3, TLS).
    - Detects STARTTLS negotiation and protocol transitions.
    - Reconstructs TLS records, cipher negotiations, and X.509 certificates.
    - Generates prioritized security findings.
    """
    # Write to a temporary file for Scapy rdpcap reader
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(pcap_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    total_packets = len(packets)
    streams: Dict[Tuple, Dict[str, Any]] = {}

    stream_counter = 0

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if not ip_layer:
            continue

        tcp_layer = pkt.getlayer(TCP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        # Canonical flow key
        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

        if flow_key not in streams:
            stream_counter += 1
            streams[flow_key] = {
                "stream_id": stream_counter,
                "client_ip": src_ip,
                "client_port": src_port,
                "server_ip": dst_ip,
                "server_port": dst_port,
                "packets": 0,
                "client_bytes": 0,
                "server_bytes": 0,
                "client_payloads": [],
                "server_payloads": [],
                "all_payload": bytearray()
            }

        s_entry = streams[flow_key]
        s_entry["packets"] += 1

        payload = bytes(tcp_layer.payload)
        if payload:
            if src_ip == s_entry["client_ip"] and src_port == s_entry["client_port"]:
                s_entry["client_bytes"] += len(payload)
                s_entry["client_payloads"].append(payload)
            else:
                s_entry["server_bytes"] += len(payload)
                s_entry["server_payloads"].append(payload)
            s_entry["all_payload"].extend(payload)

    stream_summaries: List[TcpStreamSummary] = []
    identified_protocols = set()
    all_summary_findings: List[SecurityFinding] = []

    for key, flow in streams.items():
        combined_payload = bytes(flow["all_payload"])
        protocol = _identify_protocol_from_ports_and_payload(
            flow["client_port"],
            flow["server_port"],
            combined_payload
        )
        identified_protocols.add(protocol)

        # Check for STARTTLS advertising and negotiation in plaintext
        upper_text = combined_payload.decode("utf-8", errors="ignore").upper()
        starttls_detected = any(w in upper_text for w in ["STARTTLS", "STLS"])

        # Check for TLS Handshake records
        tls_detected = b"\x16\x03" in combined_payload
        tls_version = None
        cipher_suite = None
        cert_info = None
        findings: List[SecurityFinding] = []

        if tls_detected:
            # Locate first TLS record in payload
            tls_idx = combined_payload.find(b"\x16\x03")
            if tls_idx >= 0:
                tls_data = combined_payload[tls_idx:]
                handshake = parse_tls_records_from_stream(tls_data)
                tls_version = handshake.negotiated_version or handshake.client_version
                cipher_suite = handshake.selected_cipher
                cert_info = handshake.certificate_info
                findings.extend(handshake.findings)

        # Passive Security Findings on the Stream
        if not tls_detected and starttls_detected:
            findings.append(SecurityFinding(
                title="STARTTLS Stripping or Fallback Detected in PCAP",
                severity=FindingSeverity.HIGH,
                category="Protocol",
                description=f"Stream #{flow['stream_id']} negotiated STARTTLS in plaintext but no TLS encrypted records followed.",
                recommendation="Investigate possible MitM proxy or STARTTLS stripping downgrade attack on the network segment."
            ))

        if not tls_detected and not starttls_detected and protocol in ["SMTP", "IMAP", "POP3"]:
            findings.append(SecurityFinding(
                title=f"Unencrypted Cleartext {protocol} Session",
                severity=FindingSeverity.HIGH,
                category="Protocol",
                description=f"Stream #{flow['stream_id']} exchanged {protocol} commands and data completely in the clear.",
                recommendation=f"Enforce mandatory TLS encryption for all {protocol} traffic."
            ))

        all_summary_findings.extend(findings)

        summary = TcpStreamSummary(
            stream_id=flow["stream_id"],
            client_ip=flow["client_ip"],
            client_port=flow["client_port"],
            server_ip=flow["server_ip"],
            server_port=flow["server_port"],
            protocol=protocol,
            packet_count=flow["packets"],
            client_bytes=flow["client_bytes"],
            server_bytes=flow["server_bytes"],
            starttls_detected=starttls_detected,
            tls_handshake_detected=tls_detected,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            certificate_extracted=cert_info is not None,
            certificate_info=cert_info,
            findings=findings
        )
        stream_summaries.append(summary)

    # Deduplicate summary findings
    unique_summary_findings: List[SecurityFinding] = []
    seen = set()
    for f in all_summary_findings:
        if f.title not in seen:
            unique_summary_findings.append(f)
            seen.add(f.title)

    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4
    }
    unique_summary_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    return PcapAnalysisResponse(
        filename=filename,
        total_packets=total_packets,
        total_tcp_streams=len(streams),
        identified_protocols=sorted(list(identified_protocols)),
        streams=stream_summaries,
        summary_findings=unique_summary_findings,
        processed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
