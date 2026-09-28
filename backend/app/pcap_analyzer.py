import io
import os
import tempfile
import base64
import logging
import warnings
import re
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional

# Suppress scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", module="scapy")

from scapy.all import rdpcap, TCP, IP, IPv6
from app.models import (
    PcapAnalysisResponse,
    TcpStreamSummary,
    SecurityFinding,
    FindingSeverity,
    CertificateInfo
)
from app.crypto.cipher_evaluator import parse_key_exchange
from app.pcap.tls_reconstructor import parse_tls_records_from_stream
from app.risk_engine import (
    compute_crypto_deprecation_index,
    compute_posture_exposure_deficit,
    compute_exploitation_likelihood_index,
    compute_posture_risk
)


def identify_protocol(sport: int, dport: int, payload: bytes) -> str:
    """Identifies protocol based on well-known ports and initial payload signatures."""
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

    sample = payload[:300].decode("utf-8", errors="ignore").upper()
    if "220 " in sample and ("SMTP" in sample or "ESMTP" in sample or "MAIL" in sample):
        return "SMTP"
    if "* OK" in sample and ("IMAP" in sample or "CAPABILITY" in sample):
        return "IMAP"
    if "+OK" in sample:
        return "POP3"
    if payload.startswith(b"\x16\x03"):
        return "TLS"

    return "TCP/Unknown"


def detect_cleartext_credentials(text: str, protocol: str = "Mail") -> List[Tuple[str, str]]:
    """
    Detects exposed passwords or credentials in plaintext mail sessions (SMTP/IMAP/POP3).
    Returns list of (type, masked_token) tuples.

    ``protocol`` labels each finding with the protocol actually observed on the
    stream. The token patterns themselves are protocol-agnostic on the wire — an
    ``AUTH LOGIN`` challenge/response is byte-identical whether it arrives over
    SMTP or IMAP — so hardcoding a protocol here previously mislabelled SMTP
    ``AUTH LOGIN`` captures as IMAP. Callers pass the detected stream protocol;
    the neutral "Mail" default keeps the signature safe for direct callers.
    """
    findings = []

    # POP3 USER / PASS
    pop3_pass = re.findall(r"\bPASS\s+([^\r\n]+)", text, re.IGNORECASE)
    for p in pop3_pass:
        masked = p[:2] + "****" if len(p) > 2 else "****"
        findings.append((f"{protocol} Cleartext Password", masked))

    # LOGIN user pass (SMTP AUTH LOGIN challenge/response, or IMAP LOGIN)
    imap_login = re.findall(r"\bLOGIN\s+([^\s\r\n]+)\s+([^\r\n]+)", text, re.IGNORECASE)
    for u, p in imap_login:
        masked_p = p[:2] + "****" if len(p) > 2 else "****"
        findings.append((f"{protocol} Cleartext Login", f"User: {u}, Pass: {masked_p}"))

    # SMTP AUTH PLAIN or AUTH LOGIN tokens
    auth_plain = re.findall(r"\bAUTH\s+PLAIN\s+([A-Za-z0-9+/=]{8,})", text, re.IGNORECASE)
    for token in auth_plain:
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
            parts = decoded.split("\x00")
            user = parts[1] if len(parts) > 1 else "user"
            findings.append((f"{protocol} Cleartext AUTH PLAIN", f"User: {user} [Base64 token exposed]"))
        except Exception:
            findings.append((f"{protocol} Cleartext AUTH PLAIN", "Base64 token exposed"))

    return findings


def _extract_pcap_crypto_metrics(streams: List[TcpStreamSummary]) -> Dict:
    """Extract cryptographic metrics from PCAP streams for fuzzy engine input."""
    metrics = {
        'tls_version': None,
        'cipher_name': None,
        'key_algorithm': None,
        'key_size_bits': None,
        'days_until_expiry': None,
        'banner': None,
        'forward_secrecy': False,
        'signature_algorithm': None,
        'chain_valid': True,
        'is_self_signed': False
    }
    
    # Find first stream with TLS data
    for stream in streams:
        if stream.tls_version:
            metrics['tls_version'] = stream.tls_version
        if stream.cipher_suite:
            metrics['cipher_name'] = stream.cipher_suite
            _, is_fs = parse_key_exchange(stream.cipher_suite, stream.tls_version or "")
            metrics['forward_secrecy'] = is_fs
        if stream.certificate_info:
            cert = stream.certificate_info
            metrics['key_algorithm'] = cert.public_key_algorithm
            metrics['key_size_bits'] = cert.key_size_bits
            metrics['days_until_expiry'] = cert.days_until_expiry
            metrics['signature_algorithm'] = cert.signature_algorithm
            metrics['is_self_signed'] = cert.is_self_signed
            if cert.chain_valid is False:
                metrics['chain_valid'] = False
        if metrics['tls_version']:
            break
    
    return metrics


def _severity_from_classification(classification: str) -> FindingSeverity:
    """Convert fuzzy classification to finding severity."""
    mapping = {
        'EXCELLENT': FindingSeverity.INFO,
        'GOOD': FindingSeverity.LOW,
        'ACCEPTABLE': FindingSeverity.MEDIUM,
        'POOR': FindingSeverity.HIGH,
        'CRITICAL': FindingSeverity.CRITICAL
    }
    return mapping.get(classification, FindingSeverity.MEDIUM)


def analyze_pcap_stream(pcap_bytes: bytes, filename: str = "capture.pcap") -> PcapAnalysisResponse:
    """
    High-density passive PCAP/PCAPNG forensic reconstructor:
    - Bidirectional TCP session reassembly across SMTP (25, 465, 587), IMAP (143, 993), POP3 (110, 995).
    - Detects protocol state transitions: Plaintext EHLO/CAPA -> STARTTLS/STLS -> TLS Record (0x16 0x03).
    - Detects unencrypted authentication and credential exposure.
    - Flags STARTTLS stripping and downgrade attacks.
    - Parses ClientHello/ServerHello TLS handshakes and extracts X.509 leaf certificates with SHA-256 fingerprints.
    - Integrates with fuzzy logic risk engine for consistent scoring with live scans.
    """
    # ------------------------------------------------------------------
    # VULN-06: Write PCAP bytes to a named temp file for Scapy, then
    # guarantee deletion in a finally block regardless of parse errors,
    # format failures, or unexpected exceptions.
    # ------------------------------------------------------------------
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name

        try:
            packets = rdpcap(tmp_path)
        except Exception as e:
            # Fallback empty response on malformed capture file
            return PcapAnalysisResponse(
                filename=filename,
                total_packets=0,
                total_tcp_streams=0,
                identified_protocols=[],
                streams=[],
                summary_findings=[
                    SecurityFinding(
                        title="PCAP Reassembly Error",
                        severity=FindingSeverity.HIGH,
                        category="Forensics",
                        description=f"Could not parse capture file: {str(e)}",
                        recommendation="Ensure the file is a valid libpcap (.pcap) or pcapng packet capture."
                    )
                ],
                processed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            )
    finally:
        # Always remove the temp file — even if rdpcap raised or an outer
        # exception propagated before the return above was reached.
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
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
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)

        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

        if flow_key not in streams:
            stream_counter += 1
            service_ports = {25, 465, 587, 110, 995, 143, 993}
            if dst_port in service_ports:
                client_ip, client_port = src_ip, src_port
                server_ip, server_port = dst_ip, dst_port
            elif src_port in service_ports:
                client_ip, client_port = dst_ip, dst_port
                server_ip, server_port = src_ip, src_port
            else:
                client_ip, client_port = src_ip, src_port
                server_ip, server_port = dst_ip, dst_port
            streams[flow_key] = {
                "stream_id": stream_counter,
                "client_ip": client_ip,
                "client_port": client_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "packets": 0,
                "client_bytes": 0,
                "server_bytes": 0,
                "client_segments": [],
                "server_segments": [],
                "chronological_payloads": []
            }

        s_entry = streams[flow_key]
        s_entry["packets"] += 1

        payload = bytes(tcp_layer.payload)
        seq = int(tcp_layer.seq)
        is_client = (src_ip == s_entry["client_ip"] and src_port == s_entry["client_port"])

        if payload:
            if is_client:
                s_entry["client_bytes"] += len(payload)
                s_entry["client_segments"].append((seq, payload))
            else:
                s_entry["server_bytes"] += len(payload)
                s_entry["server_segments"].append((seq, payload))
            s_entry["chronological_payloads"].append((seq, is_client, payload))

    stream_summaries: List[TcpStreamSummary] = []
    identified_protocols = set()
    all_summary_findings: List[SecurityFinding] = []

    for flow in streams.values():
        # Reorder client and server payloads by sequence number (Task 1.1)
        def reassemble_segments(segments):
            if not segments:
                return b"", ""
            segments.sort(key=lambda x: x[0])
            reconstructed = bytearray()
            seen_seqs = set()
            for s_seq, s_payload in segments:
                if s_seq not in seen_seqs:
                    reconstructed.extend(s_payload)
                    seen_seqs.add(s_seq)
            text = reconstructed.decode("utf-8", errors="ignore")
            return bytes(reconstructed), text

        client_raw, client_text = reassemble_segments(flow["client_segments"])
        server_raw, server_text = reassemble_segments(flow["server_segments"])

        # Reconstruct combined payload
        combined_payload = bytearray()
        for _, _, p in flow["chronological_payloads"]:
            combined_payload.extend(p)
        combined_payload = bytes(combined_payload)

        protocol = identify_protocol(flow["client_port"], flow["server_port"], combined_payload)
        identified_protocols.add(protocol)

        combined_text = combined_payload.decode("utf-8", errors="ignore")
        upper_text = combined_text.upper()

        # Check for STARTTLS advertisement and negotiation
        starttls_advertised = "STARTTLS" in server_text.upper() or "STLS" in server_text.upper()
        starttls_requested = "STARTTLS" in client_text.upper() or "STLS" in client_text.upper()
        if protocol == "SMTP":
            starttls_detected = (
                re.search(r"(?im)^250[- ]STARTTLS(?:\s|$)", server_text) is not None
                and re.search(r"(?im)^STARTTLS\s*$", client_text) is not None
                and re.search(r"(?im)^220[ -][^\r\n]*(?:READY TO START TLS|STARTTLS)", server_text) is not None
            )
        elif protocol == "IMAP":
            command = re.search(r"(?im)^([A-Za-z0-9]+)\s+STARTTLS\s*$", client_text)
            starttls_detected = bool(
                command
                and re.search(rf"(?im)^{re.escape(command.group(1))}\s+OK(?:\s|$)", server_text)
            )
        elif protocol == "POP3":
            starttls_detected = (
                re.search(r"(?im)^STLS\s*$", client_text) is not None
                and re.search(r"(?im)^\+OK[^\r\n]*(?:BEGIN|START).*TLS", server_text) is not None
            )
        else:
            starttls_detected = False

        # Check for TLS Handshake record (0x16 0x03)
        tls_detected = b"\x16\x03" in combined_payload
        tls_version = None
        cipher_suite = None
        cert_info = None
        findings: List[SecurityFinding] = []

        if tls_detected:
            tls_idx = combined_payload.find(b"\x16\x03")
            if tls_idx >= 0:
                tls_data = combined_payload[tls_idx:]
                handshake = parse_tls_records_from_stream(tls_data)
                tls_version = handshake.negotiated_version or handshake.client_version
                cipher_suite = handshake.selected_cipher
                cert_info = handshake.certificate_info
                findings.extend(handshake.findings)

        # 1. Plaintext credential exposure detection. The finding is labelled with
        # the protocol actually observed on this stream (SMTP/IMAP/POP3); anything
        # else falls back to a neutral "Mail" label rather than guessing.
        credential_protocol = protocol if protocol in {"SMTP", "IMAP", "POP3"} else "Mail"
        cred_leaks = detect_cleartext_credentials(combined_text, credential_protocol)
        for leak_type, leak_details in cred_leaks:
            findings.append(SecurityFinding(
                title=f"Cleartext Credential Exposure ({leak_type})",
                severity=FindingSeverity.CRITICAL,
                category="Forensics",
                description=f"Stream #{flow['stream_id']} ({protocol}) transmitted cleartext authentication credentials over unencrypted TCP session ({leak_details}).",
                recommendation="Enforce mandatory TLS encryption before allowing user authentication commands (RFC 8314)."
            ))

        # 2. STARTTLS Security Analysis (Tasks 1.2a, 1.2b, 1.2c)
        # (a) STARTTLS offered but not used
        if starttls_advertised and not starttls_requested and not tls_detected:
            findings.append(SecurityFinding(
                title="STARTTLS Offered But Not Used",
                severity=FindingSeverity.HIGH,
                category="Protocol",
                description=f"Stream #{flow['stream_id']} ({protocol}): Server offered STARTTLS encryption capability, but client did not initiate encryption and transmitted cleartext traffic.",
                recommendation="Enforce mandatory TLS in mail client / MTA transport configuration (RFC 8314)."
            ))

        # (b) Sensitive command (login/auth) precedes confirmed TLS upgrade
        if tls_detected:
            tls_idx = combined_payload.find(b"\x16\x03")
            pre_tls_text = combined_payload[:tls_idx].decode("utf-8", errors="ignore") if tls_idx > 0 else ""
            pre_tls_cred_leaks = detect_cleartext_credentials(pre_tls_text, credential_protocol)
            has_auth_cmd = any(cmd in pre_tls_text.upper() for cmd in ["AUTH ", "LOGIN ", "PASS "])
            if pre_tls_cred_leaks or has_auth_cmd:
                findings.append(SecurityFinding(
                    title="Sensitive Authentication Precedes TLS Upgrade",
                    severity=FindingSeverity.CRITICAL,
                    category="Forensics",
                    description=f"Stream #{flow['stream_id']} ({protocol}) attempted authentication in cleartext prior to confirmed TLS upgrade.",
                    recommendation="Ensure TLS session negotiation completes strictly before issuing authentication credentials."
                ))

        # (c) STARTTLS response pattern looks stripped/interfered with
        if starttls_requested and not tls_detected:
            findings.append(SecurityFinding(
                title="STARTTLS Stripping / Downgrade Attack Detected",
                severity=FindingSeverity.CRITICAL,
                category="Protocol",
                description=f"Stream #{flow['stream_id']} requested STARTTLS in plaintext, but negotiation was dropped or intercepted and no TLS records followed.",
                recommendation="Deploy MTA-STS (RFC 8461) and DANE/TLSA (RFC 7672) to enforce strict encrypted transport and thwart active MitM stripping attacks."
            ))
        elif not tls_detected and not starttls_detected and protocol in ["SMTP", "IMAP", "POP3"]:
            findings.append(SecurityFinding(
                title=f"Unencrypted {protocol} Session in Cleartext",
                severity=FindingSeverity.HIGH,
                category="Protocol",
                description=f"Stream #{flow['stream_id']} transmitted {protocol} traffic completely in the clear without STARTTLS or direct TLS.",
                recommendation=f"Configure MTA to enforce mandatory TLS encryption on {protocol} ports."
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
    unique_findings: List[SecurityFinding] = []
    seen = set()
    for f in all_summary_findings:
        if f.title not in seen:
            unique_findings.append(f)
            seen.add(f.title)

    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4
    }
    unique_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    # Integrate fuzzy logic risk scoring (Tasks 1.4 & 2.1)
    pcap_crypto_metrics = _extract_pcap_crypto_metrics(stream_summaries)
    
    # Compute Tier 1 composite indices
    cdi_score, cdi_factors = compute_crypto_deprecation_index(
        tls_version=pcap_crypto_metrics.get('tls_version') or 'TLS 1.2',
        cipher_name=pcap_crypto_metrics.get('cipher_name') or 'TLS_AES_128_GCM_SHA256',
        key_algorithm=pcap_crypto_metrics.get('key_algorithm') or 'RSA',
        key_size_bits=pcap_crypto_metrics.get('key_size_bits') or 2048,
        days_until_expiry=pcap_crypto_metrics.get('days_until_expiry') or 180,
        forward_secrecy=pcap_crypto_metrics.get('forward_secrecy', False)
    )
    
    # A packet capture cannot observe DNS authentication posture. These inputs are a
    # deliberate worst-case assumption, not an observation, and they dominate the PED
    # axis — which is why a capture with only moderate cryptographic findings can fuse
    # to CRITICAL. The assumption is disclosed in summary_findings below so the
    # classification is never attributed to the captured traffic.
    ped_score, ped_factors = compute_posture_exposure_deficit(
        spf_present=False,  # Cannot determine from PCAP alone
        dkim_present=False,  # Cannot determine from PCAP alone
        dmarc_policy="p=none",  # Cannot determine from PCAP alone
        dmarc_enforcement="monitoring only",
        dnssec_enabled=False  # Cannot determine from PCAP alone
    )
    
    eli_score, eli_factors = compute_exploitation_likelihood_index(
        banner=pcap_crypto_metrics.get('banner'),
        is_customer_facing=False
    )
    
    # Derive granular antecedent components matching scoring.py
    tls_ver = (pcap_crypto_metrics.get('tls_version') or "").upper()
    tls_comp = 1.0 if "1.3" in tls_ver else (0.75 if "1.2" in tls_ver else 0.1)

    from app.risk_engine.crypto_deprecation import classify_cipher_strength
    c_class = classify_cipher_strength(pcap_crypto_metrics.get('cipher_name') or "")
    c_strength = 1.0 if c_class == "strong" else (0.6 if c_class == "moderate" else 0.1)

    # certificate_health is asserted only when the capture actually carried an X.509
    # certificate. A capture with no certificate material is an absence of evidence,
    # not evidence of a broken certificate: scoring it 0.0 drove an otherwise clean
    # TLS session to a CRITICAL fuzzy assessment. When there is no certificate the
    # antecedent is omitted, letting the risk engine derive it from the observed
    # cipher/TLS components instead.
    cert_evidence_finding: Optional[SecurityFinding] = None
    days_exp = pcap_crypto_metrics.get('days_until_expiry')
    if days_exp is None:
        cert_hlth = None
        cert_evidence_finding = SecurityFinding(
            title="No X.509 Certificate Observed in Capture",
            severity=FindingSeverity.INFO,
            category="Certificate",
            description=(
                "The capture did not contain the server's certificate, so certificate "
                "validity, expiry and chain trust could not be assessed. Certificate "
                "health was derived from the observed TLS/cipher posture rather than "
                "treated as a failure."
            ),
            recommendation=(
                "Capture the full TLS handshake (including Certificate and CertificateVerify "
                "messages) to enable certificate and chain validation."
            )
        )
    elif days_exp <= 0:
        cert_hlth = 0.0
    elif days_exp >= 90:
        cert_hlth = 1.0
    elif days_exp >= 30:
        cert_hlth = round(0.5 + (days_exp - 30) / 60.0 * 0.5, 3)
    else:
        cert_hlth = round(max(0.0, days_exp / 30.0 * 0.5), 3)

    if cert_hlth is not None:
        sig_lower = (pcap_crypto_metrics.get('signature_algorithm') or "").lower()
        if any(weak in sig_lower for weak in ["sha1", "md5", "sha-1"]):
            cert_hlth = min(cert_hlth, 0.1)
        if pcap_crypto_metrics.get('is_self_signed') or not pcap_crypto_metrics.get('chain_valid', True):
            cert_hlth = min(cert_hlth, 0.2)

    raw_crypto_metrics = {
        'tls_compliance': tls_comp,
        'cipher_strength': c_strength,
        'pqc_readiness': 0.5
    }
    if cert_hlth is not None:
        raw_crypto_metrics['certificate_health'] = cert_hlth

    # Compute Tier 2 final fusion
    fuzzy_risk_score, linguistic_classification, antecedent_scores, risk_factors = compute_posture_risk(
        cdi_score=cdi_score,
        ped_score=ped_score,
        eli_score=eli_score,
        raw_crypto_metrics=raw_crypto_metrics
    )
    # Convert fuzzy risk score (0-100, 100=highest risk) to posture score (0-100, 100=best posture)
    fuzzy_posture_score = round(max(0.0, min(100.0, 100.0 - fuzzy_risk_score)), 1)
    
    # Disclose when certificate health could not be assessed from this capture
    if cert_evidence_finding is not None:
        unique_findings.append(cert_evidence_finding)

    # Disclose the DNS assumption the fused score depends on
    unique_findings.append(SecurityFinding(
        title="Fused Score Relies on an Unverifiable DNS Assumption",
        severity=FindingSeverity.LOW,
        category="Risk Assessment",
        description=(
            "The fused posture score below combines the cryptographic findings from this "
            "capture with a conservative assumption that SPF, DKIM, DMARC enforcement and "
            "DNSSEC are all absent, because a passive capture cannot observe DNS "
            "authentication posture. A POOR or CRITICAL classification can therefore be "
            "driven by that assumption rather than by the captured traffic."
        ),
        recommendation=(
            "Read the per-stream findings for what the capture actually proves, and run an "
            "active domain scan to assess DNS authentication posture."
        )
    ))

    # Add fuzzy findings to summary
    unique_findings.append(SecurityFinding(
        title=f"PCAP Fuzzy Risk Assessment: {linguistic_classification}",
        severity=_severity_from_classification(linguistic_classification),
        category="Risk Assessment",
        description=(
            f"Fuzzy logic posture score: {fuzzy_posture_score:.1f}/100 (Risk: {fuzzy_risk_score:.1f}) "
            "based on cryptographic posture analysis from packet capture, including the "
            "conservative DNS authentication assumption described above."
        ),
        recommendation="Review individual stream findings for specific remediation steps."
    ))

    # Keep the contract ordering (severity descending) after the late additions
    unique_findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    return PcapAnalysisResponse(
        filename=filename,
        total_packets=total_packets,
        total_tcp_streams=len(streams),
        identified_protocols=sorted(list(identified_protocols)),
        streams=stream_summaries,
        summary_findings=unique_findings,
        processed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        fuzzy_score=fuzzy_posture_score,
        linguistic_classification=linguistic_classification,
        antecedent_scores=antecedent_scores
    )
