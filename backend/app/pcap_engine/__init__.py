"""
AegisCrypta PCAP Engine - Passive Network Traffic Analysis

Implements passive analysis of captured PCAP traffic for email security forensics:
- Protocol identification (SMTP, IMAP, POP3)
- TCP stream reconstruction
- STARTTLS negotiation detection
- TLS handshake reconstruction from historical captures

Uses scapy for packet parsing and stream reconstruction.
"""

from .stream_reconstructor import reconstruct_tcp_streams
from .protocol_identifier import identify_protocols
from .starttls_detector import detect_starttls_negotiation
from .tls_parser import parse_tls_handshake_from_stream

__all__ = [
    'reconstruct_tcp_streams',
    'identify_protocols',
    'detect_starttls_negotiation',
    'parse_tls_handshake_from_stream'
]
