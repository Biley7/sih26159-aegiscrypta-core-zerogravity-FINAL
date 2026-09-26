"""
Protocol Identifier for PCAP Analysis

Identifies SMTP, IMAP, and POP3 sessions by:
- Port numbers (25/587/465, 143/993, 110/995)
- Plaintext banner/command syntax inspection as fallback
"""

from typing import List, Optional
from .stream_reconstructor import TcpStream


def identify_protocols(streams: List[TcpStream]) -> List[dict]:
    """
    Identify protocols for each TCP stream.
    
    Args:
        streams: List of TcpStream objects
    
    Returns:
        List of protocol identification results
    """
    results = []
    
    for stream in streams:
        protocol = _identify_stream_protocol(stream)
        results.append({
            'stream_id': stream.stream_id,
            'protocol': protocol,
            'client_ip': stream.client_ip,
            'client_port': stream.client_port,
            'server_ip': stream.server_ip,
            'server_port': stream.server_port,
            'confidence': _get_protocol_confidence(stream, protocol)
        })
    
    return results


def _identify_stream_protocol(stream: TcpStream) -> str:
    """Identify protocol for a single stream."""
    if not stream.server_port:
        return "UNKNOWN"
    
    # Port-based identification (primary method)
    port = stream.server_port
    
    # SMTP ports
    if port in [25, 587, 465]:
        return "SMTP"
    
    # IMAP ports
    if port in [143, 993]:
        return "IMAP"
    
    # POP3 ports
    if port in [110, 995]:
        return "POP3"
    
    # Fallback: inspect banner/command syntax
    return _identify_by_banner(stream)


def _identify_by_banner(stream: TcpStream) -> str:
    """Identify protocol by inspecting banner text."""
    if not stream.reassembled_payload:
        return "UNKNOWN"
    
    try:
        banner = stream.reassembled_payload.decode('utf-8', errors='ignore').lower()
    except:
        return "UNKNOWN"
    
    # SMTP indicators
    if any(x in banner for x in ['220', 'esmtp', 'ehlo', 'helo', 'mail from']):
        return "SMTP"
    
    # IMAP indicators
    if any(x in banner for x in ['* ok', 'imap', 'login', 'authenticate', 'select']):
        return "IMAP"
    
    # POP3 indicators
    if any(x in banner for x in ['+ok', 'pop3', 'user', 'pass', 'list', 'retr']):
        return "POP3"
    
    return "UNKNOWN"


def _get_protocol_confidence(stream: TcpStream, protocol: str) -> float:
    """Get confidence score for protocol identification."""
    if protocol == "UNKNOWN":
        return 0.0
    
    # High confidence if port matches known protocol ports
    if stream.server_port in [25, 587, 465, 143, 993, 110, 995]:
        return 1.0
    
    # Medium confidence if identified by banner
    if protocol != "UNKNOWN":
        return 0.7
    
    return 0.0
