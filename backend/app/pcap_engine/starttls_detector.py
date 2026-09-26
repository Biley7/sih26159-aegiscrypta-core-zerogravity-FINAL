"""
STARTTLS Negotiation Detector for PCAP Analysis

Detects STARTTLS command and subsequent switch from plaintext to TLS record types.
Flags sessions where:
- STARTTLS was offered but not used
- Sensitive commands appear before TLS upgrade
- STARTTLS response pattern looks stripped/interfered with
"""

from typing import List, Dict, Optional
from .stream_reconstructor import TcpStream


def detect_starttls_negotiation(streams: List[TcpStream]) -> List[dict]:
    """
    Detect STARTTLS negotiation in TCP streams.
    
    Args:
        streams: List of TcpStream objects
    
    Returns:
        List of STARTTLS detection results
    """
    results = []
    
    for stream in streams:
        detection = _detect_starttls_in_stream(stream)
        results.append({
            'stream_id': stream.stream_id,
            **detection
        })
    
    return results


def _detect_starttls_in_stream(stream: TcpStream) -> Dict:
    """Detect STARTTLS in a single stream."""
    if not stream.reassembled_payload:
        return {
            'starttls_detected': False,
            'starttls_offered': False,
            'starttls_used': False,
            'stripped': False,
            'sensitive_before_tls': False,
            'details': 'No payload available'
        }
    
    try:
        payload_str = stream.reassembled_payload.decode('utf-8', errors='ignore')
    except:
        return {
            'starttls_detected': False,
            'starttls_offered': False,
            'starttls_used': False,
            'stripped': False,
            'sensitive_before_tls': False,
            'details': 'Payload decode failed'
        }
    
    payload_lower = payload_str.lower()
    
    # Check for STARTTLS offer
    starttls_offered = 'starttls' in payload_lower
    
    # Check for STARTTLS usage (response pattern)
    starttls_used = '220 ready to start tls' in payload_lower or \
                   '235 tls' in payload_lower or \
                   'begin tls negotiation' in payload_lower
    
    # Check for potential stripping (incomplete response pattern)
    stripped = False
    if starttls_offered and not starttls_used:
        # Check if the response looks truncated or malformed
        if 'starttls' in payload_lower and '220' not in payload_lower:
            stripped = True
    
    # Check for sensitive commands before TLS upgrade
    sensitive_before_tls = False
    if starttls_offered:
        # Find STARTTLS position
        starttls_pos = payload_lower.find('starttls')
        
        # Check for sensitive commands before STARTTLS
        sensitive_commands = ['auth', 'login', 'pass', 'authenticate']
        for cmd in sensitive_commands:
            if cmd in payload_lower[:starttls_pos]:
                sensitive_before_tls = True
                break
    
    return {
        'starttls_detected': starttls_used,
        'starttls_offered': starttls_offered,
        'starttls_used': starttls_used,
        'stripped': stripped,
        'sensitive_before_tls': sensitive_before_tls,
        'details': f'STARTTLS {"offered" if starttls_offered else "not offered"}, {"used" if starttls_used else "not used"}'
    }
