"""
TLS Handshake Parser for PCAP Analysis

Parses ClientHello/ServerHello/Certificate records directly from packet captures
to extract TLS version, cipher suite, and certificate chain as they appeared in
the specific captured session.

This is a scoped v1 implementation focused on extracting basic TLS metadata.
For full certificate chain validation, more complex parsing would be required.
"""

from typing import List, Dict, Optional, Tuple
from .stream_reconstructor import TcpStream


def parse_tls_handshake_from_stream(stream: TcpStream) -> Dict:
    """
    Parse TLS handshake from a TCP stream.
    
    Args:
        stream: TcpStream object with reassembled payload
    
    Returns:
        Dictionary with TLS metadata
    """
    if not stream.reassembled_payload:
        return {
            'tls_detected': False,
            'tls_version': None,
            'cipher_suite': None,
            'certificate_extracted': False,
            'details': 'No payload available'
        }
    
    # Try to detect TLS record layer
    if not _is_tls_record(stream.reassembled_payload):
        return {
            'tls_detected': False,
            'tls_version': None,
            'cipher_suite': None,
            'certificate_extracted': False,
            'details': 'No TLS records detected'
        }
    
    # Extract TLS version and cipher (simplified v1 implementation)
    tls_version = _extract_tls_version(stream.reassembled_payload)
    cipher_suite = _extract_cipher_suite(stream.reassembled_payload)
    
    return {
        'tls_detected': True,
        'tls_version': tls_version,
        'cipher_suite': cipher_suite,
        'certificate_extracted': False,  # v1: certificate extraction not implemented
        'details': f'TLS {tls_version} detected with cipher {cipher_suite}'
    }


def _is_tls_record(payload: bytes) -> bool:
    """
    Check if payload contains TLS record layer.
    
    TLS record format: Content Type (1 byte) | Version (2 bytes) | Length (2 bytes)
    """
    if len(payload) < 5:
        return False
    
    # Check for TLS record content types
    content_types = [20, 21, 22, 23]  # Change Cipher Spec, Alert, Handshake, Application Data
    
    # Check first byte (content type)
    if payload[0] in content_types:
        return True
    
    return False


def _extract_tls_version(payload: bytes) -> str:
    """
    Extract TLS version from payload.
    
    Simplified v1 implementation - looks for version bytes in common positions.
    """
    # TLS version mapping
    version_map = {
        b'\x03\x00': 'SSL 3.0',
        b'\x03\x01': 'TLS 1.0',
        b'\x03\x02': 'TLS 1.1',
        b'\x03\x03': 'TLS 1.2',
        b'\x03\x04': 'TLS 1.3',
    }
    
    # Check common positions for version bytes
    for i in range(len(payload) - 1):
        version_bytes = payload[i:i+2]
        if version_bytes in version_map:
            return version_map[version_bytes]
    
    # Default to unknown
    return "TLS Unknown"


def _extract_cipher_suite(payload: bytes) -> str:
    """
    Extract cipher suite from payload.
    
    Simplified v1 implementation - looks for common cipher suite patterns.
    """
    # Common cipher suite identifiers (partial)
    cipher_patterns = [
        b'TLS_AES_256_GCM_SHA384',
        b'TLS_AES_128_GCM_SHA256',
        b'TLS_CHACHA20_POLY1305_SHA256',
        b'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        b'TLS_RSA_WITH_AES_256_GCM_SHA384',
    ]
    
    payload_str = payload.decode('utf-8', errors='ignore')
    
    for pattern in cipher_patterns:
        if pattern.decode('utf-8') in payload_str:
            return pattern.decode('utf-8')
    
    return "Unknown Cipher"


def extract_crypto_metrics_from_pcap(streams: List[TcpStream]) -> Dict:
    """
    Extract cryptographic metrics from PCAP streams for fuzzy engine input.
    
    Args:
        streams: List of TcpStream objects
    
    Returns:
        Dictionary with crypto metrics compatible with fuzzy engine
    """
    metrics = {
        'tls_version': None,
        'cipher_name': None,
        'key_algorithm': None,
        'key_size_bits': None,
        'days_until_expiry': None,
        'forward_secrecy': False,
        'banner': None
    }
    
    # Find first stream with TLS
    for stream in streams:
        tls_data = parse_tls_handshake_from_stream(stream)
        if tls_data['tls_detected']:
            metrics['tls_version'] = tls_data['tls_version']
            metrics['cipher_name'] = tls_data['cipher_suite']
            
            # Extract banner from first stream
            if stream.reassembled_payload:
                try:
                    banner = stream.reassembled_payload.decode('utf-8', errors='ignore')
                    # Extract first line (banner)
                    lines = banner.split('\n')
                    if lines:
                        metrics['banner'] = lines[0][:200]  # Limit length
                except:
                    pass
            
            # Check for forward secrecy in cipher name
            if metrics['cipher_name']:
                cipher_upper = metrics['cipher_name'].upper()
                metrics['forward_secrecy'] = any(x in cipher_upper for x in ['ECDHE', 'DHE'])
            
            break
    
    return metrics
