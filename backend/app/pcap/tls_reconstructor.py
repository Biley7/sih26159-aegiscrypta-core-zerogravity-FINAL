import struct
from typing import Optional, Dict, Any, List, Tuple
from app.crypto.cert_analyzer import parse_x509_certificate
from app.crypto.cipher_evaluator import evaluate_cipher_and_tls
from app.models import CertificateInfo, CipherSuiteInfo, SecurityFinding, FindingSeverity


# Common IANA TLS Cipher Suite Hex Mappings
CIPHER_SUITE_MAP = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
    0x000A: "DES-CBC3-SHA",
    0x0005: "RC4-MD5",
    0x0004: "RC4-SHA",
    0x0000: "TLS_NULL_WITH_NULL_NULL",
}

TLS_VERSION_MAP = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


class PassiveTlsHandshake:
    def __init__(self):
        self.client_hello_seen = False
        self.server_hello_seen = False
        self.client_version = None
        self.server_version = None
        self.negotiated_version = None
        self.sni_hostname = None
        self.client_ciphers: List[str] = []
        self.selected_cipher: Optional[str] = None
        self.certificate_info: Optional[CertificateInfo] = None
        self.cipher_info: Optional[CipherSuiteInfo] = None
        self.findings: List[SecurityFinding] = []


def _extract_certificate_chain(hs_body: bytes) -> List[bytes]:
    """Extract DER certificates from TLS 1.2 or TLS 1.3 Certificate messages."""
    def parse_entries(offset: int, list_length: int, tls13: bool) -> List[bytes]:
        end = offset + list_length
        if end > len(hs_body):
            return []
        certificates = []
        while offset + 3 <= end:
            cert_length = int.from_bytes(hs_body[offset:offset + 3], "big")
            offset += 3
            if cert_length == 0 or offset + cert_length > end:
                return []
            certificates.append(hs_body[offset:offset + cert_length])
            offset += cert_length
            if tls13:
                if offset + 2 > end:
                    return []
                extensions_length = int.from_bytes(hs_body[offset:offset + 2], "big")
                offset += 2 + extensions_length
                if offset > end:
                    return []
        return certificates if offset == end else []

    if len(hs_body) >= 3:
        tls12_length = int.from_bytes(hs_body[:3], "big")
        tls12_certificates = parse_entries(3, tls12_length, tls13=False)
        if tls12_certificates:
            return tls12_certificates

    if hs_body:
        context_length = hs_body[0]
        list_length_offset = 1 + context_length
        if list_length_offset + 3 <= len(hs_body):
            list_length = int.from_bytes(hs_body[list_length_offset:list_length_offset + 3], "big")
            return parse_entries(list_length_offset + 3, list_length, tls13=True)
    return []


def parse_tls_records_from_stream(payload: bytes) -> PassiveTlsHandshake:
    """
    Passively extracts TLS Handshake records (ClientHello, ServerHello, Certificate)
    from a reconstructed bidirectional TCP stream.
    """
    handshake = PassiveTlsHandshake()
    offset = 0
    total_len = len(payload)

    while offset + 5 <= total_len:
        # Check for TLS Record header: ContentType (1 byte), Version (2 bytes), Length (2 bytes)
        content_type = payload[offset]
        rec_ver = struct.unpack("!H", payload[offset + 1:offset + 3])[0]
        rec_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
        offset += 5

        if offset + rec_len > total_len:
            break

        rec_data = payload[offset:offset + rec_len]
        offset += rec_len

        # Handshake record type
        if content_type == 22 and len(rec_data) >= 4:
            hs_offset = 0
            while hs_offset + 4 <= len(rec_data):
                hs_type = rec_data[hs_offset]
                hs_len = int.from_bytes(rec_data[hs_offset + 1:hs_offset + 4], "big")
                hs_offset += 4

                if hs_offset + hs_len > len(rec_data):
                    break

                hs_body = rec_data[hs_offset:hs_offset + hs_len]
                hs_offset += hs_len

                # 1. ClientHello
                if hs_type == 1 and len(hs_body) >= 34:
                    handshake.client_hello_seen = True
                    client_ver = struct.unpack("!H", hs_body[:2])[0]
                    handshake.client_version = TLS_VERSION_MAP.get(client_ver, f"0x{client_ver:04x}")

                    # Skip Random (32 bytes)
                    pos = 34
                    # Session ID
                    if pos < len(hs_body):
                        sess_id_len = hs_body[pos]
                        pos += 1 + sess_id_len

                    # Cipher Suites
                    if pos + 2 <= len(hs_body):
                        ciphers_len = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                        pos += 2
                        num_ciphers = ciphers_len // 2
                        for _ in range(num_ciphers):
                            if pos + 2 <= len(hs_body):
                                cid = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                                cname = CIPHER_SUITE_MAP.get(cid, f"CIPHER_0x{cid:04X}")
                                handshake.client_ciphers.append(cname)
                                pos += 2

                    # Compression methods
                    if pos < len(hs_body):
                        comp_len = hs_body[pos]
                        pos += 1 + comp_len

                    # Extensions
                    if pos + 2 <= len(hs_body):
                        ext_total_len = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                        pos += 2
                        ext_end = pos + ext_total_len
                        while pos + 4 <= ext_end and pos + 4 <= len(hs_body):
                            ext_type = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                            ext_len = struct.unpack("!H", hs_body[pos + 2:pos + 4])[0]
                            pos += 4
                            ext_data = hs_body[pos:pos + ext_len]
                            pos += ext_len

                            # SNI (type 0)
                            if ext_type == 0 and len(ext_data) >= 5:
                                try:
                                    sni_len = struct.unpack("!H", ext_data[3:5])[0]
                                    handshake.sni_hostname = ext_data[5:5 + sni_len].decode("utf-8", errors="replace")
                                except Exception:
                                    pass

                            # Supported Versions (type 43)
                            elif ext_type == 43 and len(ext_data) >= 1:
                                v_list_len = ext_data[0]
                                v_pos = 1
                                while v_pos + 2 <= 1 + v_list_len and v_pos + 2 <= len(ext_data):
                                    v_id = struct.unpack("!H", ext_data[v_pos:v_pos + 2])[0]
                                    if v_id == 0x0304:
                                        handshake.client_version = "TLSv1.3"
                                    v_pos += 2

                # 2. ServerHello
                elif hs_type == 2 and len(hs_body) >= 38:
                    handshake.server_hello_seen = True
                    server_ver = struct.unpack("!H", hs_body[:2])[0]
                    handshake.negotiated_version = TLS_VERSION_MAP.get(server_ver, f"0x{server_ver:04x}")

                    # Skip Random (32 bytes)
                    pos = 34
                    if pos < len(hs_body):
                        sess_id_len = hs_body[pos]
                        pos += 1 + sess_id_len

                    # Selected Cipher Suite (2 bytes)
                    if pos + 2 <= len(hs_body):
                        selected_cid = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                        handshake.selected_cipher = CIPHER_SUITE_MAP.get(selected_cid, f"CIPHER_0x{selected_cid:04X}")
                        pos += 2

                    # Compression (1 byte)
                    pos += 1

                    # Server Extensions (Check Supported Versions 43 for TLS 1.3)
                    if pos + 2 <= len(hs_body):
                        ext_total_len = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                        pos += 2
                        ext_end = pos + ext_total_len
                        while pos + 4 <= ext_end and pos + 4 <= len(hs_body):
                            ext_type = struct.unpack("!H", hs_body[pos:pos + 2])[0]
                            ext_len = struct.unpack("!H", hs_body[pos + 2:pos + 4])[0]
                            pos += 4
                            ext_data = hs_body[pos:pos + ext_len]
                            pos += ext_len

                            if ext_type == 43 and len(ext_data) >= 2:
                                s_ver = struct.unpack("!H", ext_data[:2])[0]
                                if s_ver == 0x0304:
                                    handshake.negotiated_version = "TLSv1.3"

                # 3. Certificate
                elif hs_type == 11 and len(hs_body) >= 3:
                    certificate_chain = _extract_certificate_chain(hs_body)
                    if certificate_chain:
                        try:
                            cert_info, c_findings = parse_x509_certificate(
                                certificate_chain[0],
                                target_domain=handshake.sni_hostname,
                                intermediate_certificates=certificate_chain[1:],
                            )
                            handshake.certificate_info = cert_info
                            handshake.findings.extend(c_findings)
                        except Exception as e:
                            handshake.findings.append(SecurityFinding(
                                title="X.509 Certificate Parsing Error in PCAP",
                                severity=FindingSeverity.MEDIUM,
                                category="Certificate",
                                description=f"Could not parse extracted certificate: {str(e)}",
                                recommendation="Verify that the certificate bytes in the TCP stream are uncorrupted."
                            ))

    # Evaluate cipher and negotiated version if ServerHello was identified
    if handshake.negotiated_version and handshake.selected_cipher:
        c_tuple = (handshake.selected_cipher, handshake.negotiated_version, 256 if "256" in handshake.selected_cipher else 128)
        cipher_info, cipher_findings = evaluate_cipher_and_tls(handshake.negotiated_version, c_tuple)
        handshake.cipher_info = cipher_info
        handshake.findings.extend(cipher_findings)

    return handshake
