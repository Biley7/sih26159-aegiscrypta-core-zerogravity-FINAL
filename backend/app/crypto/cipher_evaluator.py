from typing import Tuple, List, Optional
from app.models import CipherSuiteInfo, SecurityFinding, FindingSeverity


# Known weak or broken primitives
WEAK_CIPHER_PATTERNS = {
    "RC4": "RC4 stream cipher is broken and vulnerable to plaintext recovery attacks (RFC 7465).",
    "3DES": "Triple-DES (3DES) is vulnerable to 64-bit block collision attacks such as Sweet32 (CVE-2016-2183).",
    "DES": "Single DES has an obsolete 56-bit key space and can be broken in hours.",
    "EXPORT": "Export-grade cipher suites use deliberately weakened 40/512-bit keys vulnerable to FREAK/Logjam.",
    "NULL": "NULL cipher suites transmit data completely unencrypted over the network.",
    "MD5": "MD5 hash algorithm is cryptographically broken with collision attacks.",
    "ANON": "Anonymous Diffie-Hellman provides no authentication and is completely vulnerable to MitM attacks.",
}

DEPRECATED_TLS_VERSIONS = {
    "SSLv2": (FindingSeverity.CRITICAL, "SSL 2.0 is obsolete and completely broken (DROWN attack)."),
    "SSLv3": (FindingSeverity.CRITICAL, "SSL 3.0 is obsolete and vulnerable to POODLE (RFC 7568)."),
    "TLSv1": (FindingSeverity.CRITICAL, "TLS 1.0 is deprecated by RFC 8996; lacks modern cipher suites and vulnerable to BEAST."),
    "TLSv1.0": (FindingSeverity.CRITICAL, "TLS 1.0 is deprecated by RFC 8996; lacks modern cipher suites and vulnerable to BEAST."),
    "TLSv1.1": (FindingSeverity.HIGH, "TLS 1.1 is deprecated by RFC 8996; lacks modern authenticated encryption (AEAD)."),
}


def parse_key_exchange(cipher_name: str, tls_version: str) -> Tuple[str, bool]:
    """
    Determines key exchange mechanism and whether Forward Secrecy (PFS) is provided.
    TLS 1.3 ciphers inherently mandate ephemeral key exchange.
    """
    upper = cipher_name.upper()

    # TLS 1.3 standard cipher names: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, etc.
    if tls_version == "TLSv1.3" or upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20"):
        return "ECDHE/DHE (TLS 1.3)", True

    if "ECDHE" in upper:
        return "ECDHE", True
    elif "DHE" in upper or "EDH" in upper:
        return "DHE", True
    elif "RSA" in upper or upper.startswith("AES") or upper.startswith("DES"):
        return "Static RSA", False
    elif "ECDH" in upper:
        return "Static ECDH", False
    elif "PSK" in upper:
        return "PSK", False
    return "Unknown", False


def evaluate_cipher_and_tls(
    negotiated_version: Optional[str],
    cipher_tuple: Optional[Tuple[str, str, int]]
) -> Tuple[Optional[CipherSuiteInfo], List[SecurityFinding]]:
    """
    Audits the negotiated TLS version and active cipher suite.
    Generates prioritized security findings for deprecation, forward secrecy, and weak primitives.
    """
    findings: List[SecurityFinding] = []

    if not negotiated_version or not cipher_tuple:
        return None, findings

    cipher_name, proto_ver, bits = cipher_tuple
    norm_version = negotiated_version.strip()
    key_exchange, forward_secrecy = parse_key_exchange(cipher_name, norm_version)

    # 1. TLS Version Audit
    if norm_version in DEPRECATED_TLS_VERSIONS:
        sev, desc = DEPRECATED_TLS_VERSIONS[norm_version]
        findings.append(SecurityFinding(
            title=f"Deprecated TLS Version ({norm_version})",
            severity=sev,
            category="TLS",
            description=desc,
            recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the mail server; enforce TLS 1.2 and TLS 1.3 only."
        ))

    # 2. Forward Secrecy Audit
    if not forward_secrecy:
        findings.append(SecurityFinding(
            title="Lack of Perfect Forward Secrecy (PFS)",
            severity=FindingSeverity.HIGH,
            category="Cipher",
            description=f"Active cipher '{cipher_name}' uses {key_exchange} key transport without ephemeral key exchange. Past recorded traffic can be decrypted if the private key is compromised.",
            recommendation="Configure mail server ciphers to prioritize ECDHE suites (e.g. ECDHE-RSA-AES128-GCM-SHA256 or TLS 1.3)."
        ))

    # 3. Weak Cipher Primitive Audit
    is_weak = False
    weak_reasons: List[str] = []
    upper_name = cipher_name.upper()

    for weak_tag, explanation in WEAK_CIPHER_PATTERNS.items():
        if weak_tag in upper_name:
            is_weak = True
            weak_reasons.append(explanation)
            findings.append(SecurityFinding(
                title=f"Insecure Cipher Primitive ({weak_tag})",
                severity=FindingSeverity.CRITICAL if weak_tag in ["RC4", "NULL", "DES", "EXPORT"] else FindingSeverity.HIGH,
                category="Cipher",
                description=f"Cipher '{cipher_name}' incorporates {explanation}",
                recommendation=f"Disable cipher suites containing {weak_tag} in your mail transfer agent (MTA) configuration."
            ))

    # CBC Mode check in TLS 1.2
    if "CBC" in upper_name and norm_version in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]:
        weak_reasons.append("CBC-mode cipher suites may be vulnerable to padding oracle attacks without Encrypt-then-MAC.")
        findings.append(SecurityFinding(
            title="CBC Mode Cipher Suite in Use",
            severity=FindingSeverity.LOW,
            category="Cipher",
            description=f"Cipher '{cipher_name}' uses Cipher Block Chaining (CBC) mode.",
            recommendation="Prefer modern Authenticated Encryption with Associated Data (AEAD) ciphers such as AES-GCM or CHACHA20-POLY1305."
        ))

    # Bit length check
    if bits and bits < 128:
        is_weak = True
        msg = f"Insufficient key length: {bits}-bit encryption is below the modern 128-bit minimum standard."
        weak_reasons.append(msg)
        findings.append(SecurityFinding(
            title="Weak Encryption Key Length (< 128-bit)",
            severity=FindingSeverity.CRITICAL,
            category="Cipher",
            description=msg,
            recommendation="Ensure all enabled cipher suites provide at least 128-bit or 256-bit encryption strength."
        ))

    # Determine encryption algorithm label
    enc = "Unknown"
    if "CHACHA20" in upper_name:
        enc = "CHACHA20-POLY1305"
    elif "AES" in upper_name:
        if "GCM" in upper_name:
            enc = "AES-GCM"
        elif "CCM" in upper_name:
            enc = "AES-CCM"
        elif "CBC" in upper_name:
            enc = "AES-CBC"
        else:
            enc = "AES"
    elif "3DES" in upper_name:
        enc = "3DES-EDE"
    # 4. Post-Quantum Cryptography (PQC) & SNDL Evaluation
    pqc_hybrid = any(k in upper_name or k in key_exchange.upper() for k in ["KYBER", "ML-KEM", "MLKEM", "X25519KYBER", "DILITHIUM", "ML-DSA", "PQC"])
    sndl_vulnerable = not pqc_hybrid

    if sndl_vulnerable:
        findings.append(SecurityFinding(
            title="Vulnerable to Store-Now-Decrypt-Later (SNDL) Quantum Attacks",
            severity=FindingSeverity.MEDIUM,
            category="Post-Quantum",
            description=f"Cipher '{cipher_name}' ({key_exchange}) relies on classical asymmetric primitives. Adversaries intercepting email traffic today can record encrypted sessions to decrypt once Cryptanalytically Relevant Quantum Computers (CRQCs) arrive.",
            recommendation="Adopt hybrid post-quantum key exchange (e.g. X25519 + ML-KEM-768 per NIST FIPS 203) on inbound/outbound mail gateways."
        ))

    pqc_details = "NIST FIPS 203 ML-KEM-768 / Kyber Hybrid Active" if pqc_hybrid else "Classical Asymmetric (SNDL Harvest Risk)"

    cipher_info = CipherSuiteInfo(
        name=cipher_name,
        tls_version=norm_version,
        key_exchange=key_exchange,
        forward_secrecy=forward_secrecy,
        encryption=enc,
        bits=bits,
        is_weak=is_weak,
        weak_reasons=weak_reasons,
        pqc_hybrid=pqc_hybrid,
        sndl_vulnerable=sndl_vulnerable,
        pqc_details=pqc_details
    )

    return cipher_info, findings
