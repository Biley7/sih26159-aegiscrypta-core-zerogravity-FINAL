from datetime import datetime, timezone
from typing import Optional, List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import NameOID, ExtensionOID
import fnmatch
import hashlib

from app.models import CertificateInfo, SecurityFinding, FindingSeverity

_TRUST_STORE = None

def _get_trust_store():
    """Lazily loads default trusted root CAs from Python system trust store."""
    global _TRUST_STORE
    if _TRUST_STORE is None:
        try:
            import ssl
            from cryptography.x509.verification import Store
            ctx = ssl.create_default_context()
            ca_ders = ctx.get_ca_certs(binary_form=True)
            ca_certs = []
            for d in ca_ders:
                try:
                    ca_certs.append(x509.load_der_x509_certificate(d))
                except Exception:
                    pass
            _TRUST_STORE = Store(ca_certs)
        except Exception:
            _TRUST_STORE = None
    return _TRUST_STORE


def verify_certificate_chain(
    cert: x509.Certificate,
    target_domain: Optional[str] = None,
    intermediates: Optional[List[x509.Certificate]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validates X.509 certificate against trusted root CAs (RFC 5280).
    Returns (is_valid, error_reason).
    """
    store = _get_trust_store()
    if store is None:
        return False, "System trust store is unavailable; certificate chain could not be validated."

    try:
        from cryptography.x509.verification import DNSName, PolicyBuilder

        builder = PolicyBuilder().store(store)
        if target_domain and "." in target_domain:
            verifier = builder.build_server_verifier(DNSName(target_domain))
        else:
            verifier = builder.build_client_verifier()
        verifier.verify(cert, intermediates or [])
        return True, None
    except Exception as exc:
        return False, f"Untrusted or invalid certificate chain: {exc}"


def parse_x509_certificate(
    der_bytes: bytes,
    target_domain: Optional[str] = None,
    intermediate_certificates: Optional[List[bytes]] = None,
) -> Tuple[CertificateInfo, List[SecurityFinding]]:
    """
    Parses a binary DER-encoded X.509 certificate and performs deep cryptographic audit:
    - Validity dates and expiration status.
    - Public key algorithm and bit strength.
    - Digital signature algorithm and weak hash detection.
    - SAN list and domain matching.
    - Self-signed detection and full chain validation to trusted root.
    - Computes SHA-256 fingerprint formatted with colon hex.
    """
    cert = x509.load_der_x509_certificate(der_bytes)
    now = datetime.now(timezone.utc)
    sha256_fingerprint = ":".join(f"{b:02X}" for b in hashlib.sha256(der_bytes).digest())

    # Subject & Issuer Common Names
    def get_cn(name: x509.Name) -> Optional[str]:
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cns[0].value if cns else None

    subject_cn = get_cn(cert.subject)
    issuer_cn = get_cn(cert.issuer)
    subject_dn = cert.subject.rfc4514_string()
    issuer_dn = cert.issuer.rfc4514_string()
    serial_number = hex(cert.serial_number)

    # Validity
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    days_until_expiry = (not_after - now).days

    # Self-signed
    is_self_signed = (cert.subject == cert.issuer)

    # Public Key analysis
    public_key = cert.public_key()
    pub_algo = "Unknown"
    key_size = None

    if isinstance(public_key, rsa.RSAPublicKey):
        pub_algo = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        pub_algo = f"EC ({public_key.curve.name})"
        key_size = public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        pub_algo = "Ed25519"
        key_size = 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        pub_algo = "Ed448"
        key_size = 448
    elif isinstance(public_key, dsa.DSAPublicKey):
        pub_algo = "DSA"
        key_size = public_key.key_size

    # Signature Algorithm
    sig_algo = cert.signature_algorithm_oid._name
    hash_algo_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    # Subject Alternative Names (SANs)
    san_list: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = san_ext.value
        san_list = [str(name.value) for name in san_val]
    except x509.ExtensionNotFound:
        pass

    # Domain match check
    matches_domain = None
    if target_domain:
        td = target_domain.lower()
        candidates = [s.lower() for s in san_list]
        if subject_cn:
            candidates.append(subject_cn.lower())

        matches_domain = any(
            candidate == td or (candidate.startswith("*.") and fnmatch.fnmatch(td, candidate))
            for candidate in candidates
        )

    warnings: List[str] = []
    findings: List[SecurityFinding] = []

    # 1. Expiration check
    if is_expired:
        msg = f"Certificate expired on {not_after.strftime('%Y-%m-%d')} ({abs(days_until_expiry)} days ago)."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Expired X.509 Certificate",
            severity=FindingSeverity.CRITICAL,
            category="Certificate",
            description=msg,
            recommendation="Renew and install a valid X.509 certificate immediately to prevent TLS verification failures."
        ))
    elif days_until_expiry < 30:
        msg = f"Certificate is expiring soon: {days_until_expiry} days remaining."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Certificate Expiring Soon",
            severity=FindingSeverity.MEDIUM,
            category="Certificate",
            description=msg,
            recommendation="Schedule certificate renewal before expiration to ensure uninterrupted secure communication."
        ))

    if is_not_yet_valid:
        msg = f"Certificate is not yet valid (valid from {not_before.strftime('%Y-%m-%d')})."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Certificate Not Yet Valid",
            severity=FindingSeverity.HIGH,
            category="Certificate",
            description=msg,
            recommendation="Ensure server clocks are synchronized via NTP and valid certificate dates are configured."
        ))

    # 2. Self-signed check
    if is_self_signed:
        msg = f"Certificate is self-signed (Issuer: '{issuer_cn or issuer_dn}')."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Self-Signed Certificate in Use",
            severity=FindingSeverity.HIGH,
            category="Certificate",
            description=msg,
            recommendation="Replace self-signed certificate with one issued by a publicly trusted Certificate Authority (CA) e.g., Let's Encrypt."
        ))

    # 3. Weak Public Key
    if pub_algo.startswith("RSA") and key_size and key_size < 2048:
        msg = f"Weak RSA key length detected: {key_size}-bit (minimum recommended is 2048-bit)."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Weak RSA Key Length (< 2048-bit)",
            severity=FindingSeverity.CRITICAL,
            category="Certificate",
            description=msg,
            recommendation="Regenerate certificate with an RSA key of at least 2048 bits or use ECDSA (P-256 / P-384)."
        ))
    elif pub_algo.startswith("EC") and key_size and key_size < 256:
        msg = f"Weak Elliptic Curve key size: {key_size}-bit."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Weak EC Key Size (< 256-bit)",
            severity=FindingSeverity.HIGH,
            category="Certificate",
            description=msg,
            recommendation="Upgrade to at least secp256r1 (P-256) or secp384r1 (P-384)."
        ))

    # 4. Weak Signature Algorithm (SHA-1 / MD5)
    if "sha1" in hash_algo_name.lower() or "md5" in hash_algo_name.lower() or "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        msg = f"Insecure signature digest algorithm detected: '{sig_algo}' using {hash_algo_name.upper()}."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Deprecated Digital Signature Algorithm (SHA-1 / MD5)",
            severity=FindingSeverity.CRITICAL,
            category="Certificate",
            description=msg,
            recommendation="Reissue the certificate using SHA-256 or stronger digest (e.g. SHA-384 / SHA-512)."
        ))

    # 5. Domain Mismatch
    if matches_domain is False:
        msg = f"Certificate Subject / SANs do not match target domain '{target_domain}'."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Certificate Domain Name Mismatch",
            severity=FindingSeverity.MEDIUM,
            category="Certificate",
            description=msg,
            recommendation=f"Ensure the certificate SAN list contains '{target_domain}' or its enclosing wildcard domain."
        ))

    # 6. Full Chain Validation to Trusted Root CA (Task 2.4)
    intermediates = []
    for intermediate_der in intermediate_certificates or []:
        try:
            intermediates.append(x509.load_der_x509_certificate(intermediate_der))
        except Exception:
            continue
    chain_valid, chain_error = verify_certificate_chain(cert, target_domain, intermediates)
    if not chain_valid:
        msg = chain_error or "Certificate chain validation failed to trusted root CA."
        warnings.append(msg)
        findings.append(SecurityFinding(
            title="Untrusted Certificate Chain",
            severity=FindingSeverity.CRITICAL if is_self_signed else FindingSeverity.HIGH,
            category="Certificate",
            description=msg,
            recommendation="Deploy a valid certificate issued by an accredited public CA with all required intermediate certificates configured in the bundle."
        ))

    cert_info = CertificateInfo(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        subject_dn=subject_dn,
        issuer_dn=issuer_dn,
        serial_number=serial_number,
        valid_from=not_before.isoformat(),
        valid_to=not_after.isoformat(),
        days_until_expiry=days_until_expiry,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
        public_key_algorithm=pub_algo,
        key_size_bits=key_size,
        signature_algorithm=sig_algo,
        sha256_fingerprint=sha256_fingerprint,
        san_list=san_list,
        matches_domain=matches_domain,
        warnings=warnings,
        chain_valid=chain_valid,
        chain_error=chain_error
    )

    return cert_info, findings
