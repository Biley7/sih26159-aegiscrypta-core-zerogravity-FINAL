from typing import List, Optional, Dict, Any
import numpy as np
from app.models import (
    AiRiskScore,
    CryptographicPosture,
    CheckResult,
    CheckStatus,
    FindingSeverity
)


def compute_ai_cryptographic_risk(
    checks: List[CheckResult],
    crypto_posture: Optional[CryptographicPosture] = None
) -> AiRiskScore:
    """
    Evaluates multi-dimensional cryptographic and protocol posture using an AI risk scoring model:
    - Extracts normalized feature vector across TLS, cipher strength, PFS, certificate hygiene, and DNS auth.
    - Applies weighted multi-factor risk inference.
    - Outputs calibrated 0-100 Risk Score, Risk Level (LOW, MEDIUM, HIGH, CRITICAL), and confidence.
    """
    risk_factors: List[str] = []
    mitigations: List[str] = []

    # Default baseline features (0.0 = safe, 1.0 = maximum risk)
    f_tls_obsolescence = 0.15      # Default assume TLS 1.2
    f_cipher_weakness = 0.10
    f_pfs_absence = 0.20
    f_cert_risk = 0.10
    f_key_weakness = 0.0
    f_sig_hash_weakness = 0.0
    f_protocol_exposure = 0.15
    f_dns_spoof_risk = 0.10

    observed_points = 0
    total_points = 8

    # 1. DNS Checks Analysis
    spf_check = next((c for c in checks if c.name == "SPF"), None)
    dmarc_check = next((c for c in checks if c.name == "DMARC"), None)

    if spf_check and dmarc_check:
        observed_points += 2
        if dmarc_check.status == CheckStatus.FAIL:
            f_dns_spoof_risk = 0.85
            risk_factors.append("No active DMARC policy; domain is vulnerable to spoofing and impersonation.")
            mitigations.append("Deploy DMARC policy with p=quarantine or p=reject.")
        elif dmarc_check.status == CheckStatus.WARN:
            f_dns_spoof_risk = 0.45
            risk_factors.append("DMARC is in non-enforcing monitoring mode (p=none).")
            mitigations.append("Strengthen DMARC policy to p=quarantine or p=reject.")
        else:
            f_dns_spoof_risk = 0.05

    # 2. Cryptographic Posture Analysis
    if crypto_posture and crypto_posture.protocols_audited:
        observed_points += 6
        audits = crypto_posture.protocols_audited

        # TLS Version
        if crypto_posture.deprecated_tls_found:
            f_tls_obsolescence = 0.90
            risk_factors.append("Deprecated TLS versions (SSLv3/TLS 1.0/TLS 1.1) permitted on mail servers.")
            mitigations.append("Disable deprecated TLS versions; enforce TLS 1.2 and TLS 1.3 exclusively.")
        elif any(a.tls_handshake and a.tls_handshake.negotiated_version == "TLSv1.3" for a in audits):
            f_tls_obsolescence = 0.02
        else:
            f_tls_obsolescence = 0.12

        # Ciphers & Forward Secrecy
        if crypto_posture.weak_ciphers_found:
            f_cipher_weakness = 0.85
            risk_factors.append("Weak or vulnerable cipher primitives (e.g. 3DES, RC4, or non-AEAD modes) identified.")
            mitigations.append("Decommission legacy ciphers and configure AEAD ciphers (AES-GCM / ChaCha20-Poly1305).")
        else:
            f_cipher_weakness = 0.05

        if not crypto_posture.forward_secrecy_supported:
            f_pfs_absence = 0.80
            risk_factors.append("Lack of Perfect Forward Secrecy (PFS); static RSA key transport in use.")
            mitigations.append("Mandate ephemeral Diffie-Hellman key exchange (ECDHE or TLS 1.3).")
        else:
            f_pfs_absence = 0.05

        # Certificate Hygiene
        cert_issues = False
        for a in audits:
            if a.tls_handshake and a.tls_handshake.certificate:
                cert = a.tls_handshake.certificate
                if cert.is_expired:
                    f_cert_risk = 1.0
                    cert_issues = True
                    risk_factors.append("Expired X.509 server certificate detected.")
                    mitigations.append("Immediately renew and replace the expired certificate.")
                elif cert.is_self_signed:
                    f_cert_risk = max(f_cert_risk, 0.75)
                    cert_issues = True
                    risk_factors.append("Self-signed server certificate detected.")
                    mitigations.append("Install a certificate issued by a recognized public Certificate Authority.")
                elif cert.days_until_expiry < 30:
                    f_cert_risk = max(f_cert_risk, 0.40)
                    cert_issues = True
                    risk_factors.append(f"Certificate expiring in {cert.days_until_expiry} days.")
                    mitigations.append("Schedule certificate renewal.")

                # Key length
                if cert.key_size_bits and cert.key_size_bits < 2048 and cert.public_key_algorithm.startswith("RSA"):
                    f_key_weakness = 0.85
                    risk_factors.append(f"Substandard RSA key length ({cert.key_size_bits}-bit).")
                    mitigations.append("Upgrade to at least 2048-bit RSA or 256-bit ECC.")

                # Signature algorithm
                if "sha1" in cert.signature_algorithm.lower() or "md5" in cert.signature_algorithm.lower():
                    f_sig_hash_weakness = 0.90
                    risk_factors.append(f"Deprecated signature hash digest ({cert.signature_algorithm}).")
                    mitigations.append("Reissue certificate with SHA-256 or SHA-384 digest.")

        if not cert_issues:
            f_cert_risk = 0.05

        # Protocol exposure (STARTTLS support)
        unsupported_starttls = [a for a in audits if a.starttls_advertised is False]
        if unsupported_starttls:
            f_protocol_exposure = 0.80
            risk_factors.append("STARTTLS not advertised or rejected on one or more mail endpoints.")
            mitigations.append("Enable and require STARTTLS encryption on all mail ports.")
        else:
            f_protocol_exposure = 0.10

    # Model Weights Vector
    weights = np.array([0.20, 0.18, 0.15, 0.15, 0.10, 0.08, 0.08, 0.06])
    features = np.array([
        f_tls_obsolescence,
        f_cipher_weakness,
        f_pfs_absence,
        f_cert_risk,
        f_key_weakness,
        f_sig_hash_weakness,
        f_protocol_exposure,
        f_dns_spoof_risk
    ])

    # Compute dot product
    raw_risk = float(np.dot(weights, features))
    risk_score = int(round(min(100.0, max(0.0, raw_risk * 100.0))))

    # Risk Level Categorization
    if risk_score >= 65:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    confidence = round(min(1.0, observed_points / total_points), 2)

    return AiRiskScore(
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        risk_factors=risk_factors,
        mitigation_priority=mitigations
    )
