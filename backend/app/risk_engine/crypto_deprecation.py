"""
Crypto Deprecation Index (CDI) - Tier 1 Fuzzy Inference System

Computes a 0-100 score representing cryptographic deprecation risk based on:
- TLS version (Old/Moderate/Strong)
- Cipher strength (Weak/Moderate/Strong) derived from Mozilla TLS guidelines
- Key length (Weak/Moderate/Strong) based on NIST SP 800-57
- Certificate health / validity window (Weak/Moderate/Strong) based on NIST SP 800-52r2

Uses Mamdani fuzzy inference with trapezoidal membership functions for plateau labels
(Old/Weak, Strong) and triangular for transitional labels (Moderate).

Reference Standards:
- Mozilla Server Side TLS v5.7: https://wiki.mozilla.org/Security/Server_Side_TLS
- NIST SP 800-52r2: Guidelines for the Selection, Configuration, and Use of TLS Implementations
- NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management
- RFC 8996: Deprecating TLS 1.0 and TLS 1.1
- CA/Browser Forum Baseline Requirements for Subject Public Key Info & Validity
"""

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from typing import Dict, List, Tuple, Optional

# Mozilla TLS Guidelines (v5.7) - Recommended Cipher Suite Classification
# Source: https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_ciphersuite
MOZILLA_CIPHER_STRENGTH = {
    # Modern ciphers (Strong - TLS 1.3 and AEAD ciphers)
    'TLS_AES_128_GCM_SHA256': 'strong',
    'TLS_AES_256_GCM_SHA384': 'strong',
    'TLS_CHACHA20_POLY1305_SHA256': 'strong',
    'TLS_AES_128_CCM_SHA256': 'strong',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 'strong',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 'strong',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': 'strong',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 'strong',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256': 'strong',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256': 'strong',
    
    # Intermediate ciphers (Moderate - CBC mode with HMAC, acceptable legacy)
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA': 'moderate',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA': 'moderate',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256': 'moderate',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384': 'moderate',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256': 'moderate',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384': 'moderate',
    'TLS_RSA_WITH_AES_128_GCM_SHA256': 'moderate',
    'TLS_RSA_WITH_AES_256_GCM_SHA384': 'moderate',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256': 'moderate',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384': 'moderate',
    
    # Deprecated / Broken ciphers (Weak - 3DES, RC4, DES, EXPORT, NULL)
    'TLS_RSA_WITH_AES_128_CBC_SHA': 'weak',
    'TLS_RSA_WITH_AES_256_CBC_SHA': 'weak',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA': 'weak',
    'TLS_RSA_WITH_RC4_128_SHA': 'weak',
    'TLS_RSA_WITH_RC4_128_MD5': 'weak',
    'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA': 'weak',
    'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA': 'weak',
    'TLS_RSA_WITH_DES_CBC_SHA': 'weak',
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5': 'weak',
    'TLS_RSA_WITH_NULL_SHA256': 'weak',
}

# Key length thresholds based on NIST recommendations
# Source: NIST SP 800-57 Part 1 Rev. 5, Table 2 (Security Strength)
KEY_LENGTH_THRESHOLDS = {
    'weak_max': 1024,      # Below 2048 is weak for modern use; <=1024 is severely broken
    'moderate_min': 2048,  # 2048-bit RSA provides 112 bits of security (acceptable through 2030)
    'strong_min': 3072     # 3072-bit RSA / 256-bit ECC provides 128+ bits of security (strong)
}


def classify_cipher_strength(cipher_name: str) -> str:
    """
    Classify cipher suite strength based on Mozilla TLS guidelines v5.7.
    """
    if not cipher_name:
        return 'weak'
    
    cipher_upper = cipher_name.upper().strip()
    
    if cipher_upper in MOZILLA_CIPHER_STRENGTH:
        return MOZILLA_CIPHER_STRENGTH[cipher_upper]
    
    # Heuristic classification for unlisted cipher suites
    if any(x in cipher_upper for x in ['AES_256_GCM', 'AES_128_GCM', 'CHACHA20', 'POLY1305']):
        return 'strong'
    elif any(x in cipher_upper for x in ['AES_256_CBC', 'AES_128_CBC', 'GCM']):
        return 'moderate'
    elif any(x in cipher_upper for x in ['3DES', 'RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'CBC']):
        return 'weak'
    
    return 'moderate'


def classify_key_length(algorithm: str, key_size_bits: Optional[int]) -> str:
    """
    Classify key length strength based on NIST SP 800-57 Part 1 Rev. 5 recommendations.
    """
    if key_size_bits is None:
        return 'weak'
    
    algo_upper = algorithm.upper() if algorithm else ''
    # ECC algorithms: NIST SP 800-57 specifies >=256 bits provides >=128-bit security
    if any(x in algo_upper for x in ['EC', 'ECDSA', 'ED25519', 'X25519', 'SECP256', 'PRIME256']):
        if key_size_bits >= 256:
            return 'strong'
        elif key_size_bits >= 224:
            return 'moderate'
        else:
            return 'weak'
    
    # RSA / DSA / Diffie-Hellman: >=3072 is strong, 2048 is moderate, <2048 is weak
    if key_size_bits >= KEY_LENGTH_THRESHOLDS['strong_min']:
        return 'strong'
    elif key_size_bits >= KEY_LENGTH_THRESHOLDS['moderate_min']:
        return 'moderate'
    else:
        return 'weak'


def classify_tls_version(tls_version: str) -> str:
    """
    Classify TLS version strength based on RFC 8996 and NIST SP 800-52r2.
    """
    if not tls_version:
        return 'old'
    
    tls_upper = tls_version.upper().strip()
    
    # TLS 1.3 is the modern recommended standard (RFC 8446)
    if '1.3' in tls_upper or 'TLSV1.3' in tls_upper:
        return 'strong'
    
    # TLS 1.2 is acceptable per NIST SP 800-52r2 when properly configured
    if '1.2' in tls_upper or 'TLSV1.2' in tls_upper:
        return 'moderate'
    
    # TLS 1.0, 1.1, SSLv2, SSLv3 are formally deprecated by RFC 8996
    return 'old'


def build_cdi_control_system():
    """
    Construct and compile the Mamdani control system for Crypto Deprecation Index (CDI).
    Uses trapezoidal membership for plateau sets and triangular for transitions.
    """
    # Universes of discourse
    x_tls = np.arange(0, 2.05, 0.05)          # 0=old, 1=moderate, 2=strong
    x_cipher = np.arange(0, 2.05, 0.05)       # 0=weak, 1=moderate, 2=strong
    x_key = np.arange(0, 2.05, 0.05)          # 0=weak, 1=moderate, 2=strong
    x_cert = np.arange(0, 366, 1)             # 0 to 365 days until expiry
    x_fs = np.arange(0, 2, 0.1)              # 0=no forward secrecy, 1=forward secrecy
    x_cdi = np.arange(0, 101, 0.5)            # 0-100 CDI score (0=low deprecation, 100=high)

    # Antecedent definitions
    tls_input = ctrl.Antecedent(x_tls, 'tls_version')
    cipher_input = ctrl.Antecedent(x_cipher, 'cipher_strength')
    key_input = ctrl.Antecedent(x_key, 'key_length')
    cert_input = ctrl.Antecedent(x_cert, 'cert_validity')
    fs_input = ctrl.Antecedent(x_fs, 'forward_secrecy')
    cdi_output = ctrl.Consequent(x_cdi, 'cdi')

    # Membership functions: Trapezoidal for plateaus, Triangular for transition
    # TLS Version: [0=old, 1=moderate, 2=strong]
    tls_input['old'] = fuzz.trapmf(x_tls, [0, 0, 0.4, 0.9])
    tls_input['moderate'] = fuzz.trimf(x_tls, [0.5, 1.0, 1.5])
    tls_input['strong'] = fuzz.trapmf(x_tls, [1.1, 1.6, 2.0, 2.0])

    # Cipher Strength: [0=weak, 1=moderate, 2=strong]
    cipher_input['weak'] = fuzz.trapmf(x_cipher, [0, 0, 0.4, 0.9])
    cipher_input['moderate'] = fuzz.trimf(x_cipher, [0.5, 1.0, 1.5])
    cipher_input['strong'] = fuzz.trapmf(x_cipher, [1.1, 1.6, 2.0, 2.0])

    # Key Length: [0=weak, 1=moderate, 2=strong]
    key_input['weak'] = fuzz.trapmf(x_key, [0, 0, 0.4, 0.9])
    key_input['moderate'] = fuzz.trimf(x_key, [0.5, 1.0, 1.5])
    key_input['strong'] = fuzz.trapmf(x_key, [1.1, 1.6, 2.0, 2.0])

    # Certificate Health: [days until expiry]
    # Source: CA/Browser Forum Baseline Requirements and NIST SP 800-52r2
    # Smooth continuous overlap between categories:
    # <= 15 days: weak/imminent expiry
    # 20 - 90 days: moderate renewal window (peak at 55 days)
    # >= 60 days: strong/fresh validity (plateau >= 90 days)
    cert_input['weak'] = fuzz.trapmf(x_cert, [0, 0, 15, 40])
    cert_input['moderate'] = fuzz.trimf(x_cert, [20, 55, 90])
    cert_input['strong'] = fuzz.trapmf(x_cert, [60, 90, 365, 365])

    # Forward Secrecy: [0=no forward secrecy, 1=forward secrecy]
    # Near-boolean step function (similar to SPF/DKIM pattern)
    fs_input['no'] = fuzz.trapmf(x_fs, [0, 0, 0.2, 0.5])
    fs_input['yes'] = fuzz.trapmf(x_fs, [0.5, 0.8, 1, 1])

    # CDI Output sets
    cdi_output['low'] = fuzz.trapmf(x_cdi, [0, 0, 15, 35])
    cdi_output['moderate'] = fuzz.trimf(x_cdi, [25, 50, 75])
    cdi_output['high'] = fuzz.trapmf(x_cdi, [65, 80, 100, 100])

    # Rules
    rules = [
        # All strong -> low deprecation
        ctrl.Rule(tls_input['strong'] & cipher_input['strong'] & key_input['strong'] & cert_input['strong'] & fs_input['yes'], cdi_output['low']),
        ctrl.Rule(tls_input['strong'] & cipher_input['moderate'] & key_input['strong'] & cert_input['strong'] & fs_input['yes'], cdi_output['low']),
        ctrl.Rule(tls_input['moderate'] & cipher_input['strong'] & key_input['strong'] & cert_input['strong'] & fs_input['yes'], cdi_output['low']),
        ctrl.Rule(tls_input['strong'] & cipher_input['strong'] & key_input['moderate'] & cert_input['strong'] & fs_input['yes'], cdi_output['low']),
        ctrl.Rule(tls_input['strong'] & cipher_input['strong'] & key_input['moderate'] & cert_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(tls_input['strong'] & cipher_input['moderate'] & key_input['moderate'] & cert_input['strong'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(tls_input['moderate'] & cipher_input['strong'] & key_input['moderate'] & cert_input['strong'] & fs_input['yes'], cdi_output['moderate']),

        # Moderate transitional states
        ctrl.Rule(tls_input['strong'] & cipher_input['strong'] & key_input['strong'] & cert_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(tls_input['moderate'] & cipher_input['moderate'] & key_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(key_input['moderate'] & cert_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(key_input['moderate'] & cipher_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(key_input['moderate'] & tls_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(cert_input['moderate'] & cipher_input['moderate'] & fs_input['yes'], cdi_output['moderate']),
        ctrl.Rule(tls_input['moderate'] & cert_input['moderate'] & fs_input['yes'], cdi_output['moderate']),

        # Critical deprecation triggers (unconditional — any single severe flaw)
        ctrl.Rule(tls_input['old'], cdi_output['high']),
        ctrl.Rule(cipher_input['weak'], cdi_output['high']),
        ctrl.Rule(key_input['weak'], cdi_output['high']),
        ctrl.Rule(cert_input['weak'], cdi_output['high']),

        # DEF-05 fix: Transitional rule for strong posture lacking Forward Secrecy.
        # -----------------------------------------------------------------------
        # Rationale (NIST SP 800-52r2 §3.3.1 / RFC 8446 §9.2):
        #   A TLS 1.2 deployment with a strong cipher (AES-256-GCM), a 3072-bit RSA
        #   key, and a valid certificate is *acceptable* per NIST SP 800-52r2 in
        #   transitional environments — it should NOT immediately escalate to CDI high
        #   simply because ECDHE key exchange was not negotiated.  The penalty for
        #   absent Forward Secrecy must still be quantifiable (CDI moderate rather
        #   than low), but must not trigger the Tier 2 non-dilution CRITICAL path
        #   when all other cryptographic properties are sound.
        #
        #   The standalone `fs_input['no'] → CDI high` rule below is retained for
        #   cases where *other* factors are weak/moderate (cipher_weak, key_weak,
        #   tls_old), ensuring that the absence of PFS in a degraded configuration
        #   still escalates to CDI high.  Mamdani centroid defuzzification combines
        #   both activated output sets, so the final CDI score for a truly excellent
        #   configuration that only lacks FS will settle near the moderate centroid
        #   rather than the high plateau.
        #
        #   IMPORTANT: Real-world no-FS ciphers (static RSA key exchange) land in
        #   'moderate' cipher strength in the MOZILLA_CIPHER_STRENGTH table because
        #   they lack the ECDHE prefix (e.g. TLS_RSA_WITH_AES_256_GCM_SHA384 →
        #   moderate).  The transitional rules therefore cover BOTH cipher_strong
        #   (ECDHE-based AEAD) AND cipher_moderate (static RSA AEAD) to ensure the
        #   rule actually fires for the target use-case.
        # v1: cipher strong + key strong + TLS strong/moderate + cert strong + no FS
        ctrl.Rule(
            tls_input['strong'] & cipher_input['strong'] & key_input['strong'] &
            cert_input['strong'] & fs_input['no'],
            cdi_output['moderate']
        ),
        ctrl.Rule(
            tls_input['moderate'] & cipher_input['strong'] & key_input['strong'] &
            cert_input['strong'] & fs_input['no'],
            cdi_output['moderate']
        ),
        # v2: cipher moderate (static RSA AEAD) + key strong + TLS strong/moderate + cert strong + no FS
        # This is the realistic production case: TLS 1.2 server using AES-256-GCM without
        # ECDHE key exchange but with a 3072+ bit RSA key and a fresh valid certificate.
        ctrl.Rule(
            tls_input['strong'] & cipher_input['moderate'] & key_input['strong'] &
            cert_input['strong'] & fs_input['no'],
            cdi_output['moderate']
        ),
        ctrl.Rule(
            tls_input['moderate'] & cipher_input['moderate'] & key_input['strong'] &
            cert_input['strong'] & fs_input['no'],
            cdi_output['moderate']
        ),

        # Missing Forward Secrecy is high risk when another major factor is
        # degraded; strong-key, valid-certificate TLS 1.2/1.3 cases are handled
        # by the transitional rules above instead of overlapping this rule.
        ctrl.Rule(
            fs_input['no'] & (
                tls_input['old'] | cipher_input['weak'] | key_input['weak'] |
                cert_input['weak'] | key_input['moderate'] | cert_input['moderate']
            ),
            cdi_output['high']
        ),

        # Compounded weaknesses
        ctrl.Rule(tls_input['old'] & cipher_input['weak'], cdi_output['high']),
        ctrl.Rule(cipher_input['weak'] & key_input['weak'], cdi_output['high']),
    ]

    system = ctrl.ControlSystem(rules)
    return system, (x_tls, tls_input), (x_cipher, cipher_input), (x_key, key_input), (x_cert, cert_input), (x_fs, fs_input), (x_cdi, cdi_output)


# Cache compiled control system
_CDI_SYSTEM, _TLS_DATA, _CIPHER_DATA, _KEY_DATA, _CERT_DATA, _FS_DATA, _CDI_DATA = build_cdi_control_system()


def compute_crypto_deprecation_index(
    tls_version: str,
    cipher_name: str,
    key_algorithm: str,
    key_size_bits: Optional[int],
    days_until_expiry: Optional[int] = None,
    forward_secrecy: Optional[bool] = None
) -> Tuple[float, List[Dict]]:
    """
    Compute Crypto Deprecation Index (CDI) using Mamdani fuzzy inference.
    
    Args:
        tls_version: Negotiated TLS version (e.g., "TLS 1.3")
        cipher_name: Cipher suite name (e.g., "TLS_AES_256_GCM_SHA384")
        key_algorithm: Public key algorithm (e.g., "RSA", "EC (secp256r1)")
        key_size_bits: Public key size in bits (e.g., 256 for EC, 2048 for RSA)
        days_until_expiry: Days remaining on certificate validity (None or <=0 treated as expired)
        forward_secrecy: Whether forward secrecy is provided (ECDHE/DHE key exchange)
    
    Returns:
        Tuple of (composite_score: float [0-100], contributing_factors: list[dict])
    """
    contributing_factors = []

    # If forward secrecy not explicitly supplied, infer from TLS version and cipher suite
    if forward_secrecy is None:
        cipher_upper = (cipher_name or "").upper()
        tls_upper = (tls_version or "").upper()
        if "1.3" in tls_upper:
            forward_secrecy = True
        elif any(kex in cipher_upper for kex in ["ECDHE", "DHE", "ED25519", "X25519"]):
            forward_secrecy = True
        else:
            forward_secrecy = False
    
    # Qualitative classification
    tls_class = classify_tls_version(tls_version)
    cipher_class = classify_cipher_strength(cipher_name)
    key_class = classify_key_length(key_algorithm, key_size_bits)
    
    # Numeric mapping for antecedents
    tls_numeric = {'old': 0.0, 'moderate': 1.0, 'strong': 2.0}[tls_class]
    cipher_numeric = {'weak': 0.0, 'moderate': 1.0, 'strong': 2.0}[cipher_class]
    key_numeric = {'weak': 0.0, 'moderate': 1.0, 'strong': 2.0}[key_class]
    
    # Effective cert validity days clamped to [0, 365]
    if days_until_expiry is None or days_until_expiry <= 0:
        cert_days = 0.0
    else:
        cert_days = float(min(365, max(0, days_until_expiry)))

    # Compute Antecedent membership degrees manually for explainability
    x_tls, tls_in = _TLS_DATA
    x_cipher, cipher_in = _CIPHER_DATA
    x_key, key_in = _KEY_DATA
    x_cert, cert_in = _CERT_DATA
    x_fs, fs_in = _FS_DATA

    tls_membership = {
        'old': float(fuzz.interp_membership(x_tls, tls_in['old'].mf, tls_numeric)),
        'moderate': float(fuzz.interp_membership(x_tls, tls_in['moderate'].mf, tls_numeric)),
        'strong': float(fuzz.interp_membership(x_tls, tls_in['strong'].mf, tls_numeric))
    }
    cipher_membership = {
        'weak': float(fuzz.interp_membership(x_cipher, cipher_in['weak'].mf, cipher_numeric)),
        'moderate': float(fuzz.interp_membership(x_cipher, cipher_in['moderate'].mf, cipher_numeric)),
        'strong': float(fuzz.interp_membership(x_cipher, cipher_in['strong'].mf, cipher_numeric))
    }
    fs_membership = {
        'no': float(fuzz.interp_membership(x_fs, fs_in['no'].mf, 0.0 if not forward_secrecy else 1.0)),
        'yes': float(fuzz.interp_membership(x_fs, fs_in['yes'].mf, 1.0 if forward_secrecy else 0.0))
    }
    key_membership = {
        'weak': float(fuzz.interp_membership(x_key, key_in['weak'].mf, key_numeric)),
        'moderate': float(fuzz.interp_membership(x_key, key_in['moderate'].mf, key_numeric)),
        'strong': float(fuzz.interp_membership(x_key, key_in['strong'].mf, key_numeric))
    }
    cert_membership = {
        'weak': float(fuzz.interp_membership(x_cert, cert_in['weak'].mf, cert_days)),
        'moderate': float(fuzz.interp_membership(x_cert, cert_in['moderate'].mf, cert_days)),
        'strong': float(fuzz.interp_membership(x_cert, cert_in['strong'].mf, cert_days))
    }

    # Evaluate rule firing strengths manually
    # Rule 1: all strong -> cdi low
    r1_strength = min(tls_membership['strong'], cipher_membership['strong'], key_membership['strong'], cert_membership['strong'], fs_membership['yes'])
    # Rule 2: tls old -> cdi high
    r2_strength = tls_membership['old']
    # Rule 3: cipher weak -> cdi high
    r3_strength = cipher_membership['weak']
    # Rule 4: key weak -> cdi high
    r4_strength = key_membership['weak']
    # Rule 5: cert weak -> cdi high
    r5_strength = cert_membership['weak']
    # Rule 6: moderate cert transition
    r6_strength = min(tls_membership['strong'], cipher_membership['strong'], key_membership['strong'], cert_membership['moderate'], fs_membership['yes'])
    # Rule 7: no forward secrecy -> cdi high (retained for degraded configs)
    r7_strength = fs_membership['no']
    # DEF-05 fix: transitional rules — strong posture without FS -> cdi moderate
    # Activates when TLS strong/moderate AND cipher strong AND key strong AND cert strong AND no FS.
    r_fs_transitional_strong = min(
        tls_membership['strong'], cipher_membership['strong'],
        key_membership['strong'], cert_membership['strong'], fs_membership['no']
    )
    r_fs_transitional_moderate_tls = min(
        tls_membership['moderate'], cipher_membership['strong'],
        key_membership['strong'], cert_membership['strong'], fs_membership['no']
    )
    # DEF-05 v2: cipher moderate (realistic static-RSA case) + key strong + cert strong + no FS
    r_fs_trans_cipher_mod_tls_strong = min(
        tls_membership['strong'], cipher_membership['moderate'],
        key_membership['strong'], cert_membership['strong'], fs_membership['no']
    )
    r_fs_trans_cipher_mod_tls_mod = min(
        tls_membership['moderate'], cipher_membership['moderate'],
        key_membership['strong'], cert_membership['strong'], fs_membership['no']
    )

    fired_rules = []
    if r1_strength > 0.05:
        fired_rules.append(f"IF TLS Strong AND Cipher Strong AND Key Strong AND Cert Healthy AND Forward Secrecy THEN CDI Low (activation: {r1_strength:.2f})")
    if r6_strength > 0.05:
        fired_rules.append(f"IF TLS Strong AND Cipher Strong AND Key Strong AND Cert Moderate AND Forward Secrecy THEN CDI Moderate (activation: {r6_strength:.2f})")
    if r_fs_transitional_strong > 0.05:
        fired_rules.append(
            f"IF TLS Strong AND Cipher Strong AND Key Strong AND Cert Strong AND No Forward Secrecy "
            f"THEN CDI Moderate [DEF-05: transitional rule prevents CRITICAL escalation for sound TLS lacking PFS] "
            f"(activation: {r_fs_transitional_strong:.2f})"
        )
    if r_fs_transitional_moderate_tls > 0.05:
        fired_rules.append(
            f"IF TLS Moderate AND Cipher Strong AND Key Strong AND Cert Strong AND No Forward Secrecy "
            f"THEN CDI Moderate [DEF-05: transitional] (activation: {r_fs_transitional_moderate_tls:.2f})"
        )
    if r_fs_trans_cipher_mod_tls_strong > 0.05:
        fired_rules.append(
            f"IF TLS Strong AND Cipher Moderate (Static RSA AEAD) AND Key Strong AND Cert Strong AND No Forward Secrecy "
            f"THEN CDI Moderate [DEF-05: realistic static-RSA transitional] "
            f"(activation: {r_fs_trans_cipher_mod_tls_strong:.2f})"
        )
    if r_fs_trans_cipher_mod_tls_mod > 0.05:
        fired_rules.append(
            f"IF TLS Moderate AND Cipher Moderate (Static RSA AEAD) AND Key Strong AND Cert Strong AND No Forward Secrecy "
            f"THEN CDI Moderate [DEF-05: realistic static-RSA transitional] "
            f"(activation: {r_fs_trans_cipher_mod_tls_mod:.2f})"
        )
    if r2_strength > 0.05:
        fired_rules.append(f"IF TLS Old (Deprecated) THEN CDI High (activation: {r2_strength:.2f})")
    if r3_strength > 0.05:
        fired_rules.append(f"IF Cipher Weak THEN CDI High (activation: {r3_strength:.2f})")
    if r4_strength > 0.05:
        fired_rules.append(f"IF Key Weak THEN CDI High (activation: {r4_strength:.2f})")
    if r5_strength > 0.05:
        fired_rules.append(f"IF Cert Weak (Imminent Expiry) THEN CDI High (activation: {r5_strength:.2f})")
    if r7_strength > 0.05:
        fired_rules.append(f"IF No Forward Secrecy (Static RSA/DH) THEN CDI High (activation: {r7_strength:.2f})")

    contributing_factors.append({
        'category': 'Antecedent Evaluation',
        'tls_version': {'value': tls_version, 'class': tls_class, 'membership': tls_membership},
        'cipher_strength': {'value': cipher_name, 'class': cipher_class, 'membership': cipher_membership},
        'key_length': {'value': f"{key_algorithm} {key_size_bits}-bit", 'class': key_class, 'membership': key_membership},
        'cert_validity': {'days_remaining': cert_days, 'membership': cert_membership},
        'forward_secrecy': {'value': forward_secrecy, 'membership': fs_membership},
        'fired_rules': fired_rules
    })

    # Run Mamdani simulation
    sim = ctrl.ControlSystemSimulation(_CDI_SYSTEM)
    sim.input['tls_version'] = tls_numeric
    sim.input['cipher_strength'] = cipher_numeric
    sim.input['key_length'] = key_numeric
    sim.input['cert_validity'] = cert_days
    sim.input['forward_secrecy'] = 1.0 if forward_secrecy else 0.0

    try:
        sim.compute()
        cdi_score = float(sim.output['cdi'])
    except Exception as e:
        # Standardized fallback if an anomalous boundary produces dangling activation
        cdi_score = 50.0

    # Add descriptive fired rule entries for frontend
    for r in fired_rules:
        contributing_factors.append({
            'category': 'Fired Rules',
            'description': r
        })

    return cdi_score, contributing_factors
