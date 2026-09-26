"""
Test to determine actual raw bounds of fuzzy defuzzification output.
This helps us establish RAW_MIN and RAW_MAX for rescaling.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.risk_engine import (
    compute_crypto_deprecation_index,
    compute_posture_exposure_deficit,
    compute_exploitation_likelihood_index,
    compute_posture_risk
)

def test_extreme_combinations():
    """Test extreme input combinations to determine actual output bounds."""
    
    print("Testing fuzzy engine output bounds...")
    print("=" * 60)
    
    # Test Case 1: Best case (perfect posture)
    print("\n1. BEST CASE (perfect posture):")
    cdi_best, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="ECC",
        key_size_bits=256,
        days_until_expiry=365
    )
    ped_best, _ = compute_posture_exposure_deficit(
        spf_present=True,
        dkim_present=True,
        dmarc_policy="p=reject",
        dmarc_enforcement="full",
        dnssec_enabled=True
    )
    eli_best, _ = compute_exploitation_likelihood_index(
        banner="220 mail.example.com ESMTP Postfix 3.8.0",
        is_customer_facing=False
    )
    
    fuzzy_best, _, _, _ = compute_posture_risk(
        cdi_score=cdi_best,
        ped_score=ped_best,
        eli_score=eli_best
    )
    
    print(f"  CDI: {cdi_best:.2f}")
    print(f"  PED: {ped_best:.2f}")
    print(f"  ELI: {eli_best:.2f}")
    print(f"  Final Score: {fuzzy_best:.2f}")
    
    # Test Case 2: Worst case (catastrophic posture)
    print("\n2. WORST CASE (catastrophic posture):")
    cdi_worst, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.0",
        cipher_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        key_algorithm="RSA",
        key_size_bits=1024,
        days_until_expiry=-100
    )
    ped_worst, _ = compute_posture_exposure_deficit(
        spf_present=False,
        dkim_present=False,
        dmarc_policy="",
        dmarc_enforcement="",
        dnssec_enabled=False
    )
    eli_worst, _ = compute_exploitation_likelihood_index(
        banner="220 mail.example.com ESMTP Sendmail 8.14.4",
        is_customer_facing=True
    )
    
    fuzzy_worst, _, _, _ = compute_posture_risk(
        cdi_score=cdi_worst,
        ped_score=ped_worst,
        eli_score=eli_worst
    )
    
    print(f"  CDI: {cdi_worst:.2f}")
    print(f"  PED: {ped_worst:.2f}")
    print(f"  ELI: {eli_worst:.2f}")
    print(f"  Final Score: {fuzzy_worst:.2f}")
    
    # Test Case 3: Mixed case
    print("\n3. MIXED CASE (partial issues):")
    cdi_mixed, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.2",
        cipher_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_algorithm="RSA",
        key_size_bits=2048,
        days_until_expiry=30
    )
    ped_mixed, _ = compute_posture_exposure_deficit(
        spf_present=True,
        dkim_present=False,
        dmarc_policy="p=none",
        dmarc_enforcement="monitoring only",
        dnssec_enabled=False
    )
    eli_mixed, _ = compute_exploitation_likelihood_index(
        banner="220 mail.example.com ESMTP Postfix 3.2.0",
        is_customer_facing=False
    )
    
    fuzzy_mixed, _, _, _ = compute_posture_risk(
        cdi_score=cdi_mixed,
        ped_score=ped_mixed,
        eli_score=eli_mixed
    )
    
    print(f"  CDI: {cdi_mixed:.2f}")
    print(f"  PED: {ped_mixed:.2f}")
    print(f"  ELI: {eli_mixed:.2f}")
    print(f"  Final Score: {fuzzy_mixed:.2f}")
    
    # Summary
    print("\n" + "=" * 60)
    print("OUTPUT BOUNDS SUMMARY:")
    print(f"  Minimum observed: {min(fuzzy_best, fuzzy_worst, fuzzy_mixed):.2f}")
    print(f"  Maximum observed: {max(fuzzy_best, fuzzy_worst, fuzzy_mixed):.2f}")
    print(f"  Range: {max(fuzzy_best, fuzzy_worst, fuzzy_mixed) - min(fuzzy_best, fuzzy_worst, fuzzy_mixed):.2f}")
    
    # Recommended bounds (with safety margin)
    RAW_MIN = min(fuzzy_best, fuzzy_worst, fuzzy_mixed) - 5
    RAW_MAX = max(fuzzy_best, fuzzy_worst, fuzzy_mixed) + 5
    print(f"\nRecommended RAW_MIN: {RAW_MIN:.2f}")
    print(f"Recommended RAW_MAX: {RAW_MAX:.2f}")

if __name__ == "__main__":
    test_extreme_combinations()
