"""
Unit tests for the Hierarchical Fuzzy Logic Risk-Scoring Engine.

Covers:
1. Known-outcome cases: Clearly resilient vs clearly critical configurations.
2. Boundary tests: Certificate expiry at membership function transition points.
3. Continuity / Smoothness tests: Incremental daily changes producing continuous score curves.
4. Non-dilution OR rule for Critical tier: High CDI triggers Critical despite low PED and ELI.
5. Contract compliance: Antecedent score dictionary and 5-tier classification.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from app.risk_engine import (
    compute_crypto_deprecation_index,
    compute_posture_exposure_deficit,
    compute_exploitation_likelihood_index,
    compute_posture_risk
)


def test_clearly_resilient_configuration():
    """
    Clearly Resilient Case:
    - TLS 1.3, TLS_AES_256_GCM_SHA384 (Modern), EC 256 bits, 180 days cert validity
    - SPF present, DKIM present, DMARC reject (full), DNSSEC enabled
    - Safe server software banner
    Expectation: Low risk (<25) with linguistic tag 'EXCELLENT'.
    """
    cdi_score, cdi_factors = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=180
    )
    assert cdi_score < 25.0, f"Expected low CDI, got {cdi_score}"

    ped_score, ped_factors = compute_posture_exposure_deficit(
        spf_present=True,
        dkim_present=True,
        dmarc_policy="v=DMARC1; p=reject",
        dmarc_enforcement="reject",
        dnssec_enabled=True
    )
    assert ped_score < 25.0, f"Expected low PED, got {ped_score}"

    eli_score, eli_factors = compute_exploitation_likelihood_index(
        banner="220 mx.example.com ESMTP Postfix",
        is_customer_facing=False
    )
    assert eli_score < 35.0, f"Expected low ELI, got {eli_score}"

    final_score, classification, antecedents, factors = compute_posture_risk(
        cdi_score=cdi_score,
        ped_score=ped_score,
        eli_score=eli_score
    )

    assert final_score < 25.0, f"Expected resilient final score (<25), got {final_score}"
    assert classification == "EXCELLENT", f"Expected EXCELLENT classification, got {classification}"
    assert antecedents["pqc_readiness"] == 0.5
    assert antecedents["email_auth_posture"] > 0.75
    assert antecedents["exploitation_likelihood"] < 0.35


def test_clearly_critical_configuration():
    """
    Clearly Critical Case:
    - TLS 1.0, TLS_RSA_WITH_3DES_EDE_CBC_SHA, RSA 1024 bits, expired cert (0 days)
    - SPF absent, DKIM absent, DMARC none/absent, DNSSEC disabled
    - Known-vulnerable mail server version in banner
    Expectation: High risk (>80) with linguistic tag 'CRITICAL'.
    """
    cdi_score, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.0",
        cipher_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        key_algorithm="RSA",
        key_size_bits=1024,
        days_until_expiry=0
    )
    assert cdi_score > 75.0, f"Expected high CDI, got {cdi_score}"

    ped_score, _ = compute_posture_exposure_deficit(
        spf_present=False,
        dkim_present=False,
        dmarc_policy="",
        dmarc_enforcement="",
        dnssec_enabled=False
    )
    assert ped_score > 75.0, f"Expected high PED, got {ped_score}"

    eli_score, _ = compute_exploitation_likelihood_index(
        banner="220 mail.victim.com ESMTP Postfix 2.10.1",
        is_customer_facing=True
    )
    assert eli_score > 75.0, f"Expected high ELI, got {eli_score}"

    final_score, classification, antecedents, factors = compute_posture_risk(
        cdi_score=cdi_score,
        ped_score=ped_score,
        eli_score=eli_score
    )

    assert final_score >= 80.0, f"Expected critical final score (>=80), got {final_score}"
    assert classification == "CRITICAL", f"Expected CRITICAL classification, got {classification}"
    assert antecedents["email_auth_posture"] < 0.25
    assert antecedents["exploitation_likelihood"] > 0.75


def test_boundary_transition_smoothness():
    """
    Boundary Test:
    Verifies that a certificate expiring exactly at membership transition points
    (e.g., 15 days, 45 days, 90 days) produces intermediate, smooth scores
    between neighboring categories without abrupt step-function jumps.
    """
    # 0 days (typical weak/expired) vs 25 days (weak-moderate transition point)
    # vs 45 days (typical moderate) vs 75 days (moderate-strong transition point) vs 120 days (typical strong)
    score_0, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=0
    )
    score_25, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=25
    )
    score_45, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=45
    )
    score_75, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=75
    )
    score_120, _ = compute_crypto_deprecation_index(
        tls_version="TLS 1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_algorithm="EC (secp256r1)",
        key_size_bits=256,
        days_until_expiry=120
    )

    # Risk must monotonically decrease as validity increases
    assert score_0 > score_25 > score_45 > score_75 > score_120, (
        f"Expected monotonic transition: score_0 ({score_0:.2f}) > "
        f"score_25 ({score_25:.2f}) > score_45 ({score_45:.2f}) > "
        f"score_75 ({score_75:.2f}) > score_120 ({score_120:.2f})"
    )

    # The 25-day transition point must lie smoothly between 0 and 45 days
    assert score_45 < score_25 < score_0, "Transition point at 25 days must lie strictly between 0 and 45 days"
    # The 75-day transition point must lie smoothly between 45 and 120 days
    assert score_120 < score_75 < score_45, "Transition point at 75 days must lie strictly between 45 and 120 days"


def test_incremental_change_smoothness():
    """
    Smoothness / Continuity Test:
    Moving cert expiry day by day from 90 down to 0 days must produce a continuous,
    smoothly changing score curve, NOT a discrete step function.
    Any single day's score delta must be small (< 4.0 points).
    """
    scores = []
    days_range = list(range(90, -1, -1))  # 90 down to 0 days

    for day in days_range:
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_algorithm="EC (secp256r1)",
            key_size_bits=256,
            days_until_expiry=day
        )
        scores.append(cdi)

    # Check maximum delta between adjacent days
    deltas = [abs(scores[i] - scores[i-1]) for i in range(1, len(scores))]
    max_delta = max(deltas)

    # In a step function, an expiry boundary would jump by 20-30 points in a single day.
    # In our Mamdani FIS, max delta per day should be smoothly bounded under 3.5 points.
    assert max_delta < 3.5, f"Step function detected! Max daily jump was {max_delta:.2f} points"

    # Overall direction: Risk at 0 days must be strictly higher than at 90 days
    assert scores[-1] > scores[0], "0 days until expiry must have higher risk than 90 days"


def test_single_critical_flaw_or_rule():
    """
    Test Non-Dilution of Critical Failure:
    Verifies that if one composite is High (e.g. Critical CDI due to TLS 1.0 + 3DES),
    it is NOT diluted by low PED (full email auth) and low ELI.
    The OR rule across composites must force the final classification into CRITICAL.
    """
    high_cdi = 85.0
    low_ped = 12.0
    low_eli = 15.0

    final_score, classification, _, factors = compute_posture_risk(
        cdi_score=high_cdi,
        ped_score=low_ped,
        eli_score=low_eli
    )

    # Must be categorized as CRITICAL due to non-dilution OR rule
    assert final_score >= 80.0, f"Expected final score >= 80, got {final_score}"
    assert classification == "CRITICAL", f"Expected CRITICAL, got {classification}"

    # Verify fired rules mentions the OR rule
    fired_rule_texts = [f.get("description", "") for f in factors if f.get("category") == "Fired Rules"]
    or_rule_matched = any("OR" in text and "CRITICAL" in text for text in fired_rule_texts)
    assert or_rule_matched, "Expected Critical OR rule description in fired rules"


def test_frontend_contract_antecedents():
    """
    Contract Alignment Test:
    Ensures all antecedent fields specified by the frontend contract exist,
    have correct float types, and are normalized within [0.0, 1.0].
    """
    final_score, classification, antecedents, _ = compute_posture_risk(
        cdi_score=35.0,
        ped_score=40.0,
        eli_score=30.0
    )

    required_keys = [
        "tls_compliance",
        "cipher_strength",
        "certificate_health",
        "pqc_readiness",
        "email_auth_posture",
        "exploitation_likelihood"
    ]

    for key in required_keys:
        assert key in antecedents, f"Missing key {key} in antecedent_scores"
        val = antecedents[key]
        assert isinstance(val, float), f"Key {key} must be float, got {type(val)}"
        assert 0.0 <= val <= 1.0, f"Key {key} value {val} out of bounds [0.0, 1.0]"

    valid_classifications = {"EXCELLENT", "GOOD", "ACCEPTABLE", "POOR", "CRITICAL"}
    assert classification in valid_classifications, f"Invalid classification: {classification}"
