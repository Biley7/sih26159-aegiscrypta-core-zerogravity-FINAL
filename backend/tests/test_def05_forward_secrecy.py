"""
DEF-05: Forward Secrecy Over-Penalization — End-to-End Verification
====================================================================

Verifies the CDI transitional rules added to correct the audit finding DEF-05:
"CDI has no moderate path for TLS 1.3 + no-FS scenario".

Root cause confirmed before fix:
    TLS_RSA_WITH_AES_256_GCM_SHA384 classifies as cipher='moderate' (not 'strong'),
    so the original two transitional rules (which required cipher='strong') never fired.
    The standalone `fs_no → CDI high` rule fired at strength 1.0, pushing CDI to ~86,
    which triggered the Tier 2 non-dilution OR rule → CRITICAL for a domain with
    good email auth and no known vulnerable software.

Fix applied:
    Two additional transitional rules covering cipher='moderate' + key='strong':
      - tls_moderate & cipher_moderate & key_strong & cert_strong & fs_no → CDI moderate
      - tls_strong  & cipher_moderate & key_strong & cert_strong & fs_no → CDI moderate

Test matrix:
    1. Primary case: TLS 1.2 + static RSA AES-256-GCM + RSA-4096 + 180d cert + no FS
       → CDI must be < 75 (moderate band), Tier 2 must be ACCEPTABLE/GOOD/POOR (not CRITICAL)
    2. Regression: TLS 1.0 + 3DES + RSA-1024 + expired cert + no FS
       → CDI must remain ≥ 80 (high band), Tier 2 must be CRITICAL
    3. ECDHE cipher (has FS by definition) must not activate transitional rules
    4. Tier 2 classification for case 1 must not be CRITICAL under any realistic
       email-auth posture combination
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from app.risk_engine.crypto_deprecation import (
    compute_crypto_deprecation_index,
    classify_cipher_strength,
)
from app.risk_engine import (
    compute_posture_exposure_deficit,
    compute_exploitation_likelihood_index,
    compute_posture_risk,
)


# ---------------------------------------------------------------------------
# Helper: build a realistic "good email auth" posture for Tier 2 context
# ---------------------------------------------------------------------------

def _good_posture():
    """SPF + DKIM + DMARC reject — returns (ped_score, eli_score)."""
    ped, _ = compute_posture_exposure_deficit(
        spf_present=True,
        dkim_present=True,
        dmarc_policy="v=DMARC1; p=reject",
        dmarc_enforcement="reject",
        dnssec_enabled=False,
    )
    eli, _ = compute_exploitation_likelihood_index(
        banner="220 mx.example.com ESMTP",
        is_customer_facing=False,
    )
    return ped, eli


# ---------------------------------------------------------------------------
# Test 1 — Primary DEF-05 case: TLS 1.2 + static RSA cipher + strong key + no FS
# ---------------------------------------------------------------------------

class TestDef05PrimaryCase:
    """
    The realistic production edge case DEF-05 was meant to fix.
    TLS 1.2 server using TLS_RSA_WITH_AES_256_GCM_SHA384 (static RSA key exchange —
    no forward secrecy) with a 4096-bit RSA key and a fresh certificate.
    """

    def test_cipher_classifies_as_moderate(self):
        """Static RSA AES-GCM ciphers must classify as 'moderate' (no ECDHE prefix)."""
        assert classify_cipher_strength("TLS_RSA_WITH_AES_256_GCM_SHA384") == "moderate"
        assert classify_cipher_strength("TLS_RSA_WITH_AES_128_GCM_SHA256") == "moderate"
        assert classify_cipher_strength("AES256-GCM-SHA384") == "moderate"

    def test_cdi_lands_in_moderate_band(self):
        """
        CDI must be < 75 (moderate band ceiling) so it does NOT trigger the Tier 2
        non-dilution OR rule (which fires at CDI >= ~65 high membership).
        Before the fix, CDI = 86.04. After the fix, CDI = 68.94.
        """
        cdi, factors = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=4096,
            days_until_expiry=180,
            forward_secrecy=False,
        )
        assert cdi < 75.0, (
            f"DEF-05: CDI={cdi:.2f} is still in the HIGH band (>= 75). "
            "The transitional rule for cipher_moderate + key_strong is not firing correctly."
        )
        # Transitional rule must be in fired rules
        fired = [f["description"] for f in factors if f.get("category") == "Fired Rules"]
        transitional_fired = any("DEF-05" in r and "static-RSA" in r for r in fired)
        assert transitional_fired, (
            f"DEF-05 transitional rule did not fire. Fired rules: {fired}"
        )

    def test_tier2_not_critical_with_good_auth(self):
        """
        End-to-end: TLS 1.2/static-RSA/no-FS + good email auth must not reach CRITICAL.
        Required outcome: ACCEPTABLE or GOOD, matching the final verification criterion.
        """
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=4096,
            days_until_expiry=180,
            forward_secrecy=False,
        )
        ped, eli = _good_posture()
        score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification in {"ACCEPTABLE", "GOOD"}, (
            f"DEF-05: TLS1.2/static-RSA/no-FS with good email auth classified as "
            f"{classification} (score={score:.2f}). Expected ACCEPTABLE or GOOD."
        )

    def test_tier2_not_critical_with_partial_auth(self):
        """
        Even with partial email auth (SPF only, DMARC p=none), a TLS 1.2 static-RSA
        server with a strong key should not reach CRITICAL solely due to absent PFS.
        """
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=3072,
            days_until_expiry=90,
            forward_secrecy=False,
        )
        ped, _ = compute_posture_exposure_deficit(
            spf_present=True,
            dkim_present=False,
            dmarc_policy="v=DMARC1; p=none",
            dmarc_enforcement="monitoring only",
            dnssec_enabled=False,
        )
        eli, _ = compute_exploitation_likelihood_index(
            banner="220 mx.example.com ESMTP",
            is_customer_facing=False,
        )
        score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification != "CRITICAL", (
            f"DEF-05: TLS1.2/no-FS/partial-auth => {classification} (score={score:.2f}). "
            "Should not be CRITICAL for transitional TLS 1.2 without PFS."
        )

    def test_penalty_still_applied_not_excellent(self):
        """
        Absent forward secrecy must still incur a penalty — the result must NOT be
        EXCELLENT, which would imply the FS absence was ignored entirely.
        """
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=4096,
            days_until_expiry=180,
            forward_secrecy=False,
        )
        ped, eli = _good_posture()
        score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification != "EXCELLENT", (
            "Absent forward secrecy must incur a penalty — classification must not be EXCELLENT."
        )


# ---------------------------------------------------------------------------
# Test 2 — Regression: genuinely degraded config must remain CRITICAL
# ---------------------------------------------------------------------------

class TestDef05Regression:
    """Verify that truly deprecated configurations are not softened by the transitional rules."""

    def test_tls10_3des_expired_still_critical(self):
        """TLS 1.0 + 3DES + RSA-1024 + expired cert + no FS must still classify as CRITICAL."""
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.0",
            cipher_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_algorithm="RSA",
            key_size_bits=1024,
            days_until_expiry=0,
            forward_secrecy=False,
        )
        ped, eli = _good_posture()
        score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert cdi >= 80.0, f"Expected CDI >= 80 for degraded config, got {cdi:.2f}"
        assert classification == "CRITICAL", (
            f"Degraded config (TLS1.0/3DES/RSA1024/expired) must be CRITICAL, got {classification}"
        )

    def test_weak_key_no_fs_still_critical(self):
        """RSA-1024 with absent FS — weak key should independently push to CRITICAL."""
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=1024,   # weak key despite decent cipher
            days_until_expiry=180,
            forward_secrecy=False,
        )
        ped, eli = _good_posture()
        _, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification == "CRITICAL", (
            f"RSA-1024 + no FS must be CRITICAL regardless of transitional rule. Got {classification}"
        )

    def test_expired_cert_no_fs_still_critical(self):
        """Expired certificate + no FS must remain CRITICAL."""
        cdi, _ = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=4096,
            days_until_expiry=0,   # expired
            forward_secrecy=False,
        )
        ped, eli = _good_posture()
        _, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification == "CRITICAL", (
            f"Expired cert + no FS must be CRITICAL. Got {classification}"
        )


# ---------------------------------------------------------------------------
# Test 3 — ECDHE cipher (has FS) must not activate DEF-05 transitional rules
# ---------------------------------------------------------------------------

class TestDef05NonActivation:
    """Transitional rules must NOT fire when forward secrecy is present."""

    def test_ecdhe_cipher_with_fs_not_affected(self):
        """
        ECDHE-RSA-AES256-GCM-SHA384 + forward_secrecy=True must produce CDI low/moderate
        via the standard rules, not the DEF-05 transitional path.
        """
        cdi, factors = compute_crypto_deprecation_index(
            tls_version="TLS 1.2",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            key_algorithm="RSA",
            key_size_bits=4096,
            days_until_expiry=180,
            forward_secrecy=True,
        )
        fired = [f["description"] for f in factors if f.get("category") == "Fired Rules"]
        transitional_fired = any("DEF-05" in r for r in fired)
        assert not transitional_fired, (
            f"DEF-05 transitional rule fired unexpectedly for ECDHE cipher with FS. "
            f"Fired rules: {fired}"
        )
        assert cdi < 50.0, (
            f"ECDHE/FS=True must produce CDI < 50 (low/moderate), got {cdi:.2f}"
        )

    def test_tls13_cipher_with_implicit_fs_not_affected(self):
        """TLS 1.3 cipher with implicit forward secrecy must not trigger DEF-05 path."""
        cdi, factors = compute_crypto_deprecation_index(
            tls_version="TLS 1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            key_algorithm="EC (secp256r1)",
            key_size_bits=256,
            days_until_expiry=180,
            forward_secrecy=True,
        )
        fired = [f["description"] for f in factors if f.get("category") == "Fired Rules"]
        transitional_fired = any("DEF-05" in r for r in fired)
        assert not transitional_fired, (
            f"DEF-05 transitional rule fired for TLS 1.3 with FS. Fired rules: {fired}"
        )
        assert cdi < 25.0, (
            f"TLS 1.3 / AEAD / FS=True must produce CDI < 25 (low), got {cdi:.2f}"
        )
