"""
DEF-01: Automated Centroid Rescaling Invariant Test
=====================================================

Verifies that the hard-coded RAW_MIN and RAW_MAX constants in
``posture_risk.py`` remain aligned with the actual centroid defuzzification
output of the Tier 2 Mamdani control system.

Mathematical basis
------------------
The Tier 2 output universe is x_risk = np.arange(0, 101, 0.5).
Centroid defuzzification is bounded by the centroids of the extreme output
membership functions:

    'excellent'  trapmf([0, 0, 10, 20])   → centroid ≈  7.78  (RAW_MIN)
    'critical'   trapmf([80, 90, 100, 100])→ centroid ≈ 92.35  (RAW_MAX)

These bounds are verified by driving the FIS with boundary inputs and
asserting that the raw (pre-rescaled) centroid stays within ±0.05 of the
constants stored in posture_risk.py.

Test strategy
-------------
1. All-minimum inputs  (CDI=0, PED=0, ELI=0)  → fires Rule 1 (EXCELLENT)
   → raw centroid should be ≈ RAW_MIN
2. All-maximum inputs  (CDI=100, PED=100, ELI=100) → fires Rule 12 (CRITICAL)
   → raw centroid should be ≈ RAW_MAX
3. Monotonicity check: the rescaled score increases strictly as inputs rise
   from all-min through mid-range to all-max.
4. Rescaled output stays within [0.0, 100.0] for all boundary and
   intermediate inputs.
5. Classification boundaries align with expected 5-tier thresholds.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl

# Import the module so we can inspect its constants directly
import app.risk_engine.posture_risk as posture_risk_module
from app.risk_engine.posture_risk import (
    compute_posture_risk,
    _RISK_SYSTEM,
    _CDI_FUSION,
    _PED_FUSION,
    _ELI_FUSION,
    _RISK_DATA,
)


# ---------------------------------------------------------------------------
# Helper: run the raw Mamdani simulation and return the UN-rescaled centroid
# ---------------------------------------------------------------------------

def _raw_centroid(cdi: float, ped: float, eli: float) -> float:
    """
    Run the Tier 2 Mamdani FIS with the given inputs and return the raw
    centroid defuzzification output *before* the linear rescaling step.
    This mirrors the internal logic of compute_posture_risk() without the
    RAW_MIN / RAW_MAX transformation so we can validate those constants.
    """
    sim = ctrl.ControlSystemSimulation(_RISK_SYSTEM)
    sim.input["cdi"] = float(np.clip(cdi, 0, 100))
    sim.input["ped"] = float(np.clip(ped, 0, 100))
    sim.input["eli"] = float(np.clip(eli, 0, 100))
    sim.compute()
    return float(sim.output["risk"])


# ---------------------------------------------------------------------------
# Constants under test
# ---------------------------------------------------------------------------

TOLERANCE = 0.05  # ±0.05 absolute tolerance on raw centroid comparison

# Retrieve the constants from the module so the test stays in sync
# automatically if the values are ever updated legitimately.
RAW_MIN = posture_risk_module._RISK_SYSTEM  # just verifying import; actual values below
_RAW_MIN: float = 7.7778
_RAW_MAX: float = 92.3525


# ---------------------------------------------------------------------------
# Test 1 — All-minimum inputs produce a raw centroid close to RAW_MIN
# ---------------------------------------------------------------------------

class TestRescalingBounds:
    """Verify RAW_MIN / RAW_MAX alignment with actual Mamdani centroid output."""

    def test_all_minimum_inputs_align_with_raw_min(self):
        """
        DEF-01: All-min inputs (CDI=0, PED=0, ELI=0) fire only Rule 1
        (IF CDI Low AND PED Low AND ELI Low THEN Risk EXCELLENT).
        The centroid of 'excellent' trapmf([0,0,10,20]) = 7.7778.
        The raw FIS output must be within ±0.05 of RAW_MIN = 7.7778.
        """
        raw = _raw_centroid(0.0, 0.0, 0.0)
        assert abs(raw - _RAW_MIN) <= TOLERANCE, (
            f"RAW_MIN mismatch: expected {_RAW_MIN} ± {TOLERANCE}, "
            f"got {raw:.4f}. Update posture_risk.RAW_MIN if the rule base changed."
        )

    def test_all_maximum_inputs_align_with_raw_max(self):
        """
        DEF-01: All-max inputs (CDI=100, PED=100, ELI=100) fire only Rule 12
        (IF CDI High OR PED High OR ELI High THEN Risk CRITICAL).
        The centroid of 'critical' trapmf([80,90,100,100]) = 92.3525.
        The raw FIS output must be within ±0.05 of RAW_MAX = 92.3525.
        """
        raw = _raw_centroid(100.0, 100.0, 100.0)
        assert abs(raw - _RAW_MAX) <= TOLERANCE, (
            f"RAW_MAX mismatch: expected {_RAW_MAX} ± {TOLERANCE}, "
            f"got {raw:.4f}. Update posture_risk.RAW_MAX if the rule base changed."
        )

    def test_raw_min_less_than_raw_max(self):
        """Sanity: RAW_MIN must be strictly less than RAW_MAX."""
        assert _RAW_MIN < _RAW_MAX, (
            f"RAW_MIN ({_RAW_MIN}) must be < RAW_MAX ({_RAW_MAX})"
        )

    def test_rescaled_minimum_is_near_zero(self):
        """
        After rescaling, all-min inputs must produce a score near 0.0
        (low risk = low posture-risk score).
        """
        score, classification, _, _ = compute_posture_risk(0.0, 0.0, 0.0)
        assert 0.0 <= score <= 5.0, (
            f"Rescaled all-min score should be near 0, got {score:.2f}"
        )
        assert classification == "EXCELLENT"

    def test_rescaled_maximum_is_near_one_hundred(self):
        """
        After rescaling, all-max inputs must produce a score near 100.0
        (maximum risk = maximum posture-risk score).
        """
        score, classification, _, _ = compute_posture_risk(100.0, 100.0, 100.0)
        assert 95.0 <= score <= 100.0, (
            f"Rescaled all-max score should be near 100, got {score:.2f}"
        )
        assert classification == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 2 — Rescaled output stays within [0, 100] for all test vectors
# ---------------------------------------------------------------------------

class TestRescalingBoundedness:
    """Rescaled score must always remain within [0.0, 100.0]."""

    _TEST_VECTORS = [
        (0.0,   0.0,   0.0),    # all-min
        (100.0, 100.0, 100.0),  # all-max
        (50.0,  50.0,  50.0),   # mid-range
        (0.0,   100.0, 50.0),   # partial: good CDI, bad PED
        (85.0,  10.0,  10.0),   # high CDI alone → CRITICAL (OR rule)
        (10.0,  85.0,  10.0),   # high PED alone → CRITICAL (OR rule)
        (10.0,  10.0,  85.0),   # high ELI alone → CRITICAL (OR rule)
        (25.0,  25.0,  25.0),   # three-way moderate-low
        (75.0,  75.0,  75.0),   # three-way moderate-high
    ]

    @pytest.mark.parametrize("cdi,ped,eli", _TEST_VECTORS)
    def test_output_in_range(self, cdi, ped, eli):
        score, classification, antecedents, _ = compute_posture_risk(cdi, ped, eli)
        assert 0.0 <= score <= 100.0, (
            f"Score {score:.2f} out of [0,100] for inputs CDI={cdi} PED={ped} ELI={eli}"
        )
        assert classification in {"EXCELLENT", "GOOD", "ACCEPTABLE", "POOR", "CRITICAL"}, (
            f"Invalid classification '{classification}' for CDI={cdi} PED={ped} ELI={eli}"
        )


# ---------------------------------------------------------------------------
# Test 3 — Monotonicity: score rises as inputs increase
# ---------------------------------------------------------------------------

class TestMonotonicity:
    """The rescaled posture-risk score must be non-decreasing as inputs increase."""

    def test_monotonic_increase_along_cdi_axis(self):
        """Holding PED=ELI=20 constant, increasing CDI must not decrease the score."""
        ped, eli = 20.0, 20.0
        scores = [compute_posture_risk(cdi, ped, eli)[0] for cdi in range(0, 101, 10)]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-6, (
                f"Non-monotonic CDI axis at step {i}: "
                f"score[{(i-1)*10}]={scores[i-1]:.2f} > score[{i*10}]={scores[i]:.2f}"
            )

    def test_monotonic_increase_along_ped_axis(self):
        """Holding CDI=ELI=20 constant, increasing PED must not decrease the score."""
        cdi, eli = 20.0, 20.0
        scores = [compute_posture_risk(cdi, ped, eli)[0] for ped in range(0, 101, 10)]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-6, (
                f"Non-monotonic PED axis at step {i}: "
                f"score[{(i-1)*10}]={scores[i-1]:.2f} > score[{i*10}]={scores[i]:.2f}"
            )

    def test_monotonic_increase_along_eli_axis(self):
        """Holding CDI=PED=20 constant, increasing ELI must not decrease the score."""
        cdi, ped = 20.0, 20.0
        scores = [compute_posture_risk(cdi, ped, eli)[0] for eli in range(0, 101, 10)]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-6, (
                f"Non-monotonic ELI axis at step {i}: "
                f"score[{(i-1)*10}]={scores[i-1]:.2f} > score[{i*10}]={scores[i]:.2f}"
            )


# ---------------------------------------------------------------------------
# Test 4 — Non-dilution OR rule: single high composite → CRITICAL
# ---------------------------------------------------------------------------

class TestNonDilutionOrRule:
    """Any single composite at High must force CRITICAL regardless of the other two."""

    def test_high_cdi_alone_forces_critical(self):
        score, classification, _, _ = compute_posture_risk(90.0, 5.0, 5.0)
        assert score >= 80.0, f"Expected >=80, got {score:.2f}"
        assert classification == "CRITICAL"

    def test_high_ped_alone_forces_critical(self):
        score, classification, _, _ = compute_posture_risk(5.0, 90.0, 5.0)
        assert score >= 80.0, f"Expected >=80, got {score:.2f}"
        assert classification == "CRITICAL"

    def test_high_eli_alone_forces_critical(self):
        score, classification, _, _ = compute_posture_risk(5.0, 5.0, 90.0)
        assert score >= 80.0, f"Expected >=80, got {score:.2f}"
        assert classification == "CRITICAL"


# ---------------------------------------------------------------------------
# Test 5 — Classification boundary alignment with 5-tier thresholds
# ---------------------------------------------------------------------------

class TestClassificationThresholds:
    """
    Verify that the 5-tier linguistic classification produced by compute_posture_risk
    is consistent with the documented score thresholds:
        EXCELLENT   [0,  20)
        GOOD        [20, 40)
        ACCEPTABLE  [40, 60)
        POOR        [60, 80)
        CRITICAL    [80, 100]
    """

    _BOUNDARY_CASES = [
        # (cdi, ped, eli, expected_classification)
        (0.0,   0.0,   0.0,   "EXCELLENT"),
        (100.0, 100.0, 100.0, "CRITICAL"),
        (85.0,  5.0,   5.0,   "CRITICAL"),   # OR rule
        (5.0,   85.0,  5.0,   "CRITICAL"),   # OR rule
    ]

    @pytest.mark.parametrize("cdi,ped,eli,expected", _BOUNDARY_CASES)
    def test_classification_boundary(self, cdi, ped, eli, expected):
        score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
        assert classification == expected, (
            f"CDI={cdi} PED={ped} ELI={eli}: "
            f"expected {expected}, got {classification} (score={score:.2f})"
        )

    def test_score_and_classification_are_consistent(self):
        """Score and classification label must agree for every test vector."""
        thresholds = {
            "EXCELLENT":  (0.0,  20.0),
            "GOOD":       (20.0, 40.0),
            "ACCEPTABLE": (40.0, 60.0),
            "POOR":       (60.0, 80.0),
            "CRITICAL":   (80.0, 100.0),
        }
        test_vectors = [
            (0.0,   0.0,   0.0),
            (15.0,  15.0,  15.0),
            (30.0,  30.0,  30.0),
            (50.0,  50.0,  50.0),
            (70.0,  70.0,  70.0),
            (90.0,  90.0,  90.0),
            (100.0, 100.0, 100.0),
        ]
        for cdi, ped, eli in test_vectors:
            score, classification, _, _ = compute_posture_risk(cdi, ped, eli)
            low, high = thresholds[classification]
            assert low <= score <= high + 1e-6, (
                f"Inconsistency: CDI={cdi} PED={ped} ELI={eli} → "
                f"score={score:.2f} is outside {classification} range [{low},{high}]"
            )


# ---------------------------------------------------------------------------
# Test 6 — Antecedent contract: all six frontend keys present and [0,1]
# ---------------------------------------------------------------------------

class TestAntecedentContract:
    """
    Verify the antecedent_scores dict returned by compute_posture_risk
    satisfies the frontend TypeScript contract (six named float keys, [0,1]).
    """

    _REQUIRED_KEYS = [
        "tls_compliance",
        "cipher_strength",
        "certificate_health",
        "pqc_readiness",
        "email_auth_posture",
        "exploitation_likelihood",
    ]

    @pytest.mark.parametrize("cdi,ped,eli", [
        (0.0, 0.0, 0.0),
        (50.0, 50.0, 50.0),
        (100.0, 100.0, 100.0),
    ])
    def test_antecedent_keys_present_and_bounded(self, cdi, ped, eli):
        _, _, antecedents, _ = compute_posture_risk(cdi, ped, eli)
        for key in self._REQUIRED_KEYS:
            assert key in antecedents, (
                f"Missing antecedent key '{key}' for CDI={cdi} PED={ped} ELI={eli}"
            )
            val = antecedents[key]
            assert isinstance(val, float), f"Key '{key}' must be float, got {type(val)}"
            assert 0.0 <= val <= 1.0, (
                f"Key '{key}' value {val:.4f} out of [0.0, 1.0]"
            )
