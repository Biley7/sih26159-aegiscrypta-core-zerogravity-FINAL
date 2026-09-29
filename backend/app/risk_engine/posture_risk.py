"""
Posture Risk Fusion - Tier 2 Fuzzy Inference System

Fuses Tier 1 Composite Indices:
- Crypto Deprecation Index (CDI) [0-100]
- Posture Exposure Deficit (PED) [0-100]
- Exploitation Likelihood Index (ELI) [0-100]

Produces the final Posture Risk Index (0-100) and a 5-tier linguistic classification:
- EXCELLENT (0-20)
- GOOD (20-40)
- ACCEPTABLE (40-60)
- POOR (60-80)
- CRITICAL (80-100)

Design Choice:
Includes an explicit OR rule across composites for the Critical tier
(e.g., any single composite being High triggers Critical Posture Deficit),
reflecting that one severe weakness (such as an expired certificate, deprecated TLS 1.0,
or unenforced DMARC allowing domain spoofing) should never be diluted or masked
by two unrelated strengths.
"""

import logging
import math

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("aegiscrypta.risk_engine.posture_risk")

# Constant returned when Mamdani defuzzification is impossible. Degraded result,
# never a measurement.
RISK_FALLBACK_SCORE = 50.0

# Neutral Tier-1 composite value used when an upstream index is missing or
# non-finite. 50 sits at the centroid of the 'moderate' antecedent set, i.e. the
# point of maximum ignorance in the [0, 100] universe.
COMPOSITE_NEUTRAL_VALUE = 50.0

# Empirically determined rescale bounds for the defuzzified output. Both the
# three-axis fusion and the transport-unaudited fusion reuse these because they
# share the identical 5-tier consequent: RAW_MIN is the centroid of the
# 'excellent' set (its only active rule when every observed composite is Low) and
# RAW_MAX is the centroid of the 'critical' set.
RISK_RAW_MIN = 7.7778
RISK_RAW_MAX = 92.3525


def _clamp_composite(value: Optional[float], label: str = "composite") -> float:
    """
    Coerce a Tier-1 composite index into a finite value on [0, 100].

    Non-finite (NaN / +/-inf) or non-numeric inputs are reported by the fuzzy
    antecedent membership functions as garbage and would silently corrupt the
    centroid, so they are replaced with the neutral midpoint of the universe and
    logged. Ordering is preserved for all finite inputs, so this guard is
    behaviour-preserving for well-formed scans.
    """
    try:
        numeric = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        logger.warning(
            "Non-numeric %s value %r supplied to the risk fusion; "
            "using the neutral midpoint %.1f.",
            label, value, COMPOSITE_NEUTRAL_VALUE,
        )
        return COMPOSITE_NEUTRAL_VALUE

    if math.isnan(numeric) or math.isinf(numeric):
        logger.warning(
            "Non-finite %s value %r supplied to the risk fusion; "
            "using the neutral midpoint %.1f.",
            label, value, COMPOSITE_NEUTRAL_VALUE,
        )
        return COMPOSITE_NEUTRAL_VALUE

    return max(0.0, min(100.0, numeric))


def build_posture_risk_system():
    """
    Construct and compile the Mamdani Tier 2 control system.
    """
    # Universes of discourse (0 to 100 for all composites and final risk)
    x_input = np.arange(0, 101, 0.5)
    x_risk = np.arange(0, 101, 0.5)

    cdi_in = ctrl.Antecedent(x_input, 'cdi')
    ped_in = ctrl.Antecedent(x_input, 'ped')
    eli_in = ctrl.Antecedent(x_input, 'eli')
    risk_out = ctrl.Consequent(x_risk, 'risk')

    # Fuzzification of Tier 1 Composites: Low, Moderate, High
    # Low: Trapezoidal plateau [0, 0, 20, 35]
    # Moderate: Triangular transition [25, 50, 75]
    # High: Trapezoidal plateau [65, 80, 100, 100]
    for antecedent in [cdi_in, ped_in, eli_in]:
        antecedent['low'] = fuzz.trapmf(x_input, [0, 0, 20, 35])
        antecedent['moderate'] = fuzz.trimf(x_input, [25, 50, 75])
        antecedent['high'] = fuzz.trapmf(x_input, [65, 80, 100, 100])

    # 5-Tier Output Consequent:
    # EXCELLENT (0-20), GOOD (20-40), ACCEPTABLE (40-60), POOR (60-80), CRITICAL (80-100)
    risk_out['excellent'] = fuzz.trapmf(x_risk, [0, 0, 10, 20])
    risk_out['good'] = fuzz.trimf(x_risk, [15, 30, 45])
    risk_out['acceptable'] = fuzz.trimf(x_risk, [40, 50, 60])
    risk_out['poor'] = fuzz.trimf(x_risk, [55, 70, 85])
    risk_out['critical'] = fuzz.trapmf(x_risk, [80, 90, 100, 100])

    # Rule base (12 rules)
    rules = [
        # Rule 1: All low composites -> EXCELLENT
        ctrl.Rule(cdi_in['low'] & ped_in['low'] & eli_in['low'], risk_out['excellent']),
        
        # Rules 2-4: Two low, one moderate -> GOOD
        ctrl.Rule(cdi_in['low'] & ped_in['low'] & eli_in['moderate'], risk_out['good']),
        ctrl.Rule(cdi_in['low'] & ped_in['moderate'] & eli_in['low'], risk_out['good']),
        ctrl.Rule(cdi_in['moderate'] & ped_in['low'] & eli_in['low'], risk_out['good']),
        
        # Rules 5-8: Moderate combinations -> ACCEPTABLE
        ctrl.Rule(cdi_in['moderate'] & ped_in['moderate'] & eli_in['moderate'], risk_out['acceptable']),
        ctrl.Rule(cdi_in['low'] & ped_in['moderate'] & eli_in['moderate'], risk_out['acceptable']),
        ctrl.Rule(cdi_in['moderate'] & ped_in['low'] & eli_in['moderate'], risk_out['acceptable']),
        ctrl.Rule(cdi_in['moderate'] & ped_in['moderate'] & eli_in['low'], risk_out['acceptable']),
        
        # Rules 9-11: Moderate and high combinations -> POOR
        ctrl.Rule(cdi_in['moderate'] & ped_in['high'] & eli_in['moderate'], risk_out['poor']),
        ctrl.Rule(cdi_in['high'] & ped_in['moderate'] & eli_in['moderate'], risk_out['poor']),
        ctrl.Rule(cdi_in['moderate'] & ped_in['moderate'] & eli_in['high'], risk_out['poor']),
        
        # Rule 12: CRITICAL TIER (OR across composites)
        # ==============================================================================
        # Design Choice: OR across composites ensures that any single severe weakness
        # (CDI High, PED High, or ELI High) is sufficient to trigger Critical Posture Deficit,
        # reflecting that one severe weakness shouldn't be diluted by two unrelated strengths.
        # ==============================================================================
        ctrl.Rule(cdi_in['high'] | ped_in['high'] | eli_in['high'], risk_out['critical']),
    ]

    system = ctrl.ControlSystem(rules)
    return system, (x_input, cdi_in), (x_input, ped_in), (x_input, eli_in), (x_risk, risk_out)


_RISK_SYSTEM, _CDI_FUSION, _PED_FUSION, _ELI_FUSION, _RISK_DATA = build_posture_risk_system()


def build_transport_unaudited_system():
    """
    Construct the Tier 2 fusion used when the TLS transport layer was never
    observed (no completed handshake: port 25 filtered, STARTTLS blocked, DNS
    unresolvable, or a degraded scan).

    Design intent — renormalisation over the observed dimensions:
        Absent telemetry is *not* evidence of catastrophic cryptography. Feeding
        empty strings into the CDI engine produces a worst-case CDI (86.04), and
        the Tier 2 non-dilution OR rule then promotes that artifact to a CRITICAL
        posture with score 0 — a fabricated finding about a mail exchanger the
        scan never reached. This system therefore fuses only the two composites
        that a DNS/HTTP-reachable scan genuinely observes:

            PED (SPF / DKIM / DMARC / DNSSEC records)  and
            ELI (published software vulnerabilities / exposure)

        The CDI dimension is excluded entirely rather than being pinned to a
        guessed value.

    Rule provenance:
        The three-axis base in ``build_posture_risk_system`` is structurally
        equivalent to "any High -> CRITICAL (non-diluting); two or more Moderate ->
        ACCEPTABLE; exactly one Moderate -> GOOD; all Low -> EXCELLENT". The rules
        below are that same structure projected onto the (PED, ELI) plane, so the
        tier semantics and the non-dilution guarantee are preserved. The
        membership functions and the 5-tier consequent are byte-identical to the
        three-axis system, so the defuzzified output shares that system's raw
        centroid bounds and is rescaled with the same constants.
    """
    x_input = np.arange(0, 101, 0.5)
    x_risk = np.arange(0, 101, 0.5)

    ped_in = ctrl.Antecedent(x_input, 'ped')
    eli_in = ctrl.Antecedent(x_input, 'eli')
    risk_out = ctrl.Consequent(x_risk, 'risk')

    for antecedent in [ped_in, eli_in]:
        antecedent['low'] = fuzz.trapmf(x_input, [0, 0, 20, 35])
        antecedent['moderate'] = fuzz.trimf(x_input, [25, 50, 75])
        antecedent['high'] = fuzz.trapmf(x_input, [65, 80, 100, 100])

    risk_out['excellent'] = fuzz.trapmf(x_risk, [0, 0, 10, 20])
    risk_out['good'] = fuzz.trimf(x_risk, [15, 30, 45])
    risk_out['acceptable'] = fuzz.trimf(x_risk, [40, 50, 60])
    risk_out['poor'] = fuzz.trimf(x_risk, [55, 70, 85])
    risk_out['critical'] = fuzz.trapmf(x_risk, [80, 90, 100, 100])

    rules = [
        # All observed composites Low -> EXCELLENT
        ctrl.Rule(ped_in['low'] & eli_in['low'], risk_out['excellent']),

        # Exactly one observed composite Moderate -> GOOD
        ctrl.Rule(ped_in['low'] & eli_in['moderate'], risk_out['good']),
        ctrl.Rule(ped_in['moderate'] & eli_in['low'], risk_out['good']),

        # Both observed composites Moderate -> ACCEPTABLE
        ctrl.Rule(ped_in['moderate'] & eli_in['moderate'], risk_out['acceptable']),

        # One Moderate + one High -> POOR
        ctrl.Rule(ped_in['moderate'] & eli_in['high'], risk_out['poor']),
        ctrl.Rule(ped_in['high'] & eli_in['moderate'], risk_out['poor']),

        # Non-dilution: any observed High -> CRITICAL, regardless of the other axis
        ctrl.Rule(ped_in['high'] | eli_in['high'], risk_out['critical']),
    ]

    system = ctrl.ControlSystem(rules)
    return system, (x_input, ped_in), (x_input, eli_in), (x_risk, risk_out)


_UNAUDITED_SYSTEM, _UNAUDITED_PED, _UNAUDITED_ELI, _UNAUDITED_RISK = build_transport_unaudited_system()


def _rescale_raw(raw: float) -> float:
    """Rescale a raw centroid from the shared consequent bounds onto [0, 100]."""
    if RISK_RAW_MAX == RISK_RAW_MIN:
        return COMPOSITE_NEUTRAL_VALUE
    scaled = (raw - RISK_RAW_MIN) / (RISK_RAW_MAX - RISK_RAW_MIN) * 100.0
    return max(0.0, min(100.0, scaled))


def _classify(final_score: float) -> str:
    """Map a fused risk score onto the 5-tier linguistic classification."""
    if final_score < 20.0:
        return 'EXCELLENT'
    if final_score < 40.0:
        return 'GOOD'
    if final_score < 60.0:
        return 'ACCEPTABLE'
    if final_score < 80.0:
        return 'POOR'
    return 'CRITICAL'


def compute_posture_risk_unobserved_transport(
    ped_score: float,
    eli_score: float,
) -> Tuple[float, str, Dict[str, Optional[float]], List[Dict]]:
    """
    Fuse posture risk when the TLS transport layer was never observed.

    Renormalises over the observed dimensions (PED + ELI) only. The four
    transport-derived antecedent scores are reported as ``None`` so consumers
    render "unobserved" instead of a fabricated grade, and the returned factors
    carry an explicit disclosure that the crypto dimension was excluded.

    Returns the same 4-tuple shape as :func:`compute_posture_risk`.
    """
    contributing_factors: List[Dict] = []

    ped_val = _clamp_composite(ped_score, 'ped_score')
    eli_val = _clamp_composite(eli_score, 'eli_score')

    x_input, ped_in = _UNAUDITED_PED
    _, eli_in = _UNAUDITED_ELI
    x_risk, risk_out = _UNAUDITED_RISK

    ped_mem = {
        'low': float(fuzz.interp_membership(x_input, ped_in['low'].mf, ped_val)),
        'moderate': float(fuzz.interp_membership(x_input, ped_in['moderate'].mf, ped_val)),
        'high': float(fuzz.interp_membership(x_input, ped_in['high'].mf, ped_val)),
    }
    eli_mem = {
        'low': float(fuzz.interp_membership(x_input, eli_in['low'].mf, eli_val)),
        'moderate': float(fuzz.interp_membership(x_input, eli_in['moderate'].mf, eli_val)),
        'high': float(fuzz.interp_membership(x_input, eli_in['high'].mf, eli_val)),
    }

    fired_rules: List[str] = []
    r_excellent = min(ped_mem['low'], eli_mem['low'])
    if r_excellent > 0.05:
        fired_rules.append(
            f"IF PED Low AND ELI Low THEN Risk EXCELLENT "
            f"[crypto axis unobserved — excluded from fusion] (activation: {r_excellent:.2f})"
        )
    r_good = max(
        min(ped_mem['low'], eli_mem['moderate']),
        min(ped_mem['moderate'], eli_mem['low']),
    )
    if r_good > 0.05:
        fired_rules.append(
            f"IF Exactly One Observed Composite Moderate THEN Risk GOOD (activation: {r_good:.2f})"
        )
    r_acceptable = min(ped_mem['moderate'], eli_mem['moderate'])
    if r_acceptable > 0.05:
        fired_rules.append(
            f"IF PED Moderate AND ELI Moderate THEN Risk ACCEPTABLE (activation: {r_acceptable:.2f})"
        )
    r_poor = max(
        min(ped_mem['moderate'], eli_mem['high']),
        min(ped_mem['high'], eli_mem['moderate']),
    )
    if r_poor > 0.05:
        fired_rules.append(
            f"IF One Observed Composite Moderate AND One High THEN Risk POOR (activation: {r_poor:.2f})"
        )
    r_critical = max(ped_mem['high'], eli_mem['high'])
    if r_critical > 0.05:
        fired_rules.append(
            f"IF PED High OR ELI High THEN Risk CRITICAL "
            f"[Design Choice: Non-dilution of critical failure] (activation: {r_critical:.2f})"
        )

    sim = ctrl.ControlSystemSimulation(_UNAUDITED_SYSTEM)
    sim.input['ped'] = ped_val
    sim.input['eli'] = eli_val

    final_score = RISK_FALLBACK_SCORE
    degraded = False
    degraded_reason = ""
    try:
        sim.compute()
        if 'risk' not in sim.output:
            raise ValueError(
                "transport-unaudited rule base activated zero rules for (ped, eli)"
            )
        final_score = _rescale_raw(float(sim.output['risk']))
    except Exception as e:
        degraded = True
        degraded_reason = f"{type(e).__name__}: {e}"
        final_score = RISK_FALLBACK_SCORE
        logger.warning(
            "Transport-unaudited fusion fell back to the constant default %.1f "
            "for ped_score=%s, eli_score=%s. Cause: %s",
            RISK_FALLBACK_SCORE, ped_val, eli_val, degraded_reason,
        )

    linguistic_classification = _classify(final_score)

    # Transport-derived antecedents are genuinely unknown: report them as such
    # rather than inventing a grade for a layer the scan never reached.
    antecedent_scores: Dict[str, Optional[float]] = {
        'tls_compliance': None,
        'cipher_strength': None,
        'certificate_health': None,
        'pqc_readiness': None,
        'email_auth_posture': round(max(0.0, min(1.0, 1.0 - (ped_val / 100.0))), 3),
        'exploitation_likelihood': round(max(0.0, min(1.0, eli_val / 100.0)), 3),
    }

    contributing_factors.append({
        'category': 'Tier 2 Fusion',
        'cdi_score': None,
        'ped_score': round(ped_val, 2),
        'eli_score': round(eli_val, 2),
        'final_risk_score': round(final_score, 2),
        'classification': linguistic_classification,
        'telemetry_observed': False,
        'membership_degrees': {'ped': ped_mem, 'eli': eli_mem},
        'fired_rules': fired_rules,
    })

    contributing_factors.append({
        'category': 'Engine Integrity',
        'degraded': degraded,
        'metric': 'posture_risk',
        'reason': degraded_reason,
        'note': (
            "TLS transport telemetry was not observed for this scan, so the Crypto "
            "Deprecation Index was excluded and the fused score was renormalised "
            "over the observed dimensions (Email Authentication + Exploitation "
            "Likelihood). No cryptographic conclusion is asserted for this target."
        ),
    })

    for r in fired_rules:
        contributing_factors.append({
            'category': 'Fired Rules',
            'description': r,
        })

    return final_score, linguistic_classification, antecedent_scores, contributing_factors


def compute_posture_risk(
    cdi_score: float,
    ped_score: float,
    eli_score: float,
    raw_crypto_metrics: Optional[Dict] = None
) -> Tuple[float, str, Dict[str, float], List[Dict]]:
    """
    Compute final Posture Risk Index using Tier 2 Mamdani fuzzy logic fusion.
    
    Args:
        cdi_score: Crypto Deprecation Index (0-100)
        ped_score: Posture Exposure Deficit (0-100)
        eli_score: Exploitation Likelihood Index (0-100)
        raw_crypto_metrics: Optional dictionary containing normalized metrics
    
    Returns:
        Tuple of (
            final_score: float [0-100],
            linguistic_classification: str (EXCELLENT | GOOD | ACCEPTABLE | POOR | CRITICAL),
            antecedent_scores: dict with individual antecedent values [0-1],
            contributing_factors: list[dict] with fired rules and membership degrees
        )
    """
    contributing_factors = []

    # Coerce NaN / +/-inf / None / non-numeric composites to the neutral midpoint
    # and clamp everything else to [0, 100]. Without the guard a non-finite value
    # propagates through the membership functions and corrupts the centroid.
    cdi_val = _clamp_composite(cdi_score, 'cdi_score')
    ped_val = _clamp_composite(ped_score, 'ped_score')
    eli_val = _clamp_composite(eli_score, 'eli_score')

    # Universes & antecedents
    x_input, cdi_in = _CDI_FUSION
    _, ped_in = _PED_FUSION
    _, eli_in = _ELI_FUSION
    x_risk, risk_out = _RISK_DATA

    # Compute manual membership degrees for explainability
    cdi_mem = {
        'low': float(fuzz.interp_membership(x_input, cdi_in['low'].mf, cdi_val)),
        'moderate': float(fuzz.interp_membership(x_input, cdi_in['moderate'].mf, cdi_val)),
        'high': float(fuzz.interp_membership(x_input, cdi_in['high'].mf, cdi_val))
    }
    ped_mem = {
        'low': float(fuzz.interp_membership(x_input, ped_in['low'].mf, ped_val)),
        'moderate': float(fuzz.interp_membership(x_input, ped_in['moderate'].mf, ped_val)),
        'high': float(fuzz.interp_membership(x_input, ped_in['high'].mf, ped_val))
    }
    eli_mem = {
        'low': float(fuzz.interp_membership(x_input, eli_in['low'].mf, eli_val)),
        'moderate': float(fuzz.interp_membership(x_input, eli_in['moderate'].mf, eli_val)),
        'high': float(fuzz.interp_membership(x_input, eli_in['high'].mf, eli_val))
    }

    # Evaluate rule firing strengths
    fired_rules = []
    r1_strength = min(cdi_mem['low'], ped_mem['low'], eli_mem['low'])
    if r1_strength > 0.05:
        fired_rules.append(f"IF CDI Low AND PED Low AND ELI Low THEN Risk EXCELLENT (activation: {r1_strength:.2f})")

    r_good1 = min(cdi_mem['low'], ped_mem['low'], eli_mem['moderate'])
    r_good2 = min(cdi_mem['low'], ped_mem['moderate'], eli_mem['low'])
    r_good3 = min(cdi_mem['moderate'], ped_mem['low'], eli_mem['low'])
    max_good = max(r_good1, r_good2, r_good3)
    if max_good > 0.05:
        fired_rules.append(f"IF Two Composites Low AND One Moderate THEN Risk GOOD (activation: {max_good:.2f})")

    r_acc = min(cdi_mem['moderate'], ped_mem['moderate'], eli_mem['moderate'])
    if r_acc > 0.05:
        fired_rules.append(f"IF CDI Moderate AND PED Moderate AND ELI Moderate THEN Risk ACCEPTABLE (activation: {r_acc:.2f})")

    # Critical OR rule firing:
    r_crit_or = max(cdi_mem['high'], ped_mem['high'], eli_mem['high'])
    if r_crit_or > 0.05:
        fired_rules.append(
            f"IF CDI High OR PED High OR ELI High THEN Risk CRITICAL "
            f"[Design Choice: Non-dilution of critical failure] (activation: {r_crit_or:.2f})"
        )

    # Mamdani inference
    sim = ctrl.ControlSystemSimulation(_RISK_SYSTEM)
    sim.input['cdi'] = cdi_val
    sim.input['ped'] = ped_val
    sim.input['eli'] = eli_val

    try:
        sim.compute()
        if 'risk' not in sim.output:
            raise ValueError(
                "Tier 2 rule base activated zero rules for this composite tuple"
            )
        # Rescale the raw centroid onto [0, 100]. The bounds are the defuzzified
        # centroids of the extreme consequent sets:
        #   RAW_MIN = 'excellent' [0, 0, 10, 20]  -> 7.7778
        #   RAW_MAX = 'critical'  [80, 90, 100, 100] -> 92.3525
        final_score = _rescale_raw(float(sim.output['risk']))
    except Exception as e:
        logger.warning(
            "Tier 2 fusion fell back to the constant default %.1f "
            "for cdi_score=%s, ped_score=%s, eli_score=%s. Cause: %s: %s",
            RISK_FALLBACK_SCORE, cdi_val, ped_val, eli_val, type(e).__name__, e,
        )
        final_score = RISK_FALLBACK_SCORE

    linguistic_classification = _classify(final_score)

    # Compute normalized antecedent scores (0.0 to 1.0) strictly matching Step 6 contract
    crypto_meta = raw_crypto_metrics or {}
    
    # 1. tls_compliance: 0-1 derived from TLS version component
    tls_comp = crypto_meta.get('tls_compliance', 1.0 - (cdi_val / 100.0))
    # 2. cipher_strength: 0-1 derived from cipher component
    ciph_str = crypto_meta.get('cipher_strength', 1.0 - (cdi_val / 100.0))
    # 3. certificate_health: 0-1 derived from cert freshness component
    cert_hlth = crypto_meta.get('certificate_health', 1.0 - (cdi_val / 100.0))
    
    # 4. pqc_readiness: v1 placeholder
    # ==============================================================================
    # pqc_readiness v1 — placeholder pending real hybrid key-exchange group detection;
    # documented as future work.
    # ==============================================================================
    pqc_readiness = crypto_meta.get('pqc_readiness', 0.5)
    
    # 5. email_auth_posture: 0-1 (PED inverted: low deficit = strong posture)
    email_auth_posture = max(0.0, min(1.0, 1.0 - (ped_val / 100.0)))
    
    # 6. exploitation_likelihood: 0-1 (ELI direct: 0 = low likelihood, 1 = high)
    exploitation_likelihood = max(0.0, min(1.0, eli_val / 100.0))

    antecedent_scores = {
        'tls_compliance': round(float(tls_comp), 3),
        'cipher_strength': round(float(ciph_str), 3),
        'certificate_health': round(float(cert_hlth), 3),
        'pqc_readiness': round(float(pqc_readiness), 3),
        'email_auth_posture': round(float(email_auth_posture), 3),
        'exploitation_likelihood': round(float(exploitation_likelihood), 3),
    }

    # Log Tier 2 contributing factors
    contributing_factors.append({
        'category': 'Tier 2 Fusion',
        'cdi_score': round(cdi_val, 2),
        'ped_score': round(ped_val, 2),
        'eli_score': round(eli_val, 2),
        'final_risk_score': round(final_score, 2),
        'classification': linguistic_classification,
        'membership_degrees': {
            'cdi': cdi_mem,
            'ped': ped_mem,
            'eli': eli_mem
        },
        'fired_rules': fired_rules
    })

    for r in fired_rules:
        contributing_factors.append({
            'category': 'Fired Rules',
            'description': r
        })

    return final_score, linguistic_classification, antecedent_scores, contributing_factors
