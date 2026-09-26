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

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from typing import Dict, List, Tuple, Optional


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
    
    # Clamp input scores to [0, 100]
    cdi_val = float(min(100.0, max(0.0, cdi_score)))
    ped_val = float(min(100.0, max(0.0, ped_score)))
    eli_val = float(min(100.0, max(0.0, eli_score)))

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
        raw_score = float(sim.output['risk'])
        
        # Rescale raw score to full [0, 100] range
        # Empirically determined bounds from actual rule base centroid defuzzification limits:
        # Min raw centroid (Rule 1 -> 'excellent' [0, 0, 10, 20]): 7.7778
        # Max raw centroid (Rule 12 -> 'critical' [80, 90, 100, 100]): 92.3525
        RAW_MIN = 7.7778
        RAW_MAX = 92.3525
        
        # Linear rescale with clamping to [0, 100]
        def rescale_score(raw: float, raw_min: float, raw_max: float) -> float:
            """Rescale raw fuzzy output to [0, 100] range."""
            if raw_max == raw_min:
                return 50.0  # Avoid division by zero
            scaled = (raw - raw_min) / (raw_max - raw_min) * 100.0
            return max(0.0, min(100.0, scaled))
        
        final_score = rescale_score(raw_score, RAW_MIN, RAW_MAX)
    except Exception:
        final_score = 50.0

    # 5-Tier linguistic classification based on score thresholds
    if final_score < 20.0:
        linguistic_classification = 'EXCELLENT'
    elif final_score < 40.0:
        linguistic_classification = 'GOOD'
    elif final_score < 60.0:
        linguistic_classification = 'ACCEPTABLE'
    elif final_score < 80.0:
        linguistic_classification = 'POOR'
    else:
        linguistic_classification = 'CRITICAL'

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
