"""
Posture Exposure Deficit (PED) - Tier 1 Fuzzy Inference System

Computes a 0-100 score representing email authentication posture exposure based on:
- SPF presence (bool, fuzzified as step function)
- DKIM presence (bool, fuzzified as step function)
- DMARC policy strictness (ordinal 0/1/2: None/Partial/Full enforcement)
- DNSSEC enabled (bool, fuzzified as step function)

Uses Mamdani fuzzy inference with steep trapezoidal step functions for boolean inputs,
trapezoidal plateau for None/Full, and triangular for Partial DMARC enforcement.

Reference Standards:
- RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email
- RFC 6376: DomainKeys Identified Mail (DKIM) Signatures
- RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 4033, 4034, 4035: DNS Security Extensions (DNSSEC)
"""

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from typing import Dict, List, Tuple, Optional


def classify_dmarc_policy(policy: str, enforcement: str) -> int:
    """
    Classify DMARC policy strictness as ordinal value per RFC 7489:
    - 0: None (p=none, monitoring only, spoofing unmitigated)
    - 1: Partial (p=quarantine, messages placed in spam/quarantine)
    - 2: Full (p=reject, unauthenticated messages strictly rejected)
    """
    if not policy and not enforcement:
        return 0
    
    policy_lower = policy.lower() if policy else ''
    enforcement_lower = enforcement.lower() if enforcement else ''
    
    # Check for reject (full enforcement)
    if 'p=reject' in policy_lower or 'reject' in enforcement_lower:
        return 2
    
    # Check for quarantine (partial enforcement)
    if 'p=quarantine' in policy_lower or 'quarantine' in enforcement_lower:
        return 1
    
    # Monitoring only (p=none)
    return 0


def build_ped_control_system():
    """
    Construct and compile the Mamdani control system for Posture Exposure Deficit (PED).
    """
    # Universes of discourse
    x_bool = np.arange(0, 1.05, 0.05)      # 0=absent/disabled, 1=present/enabled
    x_dmarc = np.arange(0, 2.05, 0.05)     # 0=none, 1=partial, 2=full
    x_ped = np.arange(0, 101, 0.5)         # 0-100 PED score (0=low exposure, 100=high)

    # Antecedents & Consequent
    spf_input = ctrl.Antecedent(x_bool, 'spf')
    dkim_input = ctrl.Antecedent(x_bool, 'dkim')
    dmarc_input = ctrl.Antecedent(x_dmarc, 'dmarc')
    dnssec_input = ctrl.Antecedent(x_bool, 'dnssec')
    ped_output = ctrl.Consequent(x_ped, 'ped')

    # Step-like membership functions for boolean inputs (steep transitions around 0.5)
    spf_input['absent'] = fuzz.trapmf(x_bool, [0, 0, 0.2, 0.5])
    spf_input['present'] = fuzz.trapmf(x_bool, [0.5, 0.8, 1.0, 1.0])

    dkim_input['absent'] = fuzz.trapmf(x_bool, [0, 0, 0.2, 0.5])
    dkim_input['present'] = fuzz.trapmf(x_bool, [0.5, 0.8, 1.0, 1.0])

    dnssec_input['disabled'] = fuzz.trapmf(x_bool, [0, 0, 0.2, 0.5])
    dnssec_input['enabled'] = fuzz.trapmf(x_bool, [0.5, 0.8, 1.0, 1.0])

    # DMARC Ordinal Membership:
    # 0=none (trapezoidal plateau), 1=partial (triangular transition), 2=full (trapezoidal plateau)
    dmarc_input['none'] = fuzz.trapmf(x_dmarc, [0, 0, 0.4, 0.9])
    dmarc_input['partial'] = fuzz.trimf(x_dmarc, [0.5, 1.0, 1.5])
    dmarc_input['full'] = fuzz.trapmf(x_dmarc, [1.1, 1.6, 2.0, 2.0])

    # Output: PED (0=resilient posture / low deficit, 100=critical exposure)
    ped_output['low'] = fuzz.trapmf(x_ped, [0, 0, 15, 35])
    ped_output['moderate'] = fuzz.trimf(x_ped, [25, 50, 75])
    ped_output['high'] = fuzz.trapmf(x_ped, [65, 80, 100, 100])

    rules = [
        # Full defense: SPF + DKIM + DMARC reject + DNSSEC -> Low exposure
        ctrl.Rule(spf_input['present'] & dkim_input['present'] & dmarc_input['full'] & dnssec_input['enabled'], ped_output['low']),
        ctrl.Rule(spf_input['present'] & dkim_input['present'] & dmarc_input['full'] & dnssec_input['disabled'], ped_output['low']),
        ctrl.Rule(spf_input['present'] & dkim_input['present'] & dmarc_input['partial'] & dnssec_input['enabled'], ped_output['low']),
        
        # Missing DMARC enforcement (p=none or absent) leaves domain vulnerable to impersonation
        ctrl.Rule(dmarc_input['none'], ped_output['high']),
        
        # Partial DMARC without DNSSEC -> Moderate exposure
        ctrl.Rule(spf_input['present'] & dkim_input['present'] & dmarc_input['partial'] & dnssec_input['disabled'], ped_output['moderate']),
        
        # Missing SPF or DKIM -> Moderate to High exposure
        ctrl.Rule(spf_input['absent'] & dkim_input['present'], ped_output['moderate']),
        ctrl.Rule(spf_input['present'] & dkim_input['absent'], ped_output['moderate']),
        ctrl.Rule(spf_input['absent'] & dkim_input['absent'], ped_output['high']),
        
        # Compounded failure: Missing authentication records
        ctrl.Rule(spf_input['absent'] & dmarc_input['none'], ped_output['high']),
        ctrl.Rule(dkim_input['absent'] & dmarc_input['none'], ped_output['high']),
        ctrl.Rule(spf_input['absent'] & dkim_input['absent'] & dmarc_input['none'], ped_output['high']),
    ]

    system = ctrl.ControlSystem(rules)
    return system, (x_bool, spf_input), (x_bool, dkim_input), (x_dmarc, dmarc_input), (x_bool, dnssec_input), (x_ped, ped_output)


_PED_SYSTEM, _SPF_DATA, _DKIM_DATA, _DMARC_DATA, _DNSSEC_DATA, _PED_DATA = build_ped_control_system()


def compute_posture_exposure_deficit(
    spf_present: bool,
    dkim_present: bool,
    dmarc_policy: str,
    dmarc_enforcement: str,
    dnssec_enabled: bool
) -> Tuple[float, List[Dict]]:
    """
    Compute Posture Exposure Deficit (PED) using Mamdani fuzzy logic inference.
    
    Args:
        spf_present: Whether SPF record is present and syntactically valid (RFC 7208)
        dkim_present: Whether DKIM selector record is discovered and valid (RFC 6376)
        dmarc_policy: DMARC record policy string (e.g. "v=DMARC1; p=reject")
        dmarc_enforcement: DMARC enforcement tag ("reject", "quarantine", "monitoring only")
        dnssec_enabled: Whether DNSSEC cryptographic chain of trust is validated (RFC 4033)
    
    Returns:
        Tuple of (composite_score: float [0-100], contributing_factors: list[dict])
    """
    contributing_factors = []
    
    # Classify inputs
    dmarc_ordinal = classify_dmarc_policy(dmarc_policy, dmarc_enforcement)
    dmarc_label = {0: 'none', 1: 'partial', 2: 'full'}[dmarc_ordinal]

    spf_num = 1.0 if spf_present else 0.0
    dkim_num = 1.0 if dkim_present else 0.0
    dmarc_num = float(dmarc_ordinal)
    dnssec_num = 1.0 if dnssec_enabled else 0.0

    # Retrieve universes & antecedents
    x_bool, spf_in = _SPF_DATA
    _, dkim_in = _DKIM_DATA
    x_dmarc, dmarc_in = _DMARC_DATA
    _, dnssec_in = _DNSSEC_DATA

    # Compute manual memberships
    spf_mem = {
        'absent': float(fuzz.interp_membership(x_bool, spf_in['absent'].mf, spf_num)),
        'present': float(fuzz.interp_membership(x_bool, spf_in['present'].mf, spf_num))
    }
    dkim_mem = {
        'absent': float(fuzz.interp_membership(x_bool, dkim_in['absent'].mf, dkim_num)),
        'present': float(fuzz.interp_membership(x_bool, dkim_in['present'].mf, dkim_num))
    }
    dmarc_mem = {
        'none': float(fuzz.interp_membership(x_dmarc, dmarc_in['none'].mf, dmarc_num)),
        'partial': float(fuzz.interp_membership(x_dmarc, dmarc_in['partial'].mf, dmarc_num)),
        'full': float(fuzz.interp_membership(x_dmarc, dmarc_in['full'].mf, dmarc_num))
    }
    dnssec_mem = {
        'disabled': float(fuzz.interp_membership(x_bool, dnssec_in['disabled'].mf, dnssec_num)),
        'enabled': float(fuzz.interp_membership(x_bool, dnssec_in['enabled'].mf, dnssec_num))
    }

    # Evaluate fired rule activations
    r_full_defense = min(spf_mem['present'], dkim_mem['present'], dmarc_mem['full'])
    r_dmarc_none = dmarc_mem['none']
    r_partial = min(spf_mem['present'], dkim_mem['present'], dmarc_mem['partial'])
    r_spf_absent = spf_mem['absent']
    r_dkim_absent = dkim_mem['absent']
    r_all_absent = min(spf_mem['absent'], dkim_mem['absent'], dmarc_mem['none'])

    fired_rules = []
    if r_full_defense > 0.05:
        fired_rules.append(f"IF SPF Present AND DKIM Present AND DMARC Full THEN PED Low (activation: {r_full_defense:.2f})")
    if r_partial > 0.05:
        fired_rules.append(f"IF SPF Present AND DKIM Present AND DMARC Partial THEN PED Moderate (activation: {r_partial:.2f})")
    if r_dmarc_none > 0.05:
        fired_rules.append(f"IF DMARC None (Unenforced) THEN PED High (activation: {r_dmarc_none:.2f})")
    if r_spf_absent > 0.05:
        fired_rules.append(f"IF SPF Absent THEN PED Moderate/High (activation: {r_spf_absent:.2f})")
    if r_dkim_absent > 0.05:
        fired_rules.append(f"IF DKIM Absent THEN PED Moderate/High (activation: {r_dkim_absent:.2f})")
    if r_all_absent > 0.05:
        fired_rules.append(f"IF SPF Absent AND DKIM Absent AND DMARC None THEN PED Critical High (activation: {r_all_absent:.2f})")

    contributing_factors.append({
        'category': 'Antecedent Evaluation',
        'spf': {'present': spf_present, 'membership': spf_mem},
        'dkim': {'present': dkim_present, 'membership': dkim_mem},
        'dmarc': {'policy': dmarc_policy, 'level': dmarc_label, 'membership': dmarc_mem},
        'dnssec': {'enabled': dnssec_enabled, 'membership': dnssec_mem},
        'fired_rules': fired_rules
    })

    # Run Mamdani simulation
    sim = ctrl.ControlSystemSimulation(_PED_SYSTEM)
    sim.input['spf'] = spf_num
    sim.input['dkim'] = dkim_num
    sim.input['dmarc'] = dmarc_num
    sim.input['dnssec'] = dnssec_num

    try:
        sim.compute()
        ped_score = float(sim.output['ped'])
    except Exception:
        ped_score = 50.0

    for r in fired_rules:
        contributing_factors.append({
            'category': 'Fired Rules',
            'description': r
        })

    return ped_score, contributing_factors
