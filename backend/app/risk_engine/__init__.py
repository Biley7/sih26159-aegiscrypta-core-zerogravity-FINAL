"""
AegisCrypta Risk Engine - Hierarchical Fuzzy Logic Risk Scoring System

This module implements a two-tier fuzzy inference system for email security posture assessment:
- Tier 1: Composite indices (CDI, PED, ELI) based on raw check data
- Tier 2: Final fusion producing overall posture risk score with linguistic classification

Uses scikit-fuzzy (skfuzzy) for Mamdani fuzzy inference systems.
"""

from .crypto_deprecation import compute_crypto_deprecation_index
from .posture_exposure import compute_posture_exposure_deficit
from .exploitation_likelihood import compute_exploitation_likelihood_index
from .posture_risk import compute_posture_risk

__all__ = [
    'compute_crypto_deprecation_index',
    'compute_posture_exposure_deficit',
    'compute_exploitation_likelihood_index',
    'compute_posture_risk'
]
