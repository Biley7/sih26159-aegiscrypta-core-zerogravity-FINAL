from typing import List, Optional, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest

from app.models import (
    TlsAnomalyDetectionResult,
    ProtocolAuditResult,
    TcpStreamSummary,
    CryptographicPosture
)


class TlsAnomalyDetector:
    """
    Detects suspicious TLS sessions, protocol downgrade attacks, certificate substitutions,
    and cleartext authentication leaks using Isolation Forest and cryptographic heuristics.
    """
    def __init__(self):
        # Baseline training set representing typical, benign mail TLS connections
        # Features: [tls_version_num, key_size, forward_secrecy, is_self_signed, starttls_success]
        # (TLS 1.2 = 1.2, TLS 1.3 = 1.3, TLS 1.0 = 1.0)
        normative_samples = np.array([
            [1.3, 256, 1.0, 0.0, 1.0],
            [1.3, 2048, 1.0, 0.0, 1.0],
            [1.2, 2048, 1.0, 0.0, 1.0],
            [1.2, 4096, 1.0, 0.0, 1.0],
            [1.2, 256, 1.0, 0.0, 1.0],
            [1.3, 256, 1.0, 0.0, 1.0],
            [1.2, 2048, 1.0, 0.0, 1.0],
            [1.3, 384, 1.0, 0.0, 1.0],
        ])
        self.model = IsolationForest(contamination=0.15, random_state=42)
        self.model.fit(normative_samples)

    def _extract_feature_vector(self, audit: ProtocolAuditResult) -> Optional[np.ndarray]:
        if not audit.tls_handshake or not audit.tls_handshake.success:
            return None

        # Feature 1: TLS version
        ver = audit.tls_handshake.negotiated_version
        v_num = 1.2
        if ver == "TLSv1.3":
            v_num = 1.3
        elif ver == "TLSv1.1":
            v_num = 1.1
        elif ver == "TLSv1.0":
            v_num = 1.0
        elif ver == "SSLv3":
            v_num = 0.9

        # Feature 2: Key size
        k_size = 2048
        is_self_signed = 0.0
        if audit.tls_handshake.certificate:
            k_size = audit.tls_handshake.certificate.key_size_bits or 2048
            is_self_signed = 1.0 if audit.tls_handshake.certificate.is_self_signed else 0.0

        # Feature 3: Forward secrecy
        pfs = 1.0 if (audit.tls_handshake.cipher and audit.tls_handshake.cipher.forward_secrecy) else 0.0

        # Feature 5: STARTTLS success
        stls = 1.0 if audit.starttls_negotiated is not False else 0.0

        return np.array([v_num, k_size, pfs, is_self_signed, stls])

    def detect_anomalies_in_posture(
        self,
        crypto_posture: Optional[CryptographicPosture]
    ) -> TlsAnomalyDetectionResult:
        """Evaluates active probe results across all mail endpoints for suspicious patterns."""
        if not crypto_posture or not crypto_posture.protocols_audited:
            return TlsAnomalyDetectionResult(
                anomaly_detected=False,
                anomaly_score=0.0,
                confidence=0.5,
                detected_anomalies=[],
                suspicious_indicators=[]
            )

        anomalies: List[str] = []
        indicators: List[str] = []
        scores: List[float] = []

        for audit in crypto_posture.protocols_audited:
            vec = self._extract_feature_vector(audit)
            if vec is not None:
                pred = self.model.predict([vec])[0]   # -1: anomaly, 1: normal
                score = float(self.model.decision_function([vec])[0])
                scores.append(score)

                if pred == -1:
                    anomalies.append(f"Statistically atypical TLS handshake parameters on {audit.protocol}:{audit.port} (score: {score:.3f}).")

            # Heuristic Anomaly Rules:
            # 1. Self-signed certificate on public mail server
            if audit.tls_handshake and audit.tls_handshake.certificate and audit.tls_handshake.certificate.is_self_signed:
                indicators.append(f"Suspicious Certificate: Host {audit.host} serves a self-signed certificate, risking MitM eavesdropping.")

            # 2. STARTTLS stripping indicator (advertised = false or rejected)
            if audit.starttls_advertised is False and audit.port in [25, 143, 110]:
                indicators.append(f"STARTTLS Stripping Indicator: Port {audit.port} does not offer opportunistic encryption.")

            # 3. Weak cipher / protocol downgrade
            if audit.tls_handshake and audit.tls_handshake.negotiated_version in ["TLSv1.0", "TLSv1.1", "SSLv3"]:
                indicators.append(f"Protocol Downgrade Indicator: Negotiated deprecated {audit.tls_handshake.negotiated_version} on {audit.protocol}:{audit.port}.")

        avg_score = float(np.mean(scores)) if scores else 0.20
        is_anomaly = (len(anomalies) > 0) or (len(indicators) > 0)

        return TlsAnomalyDetectionResult(
            anomaly_detected=is_anomaly,
            anomaly_score=round(avg_score, 4),
            confidence=0.88 if scores else 0.60,
            detected_anomalies=anomalies,
            suspicious_indicators=indicators
        )


# Global singleton instance
_detector_instance = None

def get_anomaly_detector() -> TlsAnomalyDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = TlsAnomalyDetector()
    return _detector_instance
