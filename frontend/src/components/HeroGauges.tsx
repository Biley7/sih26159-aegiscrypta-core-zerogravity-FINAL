import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { FindingSeverity, ScanResponse } from '../types';

interface HeroGaugesProps {
  data: ScanResponse;
  onSelectSeverity?: (sev: FindingSeverity | 'ALL') => void;
  selectedSeverity?: FindingSeverity | 'ALL';
}

export const HeroGauges: React.FC<HeroGaugesProps> = ({
  data,
  onSelectSeverity,
  selectedSeverity
}) => {
  const score = Math.max(0, Math.min(100, data.score));

  // Grade calculation with exact semantic mappings
  const getGradeInfo = (score: number) => {
    if (score >= 90) return { grade: 'A+', label: 'POSTURE HARDENED', color: '#10b981', ringClass: 'ring-emerald' };
    if (score >= 80) return { grade: 'A', label: 'STRONGLY DEFENDED', color: '#10b981', ringClass: 'ring-emerald' };
    if (score >= 65) return { grade: 'B', label: 'MODERATE EXPOSURE', color: '#f59e0b', ringClass: 'ring-amber' };
    if (score >= 50) return { grade: 'C', label: 'ELEVATED RISK', color: '#f59e0b', ringClass: 'ring-amber' };
    return { grade: 'F', label: 'CRITICAL FAILURE', color: '#f43f5e', ringClass: 'ring-rose' };
  };

  const gradeInfo = getGradeInfo(score);

  // SVG circular gauge math
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Counts of findings
  const findings = data.prioritized_findings || [];
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  // PQC analysis from cipher and host data
  const hasPqc = data.crypto_posture?.protocols_audited.some((p) => {
    const kx = (p.tls_handshake?.cipher?.key_exchange || '').toLowerCase();
    const cName = (p.tls_handshake?.cipher?.name || '').toLowerCase();
    return kx.includes('kyber') || kx.includes('ml-kem') || cName.includes('kyber') || cName.includes('mlkem');
  });

  // Transport checks
  const mtaStsCheck = data.checks.find((c) => c.name === 'MTA-STS');
  const daneCheck = data.checks.find((c) => c.name.includes('DANE') || c.name.includes('TLSA'));
  const mxCheck = data.checks.find((c) => c.name.includes('STARTTLS') || c.name === 'MX & STARTTLS');

  const starttlsActive = data.crypto_posture?.protocols_audited.some(
    (p) => p.starttls_negotiated
  ) ?? (mxCheck?.status === 'pass' || mxCheck?.status === 'warn');

  // Case-insensitive check handling both 'TLSv1.3' and 'TLS 1.3'
  const tls13Active = data.crypto_posture?.protocols_audited.some((p) => {
    const ver = (p.tls_handshake?.negotiated_version || '').toLowerCase();
    return ver === 'tlsv1.3' || ver === 'tls 1.3';
  });

  return (
    <div className="security-posture-block">
      {/* Primary Scorecard */}
      <div className="scorecard-primary">
        <div className="scorecard-header">
          <div className="scorecard-title-group">
            <ShieldCheck size={14} className="text-soc-secure" />
            <h3 className="scorecard-title">Security Posture</h3>
          </div>
          <span className="scorecard-domain font-mono">{data.domain}</span>
        </div>

        <div className="scorecard-body">
          <div className="score-gauge">
            <svg className="gauge-svg" width="80" height="80" viewBox="0 0 100 100">
              <circle
                className="gauge-bg"
                cx="50"
                cy="50"
                r={radius}
                strokeWidth="6"
                fill="transparent"
              />
              <circle
                className="gauge-progress"
                cx="50"
                cy="50"
                r={radius}
                strokeWidth="6"
                stroke={gradeInfo.color}
                fill="transparent"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
              />
            </svg>
            <div className="gauge-center">
              <span className="gauge-score font-mono">{score}</span>
              <span className="gauge-max">/100</span>
            </div>
          </div>

          <div className="scorecard-meta">
            <div className="grade-display">
              <span className={`grade-badge ${gradeInfo.ringClass}`}>
                {gradeInfo.grade}
              </span>
              <span className="grade-label">{gradeInfo.label}</span>
            </div>
            <div className="scorecard-details font-mono text-xs text-text-secondary">
              <span>{new Date(data.scanned_at).toLocaleTimeString()}</span>
              <span className="text-text-muted">NIST SP 800-52r2</span>
            </div>
          </div>
        </div>
      </div>

      {/* Key Findings */}
      <div className="findings-block">
        <h4 className="findings-heading">Key Findings</h4>
        <div className="findings-grid">
          <div className="finding-item critical">
            <span className="finding-count font-mono">{criticalCount}</span>
            <span className="finding-label">Critical</span>
          </div>
          <div className="finding-item high">
            <span className="finding-count font-mono">{highCount}</span>
            <span className="finding-label">High</span>
          </div>
          <div className="finding-item medium">
            <span className="finding-count font-mono">{mediumCount}</span>
            <span className="finding-label">Medium</span>
          </div>
          <div className="finding-item low">
            <span className="finding-count font-mono">{lowCount}</span>
            <span className="finding-label">Low</span>
          </div>
        </div>
      </div>

      {/* Transport Security */}
      <div className="transport-block">
        <h4 className="transport-heading">Transport Security</h4>
        <div className="transport-checks">
          <div className="transport-check">
            <span className="check-label">STARTTLS</span>
            <span className={`check-status ${starttlsActive ? 'secure' : 'critical'}`}>
              {starttlsActive ? 'Enforced' : 'Missing'}
            </span>
          </div>
          <div className="transport-check">
            <span className="check-label">MTA-STS</span>
            <span className={`check-status ${mtaStsCheck?.status === 'pass' ? 'secure' : 'warning'}`}>
              {mtaStsCheck?.status === 'pass' ? 'Enforce' : 'Missing'}
            </span>
          </div>
          <div className="transport-check">
            <span className="check-label">DANE/TLSA</span>
            <span className={`check-status ${daneCheck?.status === 'pass' ? 'secure' : 'critical'}`}>
              {daneCheck?.status === 'pass' ? 'Verified' : 'Unpublished'}
            </span>
          </div>
        </div>
      </div>

      {/* PQC Status */}
      <div className="pqc-block">
        <h4 className="pqc-heading">Post-Quantum Ready</h4>
        <div className="pqc-status">
          <span className={`pqc-indicator ${hasPqc ? 'ready' : 'at-risk'}`}>
            {hasPqc ? 'ML-KEM Hybrid' : 'Classical Only'}
          </span>
          <div className="pqc-bar">
            <div 
              className={`pqc-bar-fill ${hasPqc ? 'ready' : 'partial'}`}
              style={{ width: hasPqc ? '95%' : '45%' }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
