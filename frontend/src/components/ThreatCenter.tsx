import React, { useState } from 'react';
import {
  CheckCircle2,
  Cpu,
  UserCheck,
  FileKey2,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Layers
} from 'lucide-react';
import { CvssMetrics, ScanResponse } from '../types';

interface ThreatCenterProps {
  className?: string;
  score?: number | null; // 0 to 100 (posture score); null when no scan has completed
  scanData?: ScanResponse | null;
  domain?: string;
  fuzzyScore?: number | null;
  linguisticClassification?: 'EXCELLENT' | 'GOOD' | 'ACCEPTABLE' | 'POOR' | 'CRITICAL';
  antecedentScores?: {
    tls_compliance: number;
    cipher_strength: number;
    certificate_health: number;
    pqc_readiness: number;
    email_auth_posture: number;
    exploitation_likelihood: number;
  };
  activatedRules?: string[];
  defuzzificationConfidence?: number;
  cvssMetrics?: CvssMetrics;
  onOpenReportModal?: () => void;
  onSelectCredentialNode?: (nodeId: string) => void;
  onOpenAiFindings?: () => void;
}

export const ThreatCenter: React.FC<ThreatCenterProps> = ({
  className = '',
  score = null,
  scanData,
  domain = 'gmail.com',
  fuzzyScore,
  linguisticClassification,
  antecedentScores,
  activatedRules,
  defuzzificationConfidence,
  cvssMetrics,
  onOpenReportModal,
  onSelectCredentialNode,
  onOpenAiFindings
}) => {
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [showRules, setShowRules] = useState(false);
  const activeScore = scanData?.security_score ?? scanData?.score ?? score ?? null;
  const primaryCert = scanData?.crypto_posture?.protocols_audited?.[0]?.tls_handshake?.certificate ?? null;
  const certificateExpiry = primaryCert?.valid_until ?? primaryCert?.valid_to;
  const dkimCheck = scanData?.checks?.find((c) => c.name.toLowerCase().includes('dkim')) ?? null;
  const mtaStsCheck = scanData?.checks?.find((c) => c.name.toLowerCase().includes('mta-sts')) ?? null;
  const pqcEvaluated = scanData?.crypto_posture?.pqc_indicators_evaluated === true;
  const certSubject = primaryCert?.subject_cn || primaryCert?.subject_dn || null;
  const certIdentifier = certSubject
    ?? (primaryCert?.sha256_fingerprint
      ? `${primaryCert.sha256_fingerprint.slice(0, 10)}…${primaryCert.sha256_fingerprint.slice(-4)}`
      : null);
  const chainBadge = primaryCert
    ? primaryCert.chain_valid === true
      ? { label: 'CHAIN VALID', badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-800/50' }
      : primaryCert.chain_valid === false
        ? { label: 'UNTRUSTED', badgeClass: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/30 dark:text-rose-400 dark:border-rose-800/50' }
        : { label: 'UNVERIFIED', badgeClass: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-800/50' }
    : { label: 'NO DATA', badgeClass: 'bg-slate-50 text-slate-500 border-slate-200 dark:bg-slate-800/50 dark:text-slate-400 dark:border-slate-700/50' };
  const dkimSelector = typeof dkimCheck?.details?.selector === 'string' ? dkimCheck.details.selector : null;
  const dkimKeySize = typeof dkimCheck?.details?.key_size === 'number' ? dkimCheck.details.key_size : null;
  const dkimDetail = dkimCheck
    ? [dkimSelector ? `Selector ${dkimSelector}` : null, dkimKeySize ? `${dkimKeySize}-bit key` : null]
        .filter(Boolean)
        .join(' · ') || 'Details not reported'
    : 'No Credential Data';
  const dkimBadge = dkimCheck
    ? dkimCheck.status === 'pass'
      ? { label: 'ACTIVE', badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-800/50' }
      : dkimCheck.status === 'warn'
        ? { label: 'WARN', badgeClass: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-800/50' }
        : dkimCheck.status === 'fail'
          ? { label: 'FAIL', badgeClass: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/30 dark:text-rose-400 dark:border-rose-800/50' }
          : { label: 'UNKNOWN', badgeClass: 'bg-slate-50 text-slate-500 border-slate-200 dark:bg-slate-800/50 dark:text-slate-400 dark:border-slate-700/50' }
    : { label: 'NO DATA', badgeClass: 'bg-slate-50 text-slate-500 border-slate-200 dark:bg-slate-800/50 dark:text-slate-400 dark:border-slate-700/50' };

  // Speedometer calculation:
  // Mathematical formula: angle = (risk / 100) * 180 - 90
  // Low risk (0-30%) sits in the Emerald segment on the left (-90° to -36°)
  // Moderate risk (31-70%) sits in the Amber segment (-36° to +36°)
  // High risk (71-100%) sits in the Rose segment (+36° to +90°)
  const resolvedScore = typeof activeScore === 'number' && Number.isFinite(activeScore)
    ? activeScore
    : fuzzyScore !== undefined && fuzzyScore !== null
      ? Math.round(fuzzyScore)
      : null;
  const risk = resolvedScore === null ? 0 : Math.max(0, Math.min(100, 100 - resolvedScore));
  const angle = (risk / 100) * 180 - 90;

  // Linguistic status badge evaluation
  const getClassificationBadge = () => {
    if (linguisticClassification) {
      switch (linguisticClassification) {
        case 'EXCELLENT':
          return { label: 'FIS: EXCELLENT POSTURE', textColor: 'text-emerald-700 dark:text-emerald-400', bgColor: 'bg-emerald-50 border-emerald-200 dark:bg-emerald-950/30 dark:border-emerald-800/50' };
        case 'GOOD':
          return { label: 'FIS: GOOD POSTURE', textColor: 'text-emerald-600 dark:text-emerald-400', bgColor: 'bg-emerald-50 border-emerald-200 dark:bg-emerald-950/30 dark:border-emerald-800/50' };
        case 'ACCEPTABLE':
          return { label: 'FIS: ACCEPTABLE POSTURE', textColor: 'text-amber-600 dark:text-amber-400', bgColor: 'bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-800/50' };
        case 'POOR':
          return { label: 'FIS: POOR POSTURE', textColor: 'text-orange-600 dark:text-orange-400', bgColor: 'bg-orange-50 border-orange-200 dark:bg-orange-950/30 dark:border-orange-800/50' };
        case 'CRITICAL':
          return { label: 'FIS: CRITICAL RISK', textColor: 'text-rose-600 dark:text-rose-400', bgColor: 'bg-rose-50 border-rose-200 dark:bg-rose-950/30 dark:border-rose-800/50' };
      }
    }
    if (resolvedScore === null) {
      return {
        label: 'Awaiting Scan Data',
        textColor: 'text-slate-500 dark:text-slate-400',
        bgColor: 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700/50'
      };
    }
    if (resolvedScore >= 80) {
      return {
        label: pqcEvaluated ? 'Low Risk · PQC Evaluated' : 'Low Risk · PQC Not Evaluated',
        textColor: 'text-emerald-700 dark:text-emerald-400',
        bgColor: 'bg-emerald-50 border-emerald-200 dark:bg-emerald-950/30 dark:border-emerald-800/50'
      };
    }
    if (resolvedScore >= 60) {
      return {
        label: 'Moderate Risk · Advisory',
        textColor: 'text-amber-600 dark:text-amber-400',
        bgColor: 'bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-800/50'
      };
    }
    return {
      label: 'High Risk · Critical Action',
      textColor: 'text-rose-600 dark:text-rose-400',
      bgColor: 'bg-rose-50 border-rose-200 dark:bg-rose-950/30 dark:border-rose-800/50'
    };
  };

  const badge = getClassificationBadge();

  // Inference telemetry readout. Every value here is read from the scan response;
  // anything the backend did not report is labelled NOT REPORTED rather than invented.
  const aiRisk = scanData?.ai_risk_score ?? null;
  const anomaly = scanData?.anomaly_detection ?? null;
  type TelemetryTone = 'ok' | 'warn' | 'crit' | 'idle';
  const telemetry: Array<{ key: string; value: string; tone: TelemetryTone }> = [
    {
      key: 'Inference',
      value: aiRisk ? `${aiRisk.risk_level} · ${aiRisk.risk_score}/100` : 'NOT REPORTED',
      tone: aiRisk ? (aiRisk.risk_score >= 70 ? 'crit' : aiRisk.risk_score >= 40 ? 'warn' : 'ok') : 'idle'
    },
    {
      key: 'Model conf.',
      value: typeof aiRisk?.confidence === 'number' ? `${(aiRisk.confidence * 100).toFixed(0)}%` : '—',
      tone: typeof aiRisk?.confidence === 'number' ? 'ok' : 'idle'
    },
    {
      key: 'FIS certainty',
      value: typeof defuzzificationConfidence === 'number' ? `${(defuzzificationConfidence * 100).toFixed(0)}%` : '—',
      tone: typeof defuzzificationConfidence === 'number' ? 'ok' : 'idle'
    },
    {
      key: 'Rules fired',
      value: activatedRules ? String(activatedRules.length) : '—',
      tone: activatedRules && activatedRules.length > 0 ? 'warn' : 'idle'
    },
    {
      key: 'Anomaly',
      value: anomaly
        ? anomaly.anomaly_detected
          ? `DETECTED · ${anomaly.anomaly_score.toFixed(2)}`
          : 'CLEAR'
        : 'NOT REPORTED',
      tone: anomaly ? (anomaly.anomaly_detected ? 'crit' : 'ok') : 'idle'
    },
    {
      key: 'MTA-STS',
      value: mtaStsCheck ? mtaStsCheck.status.toUpperCase() : 'NOT REPORTED',
      tone: mtaStsCheck
        ? mtaStsCheck.status === 'pass'
          ? 'ok'
          : mtaStsCheck.status === 'fail'
            ? 'crit'
            : 'warn'
        : 'idle'
    },
    {
      key: 'PQC scan',
      value: scanData ? (pqcEvaluated ? 'EVALUATED' : 'NOT EVALUATED') : 'AWAITING SCAN',
      tone: scanData ? (pqcEvaluated ? 'ok' : 'warn') : 'idle'
    },
    {
      key: 'CVSS',
      value: cvssMetrics ? `${cvssMetrics.base_score.toFixed(1)} · ${cvssMetrics.severity}` : 'NOT REPORTED',
      tone: cvssMetrics
        ? cvssMetrics.base_score >= 7
          ? 'crit'
          : cvssMetrics.base_score >= 4
            ? 'warn'
            : 'ok'
        : 'idle'
    },
    {
      key: 'Findings',
      value: scanData ? String(scanData.prioritized_findings?.length ?? 0) : '—',
      tone: 'idle'
    },
    {
      key: 'Cert trust',
      value: primaryCert ? (primaryCert.chain_valid === true ? 'TRUSTED' : primaryCert.chain_valid === false ? 'UNTRUSTED' : 'UNVERIFIED') : 'NOT REPORTED',
      tone: primaryCert ? (primaryCert.chain_valid === true ? 'ok' : primaryCert.chain_valid === false ? 'crit' : 'warn') : 'idle'
    }
  ];
  const telemetryTone = (tone: TelemetryTone): string =>
    tone === 'ok'
      ? 'text-emerald-600 dark:text-emerald-400'
      : tone === 'warn'
        ? 'text-amber-600 dark:text-amber-400'
        : tone === 'crit'
          ? 'text-rose-600 dark:text-rose-400'
          : 'text-slate-500 dark:text-slate-400';

  return (
    <div className={`${className} bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-cyan-500/50 transition-colors overflow-hidden`}>
      {cvssMetrics && (
        <div className="mb-5 rounded border border-amber-500/30 bg-amber-500/10 p-3 font-mono text-xs text-amber-800 dark:text-amber-100" aria-label="CVSS vulnerability metrics">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 font-bold tracking-wide text-amber-700 dark:text-amber-300">CVSS {cvssMetrics.base_score} · {cvssMetrics.severity}</span>
            <span className="break-all text-slate-600 dark:text-slate-300">{cvssMetrics.vector_string}</span>
          </div>
        </div>
      )}

      {/* 3-Column Enterprise SOC Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        
        {/* LEFT COLUMN: Identity Credential & Policy Inspection Cards */}
        <div className="lg:col-span-4 flex flex-col sm:flex-row lg:flex-col gap-3 justify-center">
          
          {/* Credential Card 1: ID Badge */}
          <button
            type="button"
            onClick={() => {
              setActiveNode('cred-1');
              if (onSelectCredentialNode) onSelectCredentialNode('cred-1');
            }}
            className={`w-full text-left p-3.5 rounded bg-slate-50 dark:bg-slate-800/60 border transition-colors duration-150 group active:scale-[0.99] ${
              activeNode === 'cred-1'
                ? 'border-cyan-500 ring-1 ring-cyan-500/40'
                : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-300">
                  <UserCheck size={16} />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-800 dark:text-slate-100 font-sans tracking-tight">
                    Identity Credential
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 truncate max-w-[190px]" title={certIdentifier ?? undefined}>
                    {certIdentifier ?? 'No Credential Data'}
                  </div>
                </div>
              </div>

              {/* Chain status badge — only claims what the scan reported */}
              <div className={`flex items-center gap-1 px-1.5 py-0.5 rounded border ${chainBadge.badgeClass}`}>
                <CheckCircle2 size={11} />
                <span className="text-[9px] font-mono font-medium">{chainBadge.label}</span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
              <span>{primaryCert ? 'X.509 Certificate' : 'X.509 Certificate — none reported'}</span>
              <span className="text-slate-600 dark:text-slate-300">Expiry: {certificateExpiry ? new Date(certificateExpiry).toLocaleDateString() : 'Unknown'}</span>
            </div>
          </button>

          {/* Credential Card 2: Document / Policy */}
          <button
            type="button"
            onClick={() => {
              setActiveNode('cred-2');
              if (onSelectCredentialNode) onSelectCredentialNode('cred-2');
            }}
            className={`w-full text-left p-3.5 rounded bg-slate-50 dark:bg-slate-800/60 border transition-colors duration-150 group active:scale-[0.99] ${
              activeNode === 'cred-2'
                ? 'border-cyan-500 ring-1 ring-cyan-500/40'
                : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-300">
                  <FileKey2 size={16} />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-800 dark:text-slate-100 font-sans tracking-tight">
                    DKIM / MTA-STS Policy
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 truncate max-w-[190px]" title={dkimDetail}>
                    {dkimDetail}
                  </div>
                </div>
              </div>

              <div className={`flex items-center gap-1 px-1.5 py-0.5 rounded border ${dkimBadge.badgeClass}`}>
                <CheckCircle2 size={11} />
                <span className="text-[9px] font-mono font-medium">{dkimBadge.label}</span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
              <span>{dkimCheck ? `${dkimCheck.name} Check` : 'No Check Data'}</span>
              <span className={dkimCheck?.status === 'pass' ? 'text-emerald-700 dark:text-emerald-400 font-semibold' : 'text-slate-500 dark:text-slate-400 font-semibold'}>
                {dkimCheck ? dkimCheck.status.toUpperCase() : 'NO DATA'}
              </span>
            </div>
          </button>
        </div>

        {/* CENTER COLUMN: Re-Engineered Speedometer Gauge */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center py-2">
          
          {/* Centered SVG speedometer — pivot (140,130), radius 100, 7px hairline arc.
              Band boundaries sit exactly on the 30% and 70% needle positions
              (risk -> theta = 180 - 1.8 * risk degrees). */}
          <div className="relative w-64 h-36 flex items-end justify-center">
            <svg
              viewBox="0 0 280 170"
              className="w-full h-full"
              role="img"
              aria-label={`Risk index half-dial: ${resolvedScore !== null ? `${resolvedScore} of 100` : 'no score reported'}`}
            >
              {/* Full background track */}
              <path
                d="M 40 130 A 100 100 0 0 1 240 130"
                fill="none"
                className="stroke-slate-200 dark:stroke-slate-800"
                strokeWidth="7"
                strokeLinecap="round"
              />

              {/* Dark-mode bloom: a blurred duplicate of the bands, never bright.
                  Decorative only, so it is hidden from assistive tech. */}
              <g className="hidden dark:block opacity-30 blur-[3px]" aria-hidden="true">
                <path d="M 40 130 A 100 100 0 0 1 83.36 47.59" fill="none" stroke="#059669" strokeWidth="7" strokeLinecap="round" />
                <path d="M 79.12 50.66 A 100 100 0 0 1 200.88 50.66" fill="none" stroke="#f59e0b" strokeWidth="7" />
                <path d="M 196.64 47.59 A 100 100 0 0 1 240 130" fill="none" stroke="#e11d48" strokeWidth="7" strokeLinecap="round" />
              </g>

              {/* Band 1 — deep emerald, risk 0-30% */}
              <path d="M 40 130 A 100 100 0 0 1 83.36 47.59" fill="none" stroke="#059669" strokeWidth="7" strokeLinecap="round" />

              {/* Band 2 — amber, risk 30-70% */}
              <path d="M 79.12 50.66 A 100 100 0 0 1 200.88 50.66" fill="none" stroke="#f59e0b" strokeWidth="7" />

              {/* Band 3 — crimson, risk 70-100% */}
              <path d="M 196.64 47.59 A 100 100 0 0 1 240 130" fill="none" stroke="#e11d48" strokeWidth="7" strokeLinecap="round" />

              {/* Scale ticks */}
              <text x="30" y="156" className="fill-slate-500" fontSize="9" fontFamily="monospace" textAnchor="middle">0</text>
              <text x="140" y="18" className="fill-slate-500" fontSize="9" fontFamily="monospace" textAnchor="middle">50</text>
              <text x="250" y="156" className="fill-slate-500" fontSize="9" fontFamily="monospace" textAnchor="middle">100</text>

              {/* Needle, pivot at (140,130) — tip stays clear of the inner arc edge */}
              {resolvedScore !== null && (
                <g transform={`rotate(${angle} 140 130)`}>
                  <polygon points="138.5,130 140,46 141.5,130" className="fill-slate-600 dark:fill-slate-300" />
                  <circle cx="140" cy="130" r="5" className="fill-white dark:fill-slate-900 stroke-slate-400 dark:stroke-slate-600" strokeWidth="1.5" />
                  <circle cx="140" cy="130" r="2" className="fill-slate-500 dark:fill-slate-400" />
                </g>
              )}
            </svg>
          </div>

          {/* Underneath Gauge: Risk Label, Score, and Clean Badge */}
          <div className="flex flex-col items-center text-center mt-1 space-y-1.5">
            <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
              RISK INDEX
            </span>

            {/* Score & Label */}
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold font-mono font-semibold text-slate-900 dark:text-slate-100">
                {resolvedScore !== null ? resolvedScore : 'N/A'}
                {resolvedScore !== null && <span className="text-slate-500 dark:text-slate-400 text-sm tracking-tight">/100</span>}
              </span>
            </div>

            {/* Status Badge */}
            <div className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-medium border ${badge.bgColor} ${badge.textColor}`}>
              {badge.label}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: AI inference telemetry readout */}
        <div className="lg:col-span-4 flex flex-col justify-center gap-2 min-h-[160px]">

          {/* AI Forensic Audit entry point */}
          <button
            type="button"
            onClick={onOpenReportModal}
            className="self-start inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 hover:border-cyan-500/50 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors"
            title="Inspect AI forensic remediation guidance"
          >
            <Cpu size={11} />
            <span>AI Forensic Audit</span>
            <ExternalLink size={10} className="opacity-70" />
          </button>

          {/* Rigid telemetry grid — replaces the decorative node graphic. Mono only,
              because every value is an identifier, count or score. */}
          <div className="w-full rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-2.5 font-mono text-[10px] leading-relaxed">
            <div className="flex items-center justify-between gap-2 pb-1.5 mb-1.5 border-b border-slate-200 dark:border-slate-800">
              <span className="text-slate-500 dark:text-slate-400 tracking-wider">[SYS] INFERENCE ENGINE</span>
              <span className="text-slate-500 dark:text-slate-400 tracking-wider">{scanData ? 'LIVE' : 'IDLE'}</span>
            </div>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-x-3 gap-y-0.5">
              {telemetry.map((row) => (
                <div key={row.key} className="flex items-center justify-between gap-2 min-w-0">
                  <span className="text-slate-500 dark:text-slate-400 truncate">{row.key}</span>
                  <span className={`font-semibold tracking-tight truncate ${telemetryTone(row.tone)}`} title={row.value}>
                    {row.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* LOWER SECTION: Hierarchical Fuzzy Risk Explainability Breakdown (Task 3.1) */}
      {antecedentScores && (
        <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800 space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers size={14} className="text-cyan-600 dark:text-cyan-400" />
              <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 uppercase tracking-wider">
                Fuzzy Risk Decomposition (6 Antecedent Engines)
              </span>
              {defuzzificationConfidence && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-500/20">
                  Certainty: {(defuzzificationConfidence * 100).toFixed(0)}%
                </span>
              )}
            </div>

            {activatedRules && activatedRules.length > 0 && (
              <button
                type="button"
                onClick={() => setShowRules(!showRules)}
                className="text-[11px] text-cyan-700 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>{showRules ? 'Hide Fired Rules' : `Show Fired Rules (${activatedRules.length})`}</span>
                {showRules ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
            )}
          </div>

          {/* 6 Antecedents Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
            {[
              {
                id: 'tls',
                label: 'TLS Version',
                value: antecedentScores.tls_compliance,
                desc: antecedentScores.tls_compliance >= 0.9 ? 'TLS 1.3' : antecedentScores.tls_compliance >= 0.7 ? 'TLS 1.2' : 'Legacy TLS'
              },
              {
                id: 'cipher',
                label: 'Cipher Strength',
                value: antecedentScores.cipher_strength,
                desc: antecedentScores.cipher_strength >= 0.9 ? 'AEAD Strong' : antecedentScores.cipher_strength >= 0.5 ? 'CBC Moderate' : 'Weak Cipher'
              },
              {
                id: 'cert',
                label: 'Certificate Health',
                value: antecedentScores.certificate_health,
                desc: antecedentScores.certificate_health >= 0.8 ? 'Fresh & Valid' : antecedentScores.certificate_health >= 0.4 ? 'Renew Soon' : 'Deficit / Invalid'
              },
              {
                id: 'pqc',
                label: 'PQC Readiness',
                value: antecedentScores.pqc_readiness,
                desc: antecedentScores.pqc_readiness >= 0.8 ? 'PQC Ready' : antecedentScores.pqc_readiness >= 0.4 ? 'Partial PQC' : 'Not PQC Ready'
              },
              {
                id: 'auth',
                label: 'Email Auth (PED)',
                value: antecedentScores.email_auth_posture,
                desc: antecedentScores.email_auth_posture >= 0.8 ? 'DMARC Enforced' : antecedentScores.email_auth_posture >= 0.5 ? 'SPF/DKIM Only' : 'Deficit'
              },
              {
                id: 'eli',
                label: 'Vulnerability (ELI)',
                value: 1.0 - antecedentScores.exploitation_likelihood, // Invert so 1.0 is safe/good
                desc: antecedentScores.exploitation_likelihood <= 0.2 ? 'Low Exploit Likelihood' : 'Elevated Exploit Likelihood'
              }
            ].map((item) => {
              const pct = Math.round(item.value * 100);
              const barColor = pct >= 75 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-rose-500';
              const textColor = pct >= 75 ? 'text-emerald-700 dark:text-emerald-400' : pct >= 50 ? 'text-amber-600 dark:text-amber-400' : 'text-rose-600 dark:text-rose-400';
              return (
                <div
                  key={item.id}
                  className="p-2.5 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400">
                    <span className="truncate">{item.label}</span>
                    <span className={`font-bold font-mono tracking-tight ${textColor}`}>{pct}%</span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 my-1.5 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                      style={{ width: `${Math.max(4, pct)}%` }}
                    />
                  </div>
                  <span className="text-[9px] text-slate-500 dark:text-slate-400 truncate">{item.desc}</span>
                </div>
              );
            })}
          </div>

          {/* Activated Rules Explainability Trace */}
          {showRules && activatedRules && activatedRules.length > 0 && (
            <div className="p-3 rounded bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 text-[11px] space-y-1.5 text-slate-600 dark:text-slate-300 animate-fade-in">
              <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider block">
                Activated Mamdani Inference Rules (Explainability Audit):
              </span>
              <ul className="space-y-1 pl-3 list-disc text-slate-600 dark:text-slate-300">
                {activatedRules.map((rule, idx) => (
                  <li key={idx} className="font-mono text-[10px] text-slate-600 dark:text-slate-300">
                    {rule}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

    </div>
  );
};
