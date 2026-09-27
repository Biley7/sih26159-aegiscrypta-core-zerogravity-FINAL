import React, { useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  Lock,
  Sparkles,
  ExternalLink,
  Cpu,
  UserCheck,
  FileKey2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Activity,
  Layers
} from 'lucide-react';
import { Logo } from './Logo';
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
      ? { label: 'CHAIN VALID', badgeClass: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' }
      : primaryCert.chain_valid === false
        ? { label: 'UNTRUSTED', badgeClass: 'bg-rose-500/10 border-rose-500/30 text-rose-400' }
        : { label: 'UNVERIFIED', badgeClass: 'bg-amber-500/10 border-amber-500/30 text-amber-400' }
    : { label: 'NO DATA', badgeClass: 'bg-slate-500/10 border-slate-500/30 text-slate-400' };
  const dkimSelector = typeof dkimCheck?.details?.selector === 'string' ? dkimCheck.details.selector : null;
  const dkimKeySize = typeof dkimCheck?.details?.key_size === 'number' ? dkimCheck.details.key_size : null;
  const dkimDetail = dkimCheck
    ? [dkimSelector ? `Selector ${dkimSelector}` : null, dkimKeySize ? `${dkimKeySize}-bit key` : null]
        .filter(Boolean)
        .join(' · ') || 'Details not reported'
    : 'No Credential Data';
  const dkimBadge = dkimCheck
    ? dkimCheck.status === 'pass'
      ? { label: 'ACTIVE', badgeClass: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' }
      : dkimCheck.status === 'warn'
        ? { label: 'WARN', badgeClass: 'bg-amber-500/10 border-amber-500/30 text-amber-400' }
        : dkimCheck.status === 'fail'
          ? { label: 'FAIL', badgeClass: 'bg-rose-500/10 border-rose-500/30 text-rose-400' }
          : { label: 'UNKNOWN', badgeClass: 'bg-slate-500/10 border-slate-500/30 text-slate-300' }
    : { label: 'NO DATA', badgeClass: 'bg-slate-500/10 border-slate-500/30 text-slate-400' };

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
          return { label: 'FIS: EXCELLENT POSTURE', textColor: 'text-emerald-400', bgColor: 'bg-emerald-500/10 border-emerald-500/30' };
        case 'GOOD':
          return { label: 'FIS: GOOD POSTURE', textColor: 'text-teal-400', bgColor: 'bg-teal-500/10 border-teal-500/30' };
        case 'ACCEPTABLE':
          return { label: 'FIS: ACCEPTABLE POSTURE', textColor: 'text-amber-400', bgColor: 'bg-amber-500/10 border-amber-500/30' };
        case 'POOR':
          return { label: 'FIS: POOR POSTURE', textColor: 'text-orange-400', bgColor: 'bg-orange-500/10 border-orange-500/30' };
        case 'CRITICAL':
          return { label: 'FIS: CRITICAL RISK', textColor: 'text-rose-400', bgColor: 'bg-rose-500/10 border-rose-500/30' };
      }
    }
    if (resolvedScore === null) {
      return {
        label: 'Awaiting Scan Data',
        textColor: 'text-slate-400',
        bgColor: 'bg-slate-500/10 border-slate-500/30'
      };
    }
    if (resolvedScore >= 80) {
      return {
        label: pqcEvaluated ? 'Low Risk · PQC Evaluated' : 'Low Risk · PQC Not Evaluated',
        textColor: 'text-emerald-400',
        bgColor: 'bg-emerald-500/10 border-emerald-500/30'
      };
    }
    if (resolvedScore >= 60) {
      return {
        label: 'Moderate Risk · Advisory',
        textColor: 'text-amber-400',
        bgColor: 'bg-amber-500/10 border-amber-500/30'
      };
    }
    return {
      label: 'High Risk · Critical Action',
      textColor: 'text-rose-400',
      bgColor: 'bg-rose-500/10 border-rose-500/30'
    };
  };

  const badge = getClassificationBadge();

  return (
    <div className={`${className} bg-slate-50 dark:bg-slate-900/80 text-slate-900 dark:text-slate-100 border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-lg shadow-black/10 dark:shadow-black/20 hover:border-cyan-500/50 transition-all duration-200 overflow-hidden`}>
      {cvssMetrics && (
        <div className="mb-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 font-mono text-xs text-amber-100" aria-label="CVSS vulnerability metrics">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-1 font-bold tracking-wide text-amber-300">CVSS {cvssMetrics.base_score} · {cvssMetrics.severity}</span>
            <span className="break-all text-slate-300">{cvssMetrics.vector_string}</span>
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
            className={`w-full text-left p-3.5 rounded-lg bg-slate-900/90 dark:bg-[#161f30] border transition-all duration-150 group active:scale-[0.99] ${
              activeNode === 'cred-1'
                ? 'border-blue-500 ring-1 ring-blue-500/40'
                : 'border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
                  <UserCheck size={16} />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-100 font-sans tracking-tight">
                    Identity Credential
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 truncate max-w-[190px]" title={certIdentifier ?? undefined}>
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

            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>{primaryCert ? 'X.509 Certificate' : 'X.509 Certificate — none reported'}</span>
              <span className="text-slate-700 dark:text-slate-300">Expiry: {certificateExpiry ? new Date(certificateExpiry).toLocaleDateString() : 'Unknown'}</span>
            </div>
          </button>

          {/* Credential Card 2: Document / Policy */}
          <button
            type="button"
            onClick={() => {
              setActiveNode('cred-2');
              if (onSelectCredentialNode) onSelectCredentialNode('cred-2');
            }}
            className={`w-full text-left p-3.5 rounded-lg bg-slate-900/90 dark:bg-[#161f30] border transition-all duration-150 group active:scale-[0.99] ${
              activeNode === 'cred-2'
                ? 'border-blue-500 ring-1 ring-blue-500/40'
                : 'border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
                  <FileKey2 size={16} />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-100 font-sans tracking-tight">
                    DKIM / MTA-STS Policy
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 truncate max-w-[190px]" title={dkimDetail}>
                    {dkimDetail}
                  </div>
                </div>
              </div>

              <div className={`flex items-center gap-1 px-1.5 py-0.5 rounded border ${dkimBadge.badgeClass}`}>
                <CheckCircle2 size={11} />
                <span className="text-[9px] font-mono font-medium">{dkimBadge.label}</span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>{dkimCheck ? `${dkimCheck.name} Check` : 'No Check Data'}</span>
              <span className={dkimCheck?.status === 'pass' ? 'text-emerald-400 font-semibold' : 'text-slate-400 font-semibold'}>
                {dkimCheck ? dkimCheck.status.toUpperCase() : 'NO DATA'}
              </span>
            </div>
          </button>
        </div>

        {/* CENTER COLUMN: Re-Engineered Speedometer Gauge */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center py-2">
          
          {/* Centered SVG Speedometer Canvas (Radius 100, Stroke 14) */}
          <div className="relative w-64 h-36 flex items-end justify-center">
            <svg
              viewBox="0 0 280 170"
              className="w-full h-full overflow-visible"
            >
              {/* Full Background Track Arc */}
              <path
                d="M 40 130 A 100 100 0 0 1 240 130"
                fill="none"
                stroke="#1e293b"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Segment 1: Forest Emerald (0-30% Risk) */}
              <path
                d="M 40 130 A 100 100 0 0 1 90 43.4"
                fill="none"
                stroke="#10b981"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Segment 2: Solid Amber (31-70% Risk) */}
              <path
                d="M 96 39.5 A 100 100 0 0 1 184 39.5"
                fill="none"
                stroke="#f59e0b"
                strokeWidth="14"
              />

              {/* Segment 3: Deep Rose (71-100% Risk) */}
              <path
                d="M 190 43.4 A 100 100 0 0 1 240 130"
                fill="none"
                stroke="#f43f5e"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Scale Tick Markers (0, 50, 100) */}
              <text x="28" y="158" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">0</text>
              <text x="140" y="13" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">50</text>
              <text x="252" y="158" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">100</text>

              {/* Precision Needle Pivot at (140, 130) — only rendered when a score exists */}
              {resolvedScore !== null && (
              <g
                transform={`rotate(${angle} 140 130)`}
              >
                {/* Needle pointer */}
                <polygon
                  points="138,130 140,36 142,130"
                  fill="#f8fafc"
                />
                {/* Pivot disc */}
                <circle cx="140" cy="130" r="9" fill="#0f172a" stroke="#3b82f6" strokeWidth="2.5" />
                <circle cx="140" cy="130" r="3.5" fill="#f8fafc" />
              </g>
              )}
            </svg>
          </div>

          {/* Underneath Gauge: Risk Label, Score, and Clean Badge */}
          <div className="flex flex-col items-center text-center mt-1 space-y-1.5">
            <span className="text-[10px] font-mono font-semibold tracking-wider text-slate-400 uppercase">
              RISK INDEX
            </span>

            {/* Score & Label */}
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold font-mono text-slate-100">
                {resolvedScore !== null ? resolvedScore : 'N/A'}
                {resolvedScore !== null && <span className="text-slate-500 text-sm">/100</span>}
              </span>
            </div>

            {/* Status Badge */}
            <div className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-medium border ${badge.bgColor} ${badge.textColor}`}>
              {badge.label}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: AI Sentinel & Autonomous Verification */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center relative min-h-[160px]">
          
          {/* AI Forensic Audit Interactive Pill */}
          <button
            type="button"
            onClick={onOpenReportModal}
            className="mb-3 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 hover:border-slate-600 text-xs font-sans font-medium text-slate-200 flex items-center gap-2 transition-colors"
            title="Inspect AI Forensic Remediation Guidance"
          >
            <Sparkles size={13} className="text-blue-400" />
            <span>AI Forensic Audit</span>
            <ExternalLink size={11} className="text-slate-400" />
          </button>

          {/* Neural Core + Network Nodes */}
          <div className="relative w-44 h-32 flex items-center justify-center">
            
            <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 176 128">
              <line
                x1="88"
                y1="64"
                x2="140"
                y2="30"
                stroke="#334155"
                strokeWidth="1.5"
                strokeDasharray="3 3"
              />
              <line
                x1="88"
                y1="64"
                x2="140"
                y2="98"
                stroke="#334155"
                strokeWidth="1.5"
                strokeDasharray="3 3"
              />
              <circle cx="114" cy="47" r="2" fill="#3b82f6" />
              <circle cx="114" cy="81" r="2" fill="#3b82f6" />
            </svg>

            {/* Central AI Node */}
            <div
              onClick={onOpenReportModal}
              className="relative z-10 w-14 h-14 rounded-full bg-slate-800 border border-blue-500/60 flex items-center justify-center group hover:border-blue-400 transition-colors cursor-pointer shadow-sm"
              title="Click to view AI cryptographic risk findings"
            >
              <div className="flex flex-col items-center justify-center">
                <span className="text-sm font-bold font-mono text-slate-100">
                  AI
                </span>
                <span className="text-[7px] font-mono text-blue-400 font-semibold tracking-wider">
                  ACTIVE
                </span>
              </div>
            </div>

            {/* Lock Badges */}
            <div
              className="absolute top-1 right-2 w-9 h-9 rounded-lg bg-slate-800/90 border border-slate-700 flex items-center justify-center text-slate-300 shadow-sm"
              title={mtaStsCheck ? `MTA-STS policy status: ${mtaStsCheck.status.toUpperCase()}` : 'No MTA-STS policy data in this scan'}
            >
              <Lock size={14} className="text-slate-300" />
            </div>

            <div
              className="absolute bottom-1 right-2 w-9 h-9 rounded-lg bg-slate-800/90 border border-slate-700 flex items-center justify-center text-emerald-400 shadow-sm"
              title={pqcEvaluated ? 'PQC indicators evaluated by the backend scan' : 'PQC indicators not evaluated by the backend scan'}
            >
              <ShieldCheck size={14} className="text-emerald-400" />
            </div>
          </div>

          <div className="mt-2 text-[10px] font-mono text-slate-400 text-center">
            {scanData ? 'Policy view built from latest scan response' : 'Awaiting scan response'}
          </div>
        </div>

      </div>

      {/* LOWER SECTION: Hierarchical Fuzzy Risk Explainability Breakdown (Task 3.1) */}
      {antecedentScores && (
        <div className="mt-5 pt-4 border-t border-slate-800/80 space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers size={14} className="text-cyan-400" />
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Fuzzy Risk Decomposition (6 Antecedent Engines)
              </span>
              {defuzzificationConfidence && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  Certainty: {(defuzzificationConfidence * 100).toFixed(0)}%
                </span>
              )}
            </div>

            {activatedRules && activatedRules.length > 0 && (
              <button
                type="button"
                onClick={() => setShowRules(!showRules)}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
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
              const barColor = pct >= 75 ? 'bg-emerald-400' : pct >= 50 ? 'bg-amber-400' : 'bg-rose-400';
              const textColor = pct >= 75 ? 'text-emerald-400' : pct >= 50 ? 'text-amber-400' : 'text-rose-400';
              return (
                <div
                  key={item.id}
                  className="p-2.5 rounded-lg bg-slate-900/90 dark:bg-[#161f30] border border-slate-800/80 flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span className="truncate">{item.label}</span>
                    <span className={`font-bold ${textColor}`}>{pct}%</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 my-1.5 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                      style={{ width: `${Math.max(4, pct)}%` }}
                    />
                  </div>
                  <span className="text-[9px] text-slate-500 truncate">{item.desc}</span>
                </div>
              );
            })}
          </div>

          {/* Activated Rules Explainability Trace */}
          {showRules && activatedRules && activatedRules.length > 0 && (
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] space-y-1.5 text-slate-300 animate-fade-in">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
                Activated Mamdani Inference Rules (Explainability Audit):
              </span>
              <ul className="space-y-1 pl-3 list-disc text-slate-300">
                {activatedRules.map((rule, idx) => (
                  <li key={idx} className="font-mono text-[10px] text-slate-300">
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
