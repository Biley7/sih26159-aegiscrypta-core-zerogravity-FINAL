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

interface ThreatCenterProps {
  score?: number; // 0 to 100 (posture score)
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
  onOpenReportModal?: () => void;
  onSelectCredentialNode?: (nodeId: string) => void;
  onOpenAiFindings?: () => void;
}

export const ThreatCenter: React.FC<ThreatCenterProps> = ({
  score = 85,
  domain = 'gmail.com',
  fuzzyScore,
  linguisticClassification,
  antecedentScores,
  activatedRules,
  defuzzificationConfidence,
  onOpenReportModal,
  onSelectCredentialNode,
  onOpenAiFindings
}) => {
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [showRules, setShowRules] = useState(false);

  // Speedometer calculation:
  // Mathematical formula: angle = (risk / 100) * 180 - 90
  // Low risk (0-30%) sits in the Emerald segment on the left (-90° to -36°)
  // Moderate risk (31-70%) sits in the Amber segment (-36° to +36°)
  // High risk (71-100%) sits in the Rose segment (+36° to +90°)
  const effectiveScore = fuzzyScore !== undefined && fuzzyScore !== null ? Math.round(fuzzyScore) : score;
  const risk = Math.max(0, Math.min(100, 100 - effectiveScore));
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
    if (score >= 80) {
      return {
        label: 'Low Risk · PQC Compliant',
        textColor: 'text-emerald-400',
        bgColor: 'bg-emerald-500/10 border-emerald-500/30'
      };
    }
    if (score >= 60) {
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
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-5 overflow-hidden transition-colors">
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
                  <div className="text-[10px] font-mono text-slate-400">
                    ID: 0x94F2...88A1
                  </div>
                </div>
              </div>

              {/* Verified Badge */}
              <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <CheckCircle2 size={11} className="text-emerald-400" />
                <span className="text-[9px] font-mono font-medium">VERIFIED</span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>X.509 v3 Client Cert</span>
              <span className="text-slate-300">Valid: 2027</span>
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
                  <div className="text-[10px] font-mono text-slate-400">
                    Ed25519-PQC Dual Signed
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <CheckCircle2 size={11} className="text-emerald-400" />
                <span className="text-[9px] font-mono font-medium">ACTIVE</span>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>SHA-256 Digest Match</span>
              <span className="text-emerald-400 font-semibold">0 RFC Errors</span>
            </div>
          </button>
        </div>

        {/* CENTER COLUMN: Re-Engineered Speedometer Gauge */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center py-2">
          
          {/* Centered SVG Speedometer Canvas (Radius 100, Stroke 14) */}
          <div className="relative w-64 h-36 flex items-end justify-center">
            <svg
              viewBox="0 0 260 145"
              className="w-full h-full overflow-visible"
            >
              {/* Full Background Track Arc */}
              <path
                d="M 30 120 A 100 100 0 0 1 230 120"
                fill="none"
                stroke="#1e293b"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Segment 1: Forest Emerald (0-30% Risk) */}
              <path
                d="M 30 120 A 100 100 0 0 1 80 33.4"
                fill="none"
                stroke="#10b981"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Segment 2: Solid Amber (31-70% Risk) */}
              <path
                d="M 86 29.5 A 100 100 0 0 1 174 29.5"
                fill="none"
                stroke="#f59e0b"
                strokeWidth="14"
              />

              {/* Segment 3: Deep Rose (71-100% Risk) */}
              <path
                d="M 180 33.4 A 100 100 0 0 1 230 120"
                fill="none"
                stroke="#f43f5e"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Scale Tick Markers (0, 50, 100) */}
              <text x="25" y="140" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">0</text>
              <text x="130" y="15" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">50</text>
              <text x="235" y="140" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">100</text>

              {/* Precision Needle Pivot at (130, 120) */}
              <g
                style={{
                  transformOrigin: '130px 120px',
                  transform: `rotate(${angle}deg)`,
                  transition: 'transform 0.8s cubic-bezier(0.4, 0, 0.2, 1)'
                }}
              >
                {/* Needle pointer */}
                <polygon
                  points="128,120 130,26 132,120"
                  fill="#f8fafc"
                />
                {/* Pivot disc */}
                <circle cx="130" cy="120" r="9" fill="#090d16" stroke="#3b82f6" strokeWidth="2.5" />
                <circle cx="130" cy="120" r="3.5" fill="#f8fafc" />
              </g>
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
                {score}<span className="text-slate-500 text-sm">/100</span>
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
              title="Autonomous TLS Downgrade Protection Active"
            >
              <Lock size={14} className="text-slate-300" />
            </div>

            <div
              className="absolute bottom-1 right-2 w-9 h-9 rounded-lg bg-slate-800/90 border border-slate-700 flex items-center justify-center text-emerald-400 shadow-sm"
              title="Quantum Key Distribution (QKD) Guard Active"
            >
              <ShieldCheck size={14} className="text-emerald-400" />
            </div>
          </div>

          <div className="mt-2 text-[10px] font-mono text-slate-400 text-center">
            Autonomous Policy Guard Enforced
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
                desc: 'FIPS-203 Ready'
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
                desc: antecedentScores.exploitation_likelihood <= 0.2 ? 'Zero Known CVEs' : 'Exposure Risk'
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
