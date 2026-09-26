import React from 'react';
import { Activity, ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface ActivityTrendCardProps {
  checks?: CheckResult[];
  score?: number | null;
  cryptoPosture?: CryptographicPosture | null;
  antecedentScores?: {
    tls_compliance: number;
    cipher_strength: number;
    certificate_health: number;
    pqc_readiness: number;
    email_auth_posture: number;
    exploitation_likelihood: number;
  };
  onExpand?: () => void;
}

export const ActivityTrendCard: React.FC<ActivityTrendCardProps> = ({
  checks = [],
  score,
  cryptoPosture,
  antecedentScores,
  onExpand
}) => {
  const total = checks.length || 1;
  const passCount = checks.filter((c) => c.status === 'pass').length;
  const cert = cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.certificate;

  // Grade calculation
  const effectiveScore = score !== null && score !== undefined ? score : 85;
  const grade = effectiveScore >= 90 ? 'A' : effectiveScore >= 75 ? 'B' : effectiveScore >= 50 ? 'C' : 'F';
  const gradeColor = effectiveScore >= 80 ? 'text-emerald-400' : effectiveScore >= 60 ? 'text-amber-400' : 'text-rose-400';

  // Extract or compute metrics
  const tlsScore = Math.round(antecedentScores?.tls_compliance ?? (cryptoPosture?.deprecated_tls_found ? 40 : 95));
  const certScore = Math.round(antecedentScores?.certificate_health ?? (cert?.chain_valid !== false ? 95 : 30));
  const emailScore = Math.round(antecedentScores?.email_auth_posture ?? Math.round((passCount / total) * 100));

  const metrics = [
    { label: 'TLS Protocol Enforcement', value: `${tlsScore}%`, progress: tlsScore, color: 'bg-blue-500' },
    { label: 'X.509 Chain Health', value: `${certScore}%`, progress: certScore, color: certScore >= 70 ? 'bg-emerald-500' : 'bg-rose-500' },
    { label: 'Email Auth (SPF/DMARC)', value: `${emailScore}%`, progress: emailScore, color: 'bg-indigo-500' }
  ];

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-slate-400" />
          <span className="text-xs font-semibold text-slate-100 tracking-tight font-sans">
            Posture Trend &amp; Assurance
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Inspect Activity Stream"
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Snippet: Badge + Description text */}
      <div className="flex items-center gap-3 my-1 p-2 rounded-lg bg-slate-800/50 border border-slate-700/60">
        <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
          <span className={`text-base font-bold font-mono ${gradeColor}`}>
            {grade}
          </span>
        </div>
        <p className="text-[11px] text-slate-300 leading-snug font-sans">
          {effectiveScore >= 80
            ? 'Cryptographic posture meets zero-trust requirements across all audited MX endpoints.'
            : 'Remediation advised to eliminate legacy cipher and email auth vulnerabilities.'}
        </p>
      </div>

      {/* Comparative Progress Bars */}
      <div className="space-y-2 mt-2 font-mono text-xs">
        {metrics.map((m, idx) => (
          <div key={idx} className="flex items-center justify-between gap-3">
            <span className="text-[10px] text-slate-400 font-sans truncate flex-1">
              {m.label}
            </span>
            <div className="w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden shrink-0">
              <div
                className={`h-full rounded-full ${m.color} transition-all duration-300`}
                style={{ width: `${m.progress}%` }}
              />
            </div>
            <span className="text-[10px] font-semibold text-slate-200 w-9 text-right shrink-0">
              {m.value}
            </span>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="pt-2 mt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span>CHAIN: {cert?.chain_valid !== false ? 'TRUSTED' : 'UNTRUSTED'}</span>
        <span className="text-emerald-400 font-medium">
          {passCount}/{total} CHECKS PASS
        </span>
      </div>
    </div>
  );
};

