import React from 'react';
import { Activity, ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface ActivityTrendCardProps {
  className?: string;
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
  className = '',
  checks = [],
  score,
  cryptoPosture,
  antecedentScores,
  onExpand
}) => {
  const total = checks.length;
  const passCount = checks.filter((c) => c.status === 'pass').length;
  const cert = cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.certificate ?? null;

  // Grade is only shown when the scan returned a score.
  const hasScore = typeof score === 'number' && Number.isFinite(score);
  const grade = hasScore ? (score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 50 ? 'C' : 'F') : null;
  const gradeColor = hasScore
    ? score >= 80
      ? 'text-emerald-700 dark:text-emerald-400'
      : score >= 60
        ? 'text-amber-600 dark:text-amber-400'
        : 'text-rose-600 dark:text-rose-400'
    : 'text-slate-500 dark:text-slate-400';
  const summary = hasScore
    ? score >= 80
      ? 'Latest scan landed in the healthy band. Score is response-derived.'
      : 'Remediation advised based on the latest composite score.'
    : 'Awaiting scan response — no posture score available.';

  // Metric values come from antecedent scores when present, otherwise from
  // explicit posture booleans. Null means "not reported" and renders as N/A.
  const tlsScore = antecedentScores?.tls_compliance != null
    ? Math.round(antecedentScores.tls_compliance * 100)
    : cryptoPosture?.deprecated_tls_found === true
      ? 25
      : cryptoPosture?.deprecated_tls_found === false
        ? 100
        : null;
  const certScore = antecedentScores?.certificate_health != null
    ? Math.round(antecedentScores.certificate_health * 100)
    : cert?.chain_valid === true
      ? 100
      : cert?.chain_valid === false
        ? 30
        : cryptoPosture?.certificate_issues_found === true
          ? 30
          : cryptoPosture?.certificate_issues_found === false
            ? 100
            : null;
  const emailScore = total > 0 ? Math.round((passCount / total) * 100) : null;

  const metrics = [
    { label: 'TLS Protocol Enforcement', value: tlsScore, color: '#0891b2' },
    { label: 'X.509 Chain Health', value: certScore, color: certScore !== null && certScore >= 70 ? '#10b981' : '#f43f5e' },
    { label: 'Email Auth (SPF/DMARC)', value: emailScore, color: '#6366f1' }
  ];

  const chainLabel = cert
    ? cert.chain_valid === true
      ? 'Trusted'
      : cert.chain_valid === false
        ? 'Untrusted'
        : 'Unverified'
    : 'No Cert Data';

  return (
    <div className={`${className} bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 transition-colors hover:border-cyan-500/50 flex flex-col h-auto`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3 shrink-0 min-w-0">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-cyan-600 dark:text-cyan-400" />
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
            Posture Composition · Assurance
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-400 transition-colors"
          title="Inspect Activity Stream"
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Snippet: Badge + Description text */}
      <div className="flex items-center gap-3 my-2 p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 shrink-0 min-w-0">
        <div className="w-10 h-10 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-center shrink-0">
          <span className={`text-lg font-bold font-mono tracking-tight ${gradeColor}`}>
            {grade ?? '—'}
          </span>
        </div>
        <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-snug font-sans">
          {summary}
        </p>
      </div>

      {/* Comparative Progress Bars */}
      <div className="space-y-3 mt-1 font-mono text-[11px] shrink-0">
        {metrics.map((m, idx) => {
          const barColor = m.value === null ? '#94a3b8' : m.color;
          return (
            <div key={idx} className="flex items-center justify-between gap-3">
              <span className="text-[10px] font-medium text-slate-700 dark:text-slate-300 font-sans truncate flex-1 tracking-wide">
                {m.label}
              </span>
              <div className="w-20 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden shrink-0">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${m.value ?? 0}%`,
                    background: barColor
                  }}
                />
              </div>
              <span className={`text-[10px] font-semibold font-mono w-10 text-right shrink-0 tracking-tight ${m.value === null ? 'text-slate-500 dark:text-slate-400' : 'text-cyan-700 dark:text-cyan-400/90'}`}>
                {m.value === null ? 'N/A' : `${m.value}%`}
              </span>
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="mt-auto pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2 text-[10px] font-mono text-slate-500 dark:text-slate-400 shrink-0 min-w-0">
        <span className="tracking-widest uppercase truncate min-w-0" title={`Chain: ${chainLabel}`}>Chain: {chainLabel}</span>
        <span className={`font-semibold tracking-widest uppercase whitespace-nowrap shrink-0 ${total > 0 ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'}`}>
          {total > 0 ? `${passCount}/${total} Checks Pass` : 'No Check Data'}
        </span>
      </div>
    </div>
  );
};
