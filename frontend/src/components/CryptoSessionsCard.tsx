import React from 'react';
import { ArrowUpRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface CryptoSessionsCardProps {
  className?: string;
  score?: number | null;
  checks?: CheckResult[] | null;
  cryptoPosture?: CryptographicPosture | null;
  onExplore?: () => void;
}

export const CryptoSessionsCard: React.FC<CryptoSessionsCardProps> = ({
  className = '',
  score = null,
  checks,
  cryptoPosture = null,
  onExplore
}) => {
  const checkList = checks ?? [];
  const protocols = cryptoPosture?.protocols_audited ?? [];

  const passCount = checkList.filter((c) => c.status === 'pass').length;
  const evaluatedChecks = checkList.filter((c) => c.status !== 'unknown').length;
  const negotiatedCount = protocols.filter((p) => p.tls_handshake?.success === true).length;
  const handshakeReported = protocols.filter((p) => p.tls_handshake != null).length;

  const hasScore = typeof score === 'number' && Number.isFinite(score);
  const gaugePct = hasScore ? Math.max(0, Math.min(100, Math.round(score as number))) : 0;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (gaugePct / 100) * circumference;

  const checkBarPct = evaluatedChecks > 0 ? Math.round((passCount / evaluatedChecks) * 100) : 0;
  const handshakeBarPct = handshakeReported > 0 ? Math.round((negotiatedCount / handshakeReported) * 100) : 0;
  const pqcEvaluated = cryptoPosture?.pqc_indicators_evaluated === true;
  const hasPosture = cryptoPosture !== null;

  return (
    <div className={`${className} bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-md p-5 transition-colors hover:border-cyan-500/50 flex flex-col justify-between`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <span className="text-[11px] font-semibold tracking-widest text-slate-500 dark:text-slate-400 uppercase block">
            Audit Certification · Real-Time
          </span>
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100 tracking-tight mt-1">
            Email Cryptographic Sessions
          </h3>
        </div>
        <button
          type="button"
          onClick={onExplore}
          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
          title="Expand Session Details"
        >
          <ArrowUpRight size={14} />
        </button>
      </div>

      {/* Main: Gauge + Counters */}
      <div className="flex items-center gap-6 my-auto py-2">
        {/* Radial Gauge */}
        <div className="relative flex items-center justify-center shrink-0 w-24 h-24">
          <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 90 90">
            <circle
              cx="45"
              cy="45"
              r={radius}
              className="stroke-slate-200 dark:stroke-slate-800"
              strokeWidth="6"
              fill="transparent"
            />
            {hasScore && (
              <circle
                cx="45"
                cy="45"
                r={radius}
                className="stroke-cyan-500 dark:stroke-[#00f0ff]"
                strokeWidth="6"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: 'stroke-dashoffset 0.7s ease-out' }}
              />
            )}
          </svg>

          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className={`text-xl font-bold font-mono ${hasScore ? 'text-slate-800 dark:text-slate-100' : 'text-slate-400 dark:text-slate-500'}`}>
              {hasScore ? `${gaugePct}%` : 'N/A'}
            </span>
            <span className="text-[9px] font-mono text-cyan-700 dark:text-cyan-400 tracking-wider uppercase">
              POSTURE SCORE
            </span>
          </div>
        </div>

        {/* Counters */}
        <div className="flex-1 space-y-3 min-w-0">
          <div>
            <div className="flex items-baseline justify-between text-xs mb-1.5">
              <span className="text-slate-500 dark:text-slate-400 text-[11px] tracking-wide uppercase">Checks Executed</span>
              <span className="text-[10px] font-mono text-cyan-700 dark:text-cyan-400 tracking-wider">
                {checkList.length > 0 ? `${passCount} passed` : 'No checks reported'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-base font-bold font-mono text-cyan-700 dark:text-cyan-400 tracking-wider">
                {checkList.length}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-cyan-500 dark:bg-cyan-400"
                  style={{ width: `${checkBarPct}%` }}
                />
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-baseline justify-between text-xs mb-1.5">
              <span className="text-slate-500 dark:text-slate-400 text-[11px] tracking-wide uppercase">Protocols Audited</span>
              <span className="text-[10px] font-mono text-emerald-700 dark:text-emerald-400 tracking-wider">
                {protocols.length > 0 ? `${negotiatedCount} negotiated` : 'No probes reported'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-base font-bold font-mono text-emerald-700 dark:text-emerald-400 tracking-wider">
                {protocols.length}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-emerald-500"
                  style={{ width: `${handshakeBarPct}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Pill Status */}
      <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
        <span className="flex items-center gap-1.5 tracking-wider">
          <span className={`w-1.5 h-1.5 rounded-full ${hasPosture ? 'bg-cyan-500 dark:bg-cyan-400 animate-pulse' : 'bg-slate-400 dark:bg-slate-600'}`}></span>
          <span className={hasPosture ? 'text-cyan-700 dark:text-cyan-400 tracking-wider' : 'text-slate-500 dark:text-slate-500 tracking-wider'}>
            {hasPosture
              ? pqcEvaluated
                ? 'PQC indicators evaluated'
                : 'PQC indicators not evaluated'
              : 'No crypto posture data'}
          </span>
        </span>
        <span className={`font-semibold tracking-widest uppercase ${checkList.length > 0 ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-500'}`}>
          {checkList.length > 0 ? `${passCount}/${checkList.length} Pass` : 'Awaiting scan'}
        </span>
      </div>
    </div>
  );
};
