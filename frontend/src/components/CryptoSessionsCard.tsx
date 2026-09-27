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
    <div className={`${className} bg-[#0c1220]/80 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-lg shadow-black/20 hover:border-cyan-500/30 transition-all duration-200 flex flex-col justify-between`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <span className="text-[11px] font-semibold tracking-widest text-slate-400 uppercase block">
            Audit Certification · Real-Time
          </span>
          <h3 className="text-sm font-semibold text-slate-100 tracking-tight mt-1">
            Email Cryptographic Sessions
          </h3>
        </div>
        <button
          type="button"
          onClick={onExplore}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
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
              stroke="#1e293b"
              strokeWidth="6"
              fill="transparent"
            />
            {hasScore && (
              <circle
                cx="45"
                cy="45"
                r={radius}
                stroke="#00f0ff"
                strokeWidth="6"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-700 ease-out"
                style={{
                  filter: 'drop-shadow(0 0 4px rgba(0, 240, 255, 0.35))'
                }}
              />
            )}
          </svg>

          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className={`text-xl font-bold font-mono ${hasScore ? 'text-slate-100' : 'text-slate-500'}`}>
              {hasScore ? `${gaugePct}%` : 'N/A'}
            </span>
            <span className="text-[9px] font-mono text-cyan-400/90 tracking-wider uppercase">
              POSTURE SCORE
            </span>
          </div>
        </div>

        {/* Counters */}
        <div className="flex-1 space-y-3 min-w-0">
          <div>
            <div className="flex items-baseline justify-between text-xs mb-1.5">
              <span className="text-slate-400 text-[11px] tracking-wide uppercase">Checks Executed</span>
              <span className="text-[10px] font-mono text-cyan-400/90 tracking-wider">
                {checkList.length > 0 ? `${passCount} passed` : 'No checks reported'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-base font-bold font-mono text-cyan-400/90 tracking-wider">
                {checkList.length}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-900 overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${checkBarPct}%`,
                    background: 'linear-gradient(90deg, #00f0ff, #0ea5e9)',
                    boxShadow: '0 0 6px rgba(0, 240, 255, 0.35)'
                  }}
                />
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-baseline justify-between text-xs mb-1.5">
              <span className="text-slate-400 text-[11px] tracking-wide uppercase">Protocols Audited</span>
              <span className="text-[10px] font-mono text-emerald-400 tracking-wider">
                {protocols.length > 0 ? `${negotiatedCount} negotiated` : 'No probes reported'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-base font-bold font-mono text-emerald-400 tracking-wider">
                {protocols.length}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-900 overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${handshakeBarPct}%`,
                    background: 'linear-gradient(90deg, #10b981, #059669)',
                    boxShadow: '0 0 6px rgba(16, 185, 129, 0.35)'
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Pill Status */}
      <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span className="flex items-center gap-1.5 tracking-wider">
          <span className={`w-1.5 h-1.5 rounded-full ${hasPosture ? 'bg-[#00f0ff] animate-pulse' : 'bg-slate-600'}`}></span>
          <span className={hasPosture ? 'text-cyan-400/90 tracking-wider' : 'text-slate-500 tracking-wider'}>
            {hasPosture
              ? pqcEvaluated
                ? 'PQC indicators evaluated'
                : 'PQC indicators not evaluated'
              : 'No crypto posture data'}
          </span>
        </span>
        <span className={`font-semibold tracking-widest uppercase ${checkList.length > 0 ? 'text-emerald-400' : 'text-slate-500'}`}>
          {checkList.length > 0 ? `${passCount}/${checkList.length} Pass` : 'Awaiting scan'}
        </span>
      </div>
    </div>
  );
};
