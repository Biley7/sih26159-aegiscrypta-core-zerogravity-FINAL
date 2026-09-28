import React from 'react';
import { ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture, ScanResponse } from '../types';

interface ActiveReportCardProps {
  className?: string;
  checks?: CheckResult[];
  score?: number | null;
  cryptoPosture?: CryptographicPosture | null;
  scanData?: ScanResponse | null;
  onExpand?: () => void;
}

export const ActiveReportCard: React.FC<ActiveReportCardProps> = ({
  className = '',
  checks = [],
  score,
  cryptoPosture,
  scanData,
  onExpand
}) => {
  const activeChecks = scanData?.checks ?? checks;
  const activeScore = scanData?.security_score ?? scanData?.score ?? score ?? null;
  const activeCryptoPosture = scanData?.crypto_posture ?? cryptoPosture ?? null;
  const total = activeChecks.length;
  const passCount = activeChecks.filter((c) => c.status === 'pass').length;
  const warnCount = activeChecks.filter((c) => c.status === 'warn').length;
  const failCount = activeChecks.filter((c) => c.status === 'fail').length;

  const share = (count: number) => (total > 0 ? `${Math.round((count / total) * 100)}%` : 'N/A');
  const fsPct = activeCryptoPosture ? (activeCryptoPosture.forward_secrecy_supported ? '100%' : '0%') : 'N/A';

  // Real scan statistics — "N/A" whenever the response has no checks.
  const stats = [
    { value: share(passCount), label: 'Pass' },
    { value: share(warnCount), label: 'Warn' },
    { value: share(failCount), label: 'Critical' },
    { value: fsPct, label: 'PFS' }
  ];

  return (
    <div className={`${className} bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-lg p-5 transition-colors hover:border-cyan-500/50 flex flex-col justify-between`}>
      {/* Top Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
            Active Security Report
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 dark:bg-cyan-400 animate-pulse"></span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono tracking-tight text-slate-600 dark:text-slate-400">
            {activeScore !== null && activeScore !== undefined ? `${activeScore}/100` : 'N/A'}
          </span>
          <button
            type="button"
            onClick={onExpand}
            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-400 transition-colors"
            title="Open Report Details"
          >
            <ChevronRight size={15} />
          </button>
        </div>
      </div>

      {/* No historical time series is returned by the scan API, so this panel
          shows an explicit flatline instead of an invented trend curve. */}
      <div className="relative w-full h-28 my-auto py-1">
        <svg
          viewBox="0 0 240 90"
          className="w-full h-full"
          preserveAspectRatio="none"
          role="img"
          aria-label="Insufficient historical data for a posture trend"
        >
          {/* Grid lines */}
          <line x1="10" y1="25" x2="230" y2="25" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />
          <line x1="10" y1="55" x2="230" y2="55" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />
          <line x1="10" y1="78" x2="230" y2="78" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />

          {/* Flatline indicating absence of time-series observations */}
          <line
            x1="12"
            y1="55"
            x2="228"
            y2="55"
            className="stroke-slate-300 dark:stroke-slate-600"
            strokeWidth="1.5"
            strokeDasharray="5 4"
          />

          <text x="120" y="42" textAnchor="middle" className="fill-slate-500" fontSize="9" fontFamily="monospace" letterSpacing="1">
            INSUFFICIENT DATA
          </text>
          <text x="120" y="68" textAnchor="middle" className="fill-slate-500 dark:fill-slate-500" fontSize="6.5" fontFamily="monospace">
            NO HISTORICAL TIME SERIES IN SCAN RESPONSE
          </text>
        </svg>
      </div>

      {/* Stats Bar */}
      <div className="pt-3 border-t border-slate-200 dark:border-slate-800 grid grid-cols-4 gap-1.5 text-center font-mono">
        {stats.map((st, i) => (
          <div key={i} className="flex flex-col gap-0.5">
            <span className={`text-xs font-bold font-mono tracking-tight ${
              st.value === 'N/A' ? 'text-slate-500 dark:text-slate-400' :
              st.label === 'Critical' ? 'text-rose-600 dark:text-rose-400' :
              st.label === 'Warn' ? 'text-amber-600 dark:text-amber-400' :
              st.label === 'PFS' ? 'text-cyan-700 dark:text-cyan-400' : 'text-emerald-700 dark:text-emerald-400'
            }`}>
              {st.value}
            </span>
            <span className="text-[9px] text-slate-500 dark:text-slate-400 tracking-[0.2em] uppercase">
              {st.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
