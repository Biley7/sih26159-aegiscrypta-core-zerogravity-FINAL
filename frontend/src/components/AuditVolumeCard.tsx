import React from 'react';
import { ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';
import { buildSignalRows, signalColor } from '../scanMetrics';

interface AuditVolumeCardProps {
  className?: string;
  checks?: CheckResult[];
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

export const AuditVolumeCard: React.FC<AuditVolumeCardProps> = ({
  className = '',
  checks = [],
  cryptoPosture,
  onExpand
}) => {
  // Bars map only to checks and protocol probes present in the scan response.
  const bars = buildSignalRows(checks, cryptoPosture);

  const failedCount = checks.filter((c) => c.status === 'fail').length;
  const unknownCount = checks.filter((c) => c.status === 'unknown').length;
  const hasChecks = checks.length > 0;

  // Honest all-clear: only when checks ran and every one is a definite pass.
  const summary = !hasChecks
    ? { label: 'No Check Data', className: 'text-amber-600 dark:text-amber-400' }
    : failedCount > 0
      ? { label: `${failedCount} Failed`, className: 'text-rose-600 dark:text-rose-400' }
      : unknownCount > 0
        ? { label: `${unknownCount} Unknown`, className: 'text-amber-600 dark:text-amber-400' }
        : { label: 'All Checks Healthy', className: 'text-emerald-700 dark:text-emerald-400' };

  return (
    <div className={`${className} bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 rounded-md p-5 transition-colors hover:border-cyan-500/50 flex flex-col justify-between`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="uppercase tracking-[0.2em] text-[10px] sm:text-[11px] font-bold text-slate-500 dark:text-slate-400">
            Audit Volume · Core Inquiries
          </span>
          <span className={`text-[10px] font-mono tracking-widest uppercase ${hasChecks ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-500'}`}>
            {hasChecks ? 'Scanned' : 'Pending'}
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-400 transition-colors"
          title="Inspect Inquiries"
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Bar Chart Container */}
      {bars.length === 0 ? (
        <div className="h-28 flex flex-col items-center justify-center gap-1 px-1 pt-2 pb-1 text-center">
          <span className="text-[11px] font-mono text-slate-600 dark:text-slate-300 tracking-wider">INSUFFICIENT DATA</span>
          <span className="text-[9px] font-mono text-slate-500 dark:text-slate-500 tracking-wider">
            NO CHECKS OR PROTOCOL PROBES IN SCAN RESPONSE
          </span>
        </div>
      ) : (
        <div className="h-28 flex items-end gap-1 px-1 pt-2 pb-1">
          {bars.map((bar, i) => {
            const barColor = signalColor(bar.value);
            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group" title={bar.tooltip}>
                <div className="w-full relative rounded-sm overflow-hidden bg-slate-100 dark:bg-slate-800/60 flex items-end h-full">
                  <div
                    className="w-full rounded-sm transition-all duration-500 group-hover:brightness-110"
                    style={{
                      height: `${bar.value ?? 0}%`,
                      background: `linear-gradient(180deg, ${barColor}cc, ${barColor})`
                    }}
                  />
                </div>
                <span className="text-[9px] font-mono text-cyan-700 dark:text-cyan-400/80 truncate max-w-full tracking-wider">
                  {bar.label}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Bottom Summary Indicator */}
      <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
        <span className="tracking-widest uppercase">{checks.length} Checks Executed</span>
        <span className={`font-semibold tracking-widest uppercase ${summary.className}`}>
          {summary.label}
        </span>
      </div>
    </div>
  );
};
