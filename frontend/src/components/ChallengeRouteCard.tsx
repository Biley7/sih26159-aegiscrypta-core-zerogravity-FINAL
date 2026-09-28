import React from 'react';
import { Route, ArrowUpRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';
import { buildSignalRows, signalColor } from '../scanMetrics';

interface ChallengeRouteCardProps {
  className?: string;
  checks?: CheckResult[];
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

export const ChallengeRouteCard: React.FC<ChallengeRouteCardProps> = ({
  className = '',
  checks = [],
  cryptoPosture,
  onExpand
}) => {
  // Every bar maps to a check or protocol probe present in the scan response.
  const signals = buildSignalRows(checks, cryptoPosture);
  const totalProbes = signals.length;
  const passedProbes = signals.filter((s) => s.value !== null && s.value >= 70).length;
  const unknownProbes = signals.filter((s) => s.value === null).length;

  return (
    <div className={`${className} bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-lg p-5 transition-colors hover:border-cyan-500/50 flex flex-col justify-between`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Route size={15} className="text-emerald-600 dark:text-emerald-400" />
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
            Challenge Routes · Ingress Probes
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
          title="Inspect Routes"
        >
          <ArrowUpRight size={14} />
        </button>
      </div>

      {/* Bar Chart */}
      {totalProbes === 0 ? (
        <div className="h-28 flex flex-col items-center justify-center gap-1 px-1 pt-2 pb-1 text-center">
          <span className="text-[11px] font-mono text-slate-600 dark:text-slate-300 tracking-wider">INSUFFICIENT DATA</span>
          <span className="text-[9px] font-mono text-slate-500 dark:text-slate-500 tracking-wider">
            NO CHECKS OR PROTOCOL PROBES IN SCAN RESPONSE
          </span>
        </div>
      ) : (
        <div className="h-28 flex items-end gap-1 px-1 pt-2 pb-1">
          {signals.map((m, i) => {
            const c = signalColor(m.value);
            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group" title={m.tooltip}>
                <div className="w-full relative rounded-sm overflow-hidden bg-slate-100 dark:bg-slate-800/60 flex items-end h-full">
                  <div
                    className="w-full rounded-sm transition-all duration-500 group-hover:brightness-110"
                    style={{
                      height: `${m.value ?? 0}%`,
                      background: `linear-gradient(180deg, ${c}cc, ${c})`
                    }}
                  />
                </div>
                <span className="text-[8px] font-mono text-cyan-700 dark:text-cyan-400/80 truncate max-w-full tracking-wider">
                  {m.label}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Footer Metrics */}
      <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
        <span className="tracking-widest uppercase">
          {totalProbes > 0 ? `${totalProbes} Signals Audited` : 'No Signals Audited'}
        </span>
        <span className={`font-semibold tracking-widest uppercase ${totalProbes === 0 ? 'text-slate-500 dark:text-slate-500' : 'text-emerald-700 dark:text-emerald-400'}`}>
          {totalProbes === 0
            ? 'Insufficient Data'
            : `${passedProbes}/${totalProbes} OK${unknownProbes > 0 ? ` · ${unknownProbes} N/A` : ''}`}
        </span>
      </div>
    </div>
  );
};
