import React from 'react';
import { ArrowUpRight } from 'lucide-react';

interface CryptoSessionsCardProps {
  percentage?: number;
  recentCount?: number;
  middleRangeCount?: number;
  activeRate?: string;
  onExplore?: () => void;
}

export const CryptoSessionsCard: React.FC<CryptoSessionsCardProps> = ({
  percentage = 30,
  recentCount = 300,
  middleRangeCount = 558,
  activeRate = '99.4%',
  onExplore
}) => {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
            Audit Certification
          </span>
          <h3 className="text-sm font-semibold text-slate-100 tracking-tight mt-0.5">
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
      <div className="flex items-center gap-5 my-auto">
        {/* Radial Gauge */}
        <div className="relative flex items-center justify-center shrink-0 w-22 h-22">
          <svg className="w-22 h-22 transform -rotate-90" viewBox="0 0 90 90">
            <circle
              cx="45"
              cy="45"
              r={radius}
              stroke="#1e293b"
              strokeWidth="6"
              fill="transparent"
            />
            <circle
              cx="45"
              cy="45"
              r={radius}
              stroke="#3b82f6"
              strokeWidth="6"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-700 ease-out"
            />
          </svg>

          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-lg font-bold font-mono text-slate-100">
              {percentage}%
            </span>
            <span className="text-[8px] font-mono text-slate-400 uppercase">
              VERIFIED
            </span>
          </div>
        </div>

        {/* Counters */}
        <div className="flex-1 space-y-2.5 min-w-0">
          <div>
            <div className="flex items-baseline justify-between text-xs mb-1">
              <span className="text-slate-400 text-[11px]">Recent Requests</span>
              <span className="text-[10px] font-mono text-slate-400">6.3% / 5.31%</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold font-mono text-slate-100">
                {recentCount}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500"
                  style={{ width: '64%' }}
                />
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-baseline justify-between text-xs mb-1">
              <span className="text-slate-400 text-[11px]">Middle Range</span>
              <span className="text-[10px] font-mono text-emerald-400">8.2% / 10.15%</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold font-mono text-slate-100">
                {middleRangeCount}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-emerald-500"
                  style={{ width: '48%' }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Pill Status */}
      <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
          <span>FIPS-203 Post-Quantum Session State</span>
        </span>
        <span className="text-emerald-400 font-medium">{activeRate} PASS</span>
      </div>
    </div>
  );
};
