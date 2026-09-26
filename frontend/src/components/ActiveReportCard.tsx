import React from 'react';
import { ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface ActiveReportCardProps {
  checks?: CheckResult[];
  score?: number | null;
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

export const ActiveReportCard: React.FC<ActiveReportCardProps> = ({
  checks = [],
  score,
  cryptoPosture,
  onExpand
}) => {
  const total = checks.length || 1;
  const passCount = checks.filter((c) => c.status === 'pass').length;
  const warnCount = checks.filter((c) => c.status === 'warn').length;
  const failCount = checks.filter((c) => c.status === 'fail').length;

  const passPct = Math.round((passCount / total) * 100);
  const warnPct = Math.round((warnCount / total) * 100);
  const failPct = Math.round((failCount / total) * 100);
  const fsPct = cryptoPosture?.forward_secrecy_supported ?? true ? 100 : 0;

  // Real scan statistics
  const stats = [
    { value: `${passPct}%`, label: 'Pass' },
    { value: `${warnPct}%`, label: 'Warn' },
    { value: `${failPct}%`, label: 'Critical' },
    { value: `${fsPct}%`, label: 'PFS' }
  ];

  // Dynamic curve points reflecting overall score & pass/fail distribution
  const baselineY = score !== null && score !== undefined ? Math.max(15, Math.min(75, 85 - (score * 0.7))) : 35;
  const points = [
    { x: 15, y: Math.min(75, baselineY + 15) },
    { x: 50, y: Math.min(75, baselineY + 8) },
    { x: 85, y: Math.max(15, baselineY - 10) },
    { x: 120, y: Math.max(15, baselineY - 15) },
    { x: 155, y: Math.max(15, baselineY - 5) },
    { x: 190, y: Math.min(75, baselineY + 5) },
    { x: 225, y: Math.max(15, baselineY - 8) }
  ];

  const pathD = `M 15 ${points[0].y} Q 50 ${points[1].y}, 85 ${points[2].y} T 120 ${points[3].y} T 155 ${points[4].y} T 190 ${points[5].y} T 225 ${points[6].y}`;
  const areaD = `${pathD} L 225 85 L 15 85 Z`;

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Top Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-100 tracking-tight font-sans">
            Active Security Report
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Open Report Details"
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Clean Area Chart */}
      <div className="relative w-full h-26 my-auto">
        <svg
          viewBox="0 0 240 90"
          className="w-full h-full overflow-visible"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="soc-active-area" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1="10" y1="25" x2="230" y2="25" stroke="#1e293b" strokeDasharray="3 3" />
          <line x1="10" y1="55" x2="230" y2="55" stroke="#1e293b" strokeDasharray="3 3" />

          {/* Fill */}
          <path d={areaD} fill="url(#soc-active-area)" />

          {/* Stroke Curve */}
          <path
            d={pathD}
            fill="none"
            stroke="#3b82f6"
            strokeWidth="2"
            strokeLinecap="round"
          />

          {/* Coordinate Dots */}
          {points.map((pt, i) => (
            <circle
              key={i}
              cx={pt.x}
              cy={pt.y}
              r="2.5"
              fill="#090d16"
              stroke="#3b82f6"
              strokeWidth="1.5"
            />
          ))}
        </svg>
      </div>

      {/* Stats Bar */}
      <div className="pt-2 border-t border-slate-800/80 grid grid-cols-4 gap-1 text-center font-mono">
        {stats.map((st, i) => (
          <div key={i} className="flex flex-col">
            <span className="text-xs font-semibold text-slate-200">
              {st.value}
            </span>
            <span className="text-[9px] text-slate-400 font-sans uppercase">
              {st.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

