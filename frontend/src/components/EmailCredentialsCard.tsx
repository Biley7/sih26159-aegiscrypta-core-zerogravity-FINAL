import React from 'react';
import { MailCheck, ArrowUpRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface EmailCredentialsCardProps {
  className?: string;
  checks?: CheckResult[];
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

type AuthState = 'pass' | 'warn' | 'fail' | 'unknown';

function stateFromCheck(check: CheckResult | undefined): AuthState {
  if (!check) return 'unknown';
  switch (check.status) {
    case 'pass':
      return 'pass';
    case 'warn':
      return 'warn';
    case 'fail':
      return 'fail';
    default:
      return 'unknown';
  }
}

const STATE_COLORS: Record<AuthState, string> = {
  pass: '#10b981',
  warn: '#f59e0b',
  fail: '#f43f5e',
  unknown: '#94a3b8'
};

export const EmailCredentialsCard: React.FC<EmailCredentialsCardProps> = ({
  className = '',
  checks = [],
  cryptoPosture,
  onExpand
}) => {
  const findCheck = (fragment: string) => checks.find((c) => c.name.toLowerCase().includes(fragment));
  const cert = cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.certificate ?? null;

  // Missing forward secrecy or chain data must never be coerced to a pass.
  const authItems: { name: string; short: string; state: AuthState }[] = [
    { name: 'SPF', short: 'SPF', state: stateFromCheck(findCheck('spf')) },
    { name: 'DKIM', short: 'DKIM', state: stateFromCheck(findCheck('dkim')) },
    { name: 'DMARC', short: 'DMARC', state: stateFromCheck(findCheck('dmarc')) },
    { name: 'MTA-STS', short: 'STS', state: stateFromCheck(findCheck('mta-sts')) },
    { name: 'STARTTLS', short: 'TLS', state: stateFromCheck(findCheck('starttls')) },
    {
      name: 'FORWARD SEC',
      short: 'PFS',
      state: cryptoPosture ? (cryptoPosture.forward_secrecy_supported ? 'pass' : 'fail') : 'unknown'
    },
    {
      name: 'CERT TRUST',
      short: 'CERT',
      state: cert?.chain_valid === true ? 'pass' : cert?.chain_valid === false ? 'fail' : 'unknown'
    }
  ];

  const totalEvaluated = authItems.length;
  const totalPassed = authItems.filter((i) => i.state === 'pass').length;
  const unknownCount = authItems.filter((i) => i.state === 'unknown').length;

  // The line encodes per-check status only (no fabricated time-series baseline).
  const xPositions = [15, 52, 90, 128, 165, 202, 240];
  const yForState = (state: AuthState, idx: number): number => {
    const offset = idx % 2 === 0 ? 0 : 6;
    switch (state) {
      case 'pass':
        return 22 + offset;
      case 'warn':
        return 45 + offset;
      case 'fail':
        return 68;
      default:
        return 45;
    }
  };
  const line1Points = authItems.map((item, idx) => ({
    x: xPositions[idx] ?? idx * 35 + 15,
    y: yForState(item.state, idx)
  }));

  const line1Path = `M ${line1Points.map((p) => `${p.x} ${p.y}`).join(' L ')}`;

  return (
    <div className={`${className} bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 rounded-md p-5 transition-colors hover:border-cyan-500/50 flex flex-col justify-between`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <MailCheck size={15} className="text-cyan-600 dark:text-cyan-400" />
          <span className="uppercase tracking-[0.2em] text-[10px] sm:text-[11px] font-bold text-slate-500 dark:text-slate-400">
            Email Auth · TLS Credentials
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-cyan-700 dark:hover:text-cyan-400 transition-colors"
          title="Inspect Handshakes"
        >
          <ArrowUpRight size={14} />
        </button>
      </div>

      {/* Per-check status line */}
      <div className="relative w-full h-28 my-auto">
        <svg
          viewBox="0 0 270 90"
          className="w-full h-full"
          preserveAspectRatio="none"
        >
          {/* Grid lines */}
          <line x1="5" y1="20" x2="265" y2="20" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />
          <line x1="5" y1="50" x2="265" y2="50" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />
          <line x1="5" y1="80" x2="265" y2="80" className="stroke-slate-200 dark:stroke-slate-800" strokeDasharray="3 3" />

          {/* Latest scan results, one point per check */}
          <path
            d={line1Path}
            fill="none"
            className="stroke-cyan-600 dark:stroke-cyan-400"
            strokeWidth="2.2"
            strokeLinecap="round"
          />

          {line1Points.map((pt, i) => {
            const state = authItems[i]?.state ?? 'unknown';
            return (
              <circle
                key={i}
                cx={pt.x}
                cy={pt.y}
                r="3"
                className="fill-white dark:fill-slate-900"
                stroke={STATE_COLORS[state]}
                strokeWidth="2"
                strokeDasharray={state === 'unknown' ? '2 2' : undefined}
              />
            );
          })}

          {/* Categorical x-axis labels (not a time series) */}
          {line1Points.map((pt, i) => (
            <text
              key={`label-${i}`}
              x={pt.x}
              y="88"
              textAnchor="middle"
              className="fill-slate-500 dark:fill-slate-500"
              fontSize="6.5"
              fontFamily="monospace"
            >
              {authItems[i]?.short}
            </text>
          ))}
        </svg>
      </div>

      {/* Axis & Legend */}
      <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-600 dark:text-slate-400">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 inline-block bg-cyan-600 dark:bg-cyan-400"></span>
            <span className="tracking-widest uppercase">Latest scan checks</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full inline-block border-2 border-slate-500 dark:border-slate-400"></span>
            <span className="tracking-widest uppercase">Unknown</span>
          </span>
        </div>
        <span className={`font-semibold tracking-widest uppercase ${unknownCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
          {totalPassed}/{totalEvaluated} Passed{unknownCount > 0 ? ` · ${unknownCount} N/A` : ''}
        </span>
      </div>
    </div>
  );
};
