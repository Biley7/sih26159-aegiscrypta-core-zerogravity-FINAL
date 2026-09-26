import React from 'react';
import { MailCheck, ArrowUpRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface EmailCredentialsCardProps {
  checks?: CheckResult[];
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

export const EmailCredentialsCard: React.FC<EmailCredentialsCardProps> = ({
  checks = [],
  cryptoPosture,
  onExpand
}) => {
  // Extract key email auth and crypto statuses
  const spfPass = checks.some((c) => c.name.toLowerCase().includes('spf') && c.status === 'pass');
  const dkimPass = checks.some((c) => c.name.toLowerCase().includes('dkim') && c.status === 'pass');
  const dmarcPass = checks.some((c) => c.name.toLowerCase().includes('dmarc') && c.status === 'pass');
  const mtaStsPass = checks.some((c) => c.name.toLowerCase().includes('mta-sts') && c.status === 'pass');
  const starttlsPass = checks.some((c) => c.name.toLowerCase().includes('starttls') && c.status === 'pass');
  const fsPass = cryptoPosture?.forward_secrecy_supported ?? true;
  const certPass = cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.certificate?.chain_valid !== false;

  const authItems = [
    { name: 'SPF', pass: spfPass },
    { name: 'DKIM', pass: dkimPass },
    { name: 'DMARC', pass: dmarcPass },
    { name: 'MTA-STS', pass: mtaStsPass },
    { name: 'STARTTLS', pass: starttlsPass },
    { name: 'FORWARD SEC', pass: fsPass },
    { name: 'CERT TRUST', pass: certPass }
  ];

  const totalEvaluated = authItems.length;
  const totalPassed = authItems.filter((i) => i.pass).length;

  // Dynamically compute SVG coordinates across the 270x90 canvas
  // Pass -> higher on graph (lower y, e.g. 20-35), Fail -> lower on graph (higher y, e.g. 65-75)
  const xPositions = [15, 52, 90, 128, 165, 202, 240];
  const line1Points = authItems.map((item, idx) => ({
    x: xPositions[idx] || (idx * 35 + 15),
    y: item.pass ? 22 + (idx % 2 === 0 ? 0 : 8) : 68 + (idx % 2 === 0 ? 4 : 0)
  }));

  // Baseline standard line
  const line2Points = [
    { x: 15, y: 55 },
    { x: 52, y: 50 },
    { x: 90, y: 48 },
    { x: 128, y: 52 },
    { x: 165, y: 45 },
    { x: 202, y: 50 },
    { x: 240, y: 46 }
  ];

  const line1Path = `M ${line1Points.map((p) => `${p.x} ${p.y}`).join(' L ')}`;
  const line2Path = `M ${line2Points.map((p) => `${p.x} ${p.y}`).join(' L ')}`;

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <MailCheck size={14} className="text-slate-400" />
          <span className="text-xs font-semibold text-slate-100 tracking-tight font-sans">
            Email Authentication &amp; TLS Credentials
          </span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Inspect Handshakes"
        >
          <ArrowUpRight size={14} />
        </button>
      </div>

      {/* Dual Line Chart */}
      <div className="relative w-full h-26 my-auto">
        <svg
          viewBox="0 0 270 90"
          className="w-full h-full overflow-visible"
          preserveAspectRatio="none"
        >
          {/* Grid lines */}
          <line x1="5" y1="20" x2="265" y2="20" stroke="#1e293b" strokeDasharray="3 3" />
          <line x1="5" y1="50" x2="265" y2="50" stroke="#1e293b" strokeDasharray="3 3" />
          <line x1="5" y1="80" x2="265" y2="80" stroke="#1e293b" strokeDasharray="3 3" />

          {/* Secondary Baseline Line */}
          <path
            d={line2Path}
            fill="none"
            stroke="#64748b"
            strokeWidth="1.5"
            strokeDasharray="4 3"
          />

          {/* Primary Scan Results Line */}
          <path
            d={line1Path}
            fill="none"
            stroke="#3b82f6"
            strokeWidth="2"
            strokeLinecap="round"
          />

          {line1Points.map((pt, i) => (
            <circle
              key={i}
              cx={pt.x}
              cy={pt.y}
              r="3"
              fill="#090d16"
              stroke={authItems[i]?.pass ? '#10b981' : '#f43f5e'}
              strokeWidth="2"
            />
          ))}
        </svg>
      </div>

      {/* Axis & Legend */}
      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-0.5 bg-blue-500 inline-block"></span>
            <span>Audited Vector</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-0.5 bg-slate-500 inline-block"></span>
            <span>Policy Baseline</span>
          </span>
        </div>
        <span className="text-emerald-400 font-semibold">
          {totalPassed}/{totalEvaluated} ALIGNED
        </span>
      </div>
    </div>
  );
};

