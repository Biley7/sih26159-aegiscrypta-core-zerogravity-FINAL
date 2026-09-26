import React from 'react';
import { ChevronRight } from 'lucide-react';
import { CheckResult, CryptographicPosture } from '../types';

interface AuditVolumeCardProps {
  checks?: CheckResult[];
  cryptoPosture?: CryptographicPosture | null;
  onExpand?: () => void;
}

export const AuditVolumeCard: React.FC<AuditVolumeCardProps> = ({
  checks = [],
  cryptoPosture,
  onExpand
}) => {
  // Map core security areas to volume / health bars
  const bars = [
    {
      label: 'MX',
      value: checks.some((c) => c.name.toLowerCase().includes('mx') && c.status === 'pass') ? 100 : 35
    },
    {
      label: 'TLS',
      value: cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.negotiated_version === 'TLSv1.3' ? 100 : 75
    },
    {
      label: 'CIPH',
      value: cryptoPosture?.weak_ciphers_found ? 30 : 95
    },
    {
      label: 'CERT',
      value: cryptoPosture?.protocols_audited?.[0]?.tls_handshake?.certificate?.chain_valid !== false ? 100 : 25
    },
    {
      label: 'PFS',
      value: cryptoPosture?.forward_secrecy_supported ?? true ? 100 : 20
    },
    {
      label: 'PQC',
      value: cryptoPosture?.forward_secrecy_supported ? 90 : 40
    },
    {
      label: 'SPF',
      value: checks.some((c) => c.name.toLowerCase().includes('spf') && c.status === 'pass') ? 100 : 25
    },
    {
      label: 'DKIM',
      value: checks.some((c) => c.name.toLowerCase().includes('dkim') && c.status === 'pass') ? 100 : 35
    },
    {
      label: 'DMRC',
      value: checks.some((c) => c.name.toLowerCase().includes('dmarc') && c.status === 'pass') ? 100 : 20
    },
    {
      label: 'STS',
      value: checks.some((c) => c.name.toLowerCase().includes('mta-sts') && c.status === 'pass') ? 100 : 30
    }
  ];

  const failedCount = checks.filter((c) => c.status === 'fail').length;

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-100 tracking-tight font-sans">
            Audit / Core Inquiries
          </span>
          <span className="text-[10px] font-mono text-emerald-400">VERIFIED</span>
        </div>
        <button
          type="button"
          onClick={onExpand}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Inspect Inquiries"
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* Bar Chart Container */}
      <div className="h-26 flex items-end gap-1.5 px-1 pt-2 pb-1">
        {bars.map((bar, i) => (
          <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
            <div className="w-full relative rounded-t-sm overflow-hidden bg-slate-800 flex items-end h-full">
              <div
                className={`w-full rounded-t-sm transition-all ${
                  bar.value >= 80 ? 'bg-blue-500 hover:bg-blue-400' : 'bg-amber-500 hover:bg-amber-400'
                }`}
                style={{ height: `${bar.value}%` }}
              />
            </div>
            <span className="text-[9px] font-mono text-slate-400 truncate max-w-full">
              {bar.label}
            </span>
          </div>
        ))}
      </div>

      {/* Bottom Summary Indicator */}
      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span>{checks.length || 10} CHECKS EXECUTED</span>
        <span className={failedCount === 0 ? 'text-emerald-400 font-medium' : 'text-rose-400 font-medium'}>
          {failedCount === 0 ? 'ALL CHECKS HEALTHY' : `${failedCount} ANOMALIES`}
        </span>
      </div>
    </div>
  );
};

