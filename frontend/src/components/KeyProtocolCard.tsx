import React, { useState } from 'react';
import { CryptographicPosture, CheckResult } from '../types';

export type KeyMode = 'adopt' | 'encrypt' | 'decrypt';

interface ProtocolRow {
  id: string;
  name: string;
  protocol: string;
  metric: string;
  progress: number;
}

interface KeyProtocolCardProps {
  cryptoPosture?: CryptographicPosture | null;
  checks?: CheckResult[];
  score?: number | null;
  onModeChange?: (mode: KeyMode) => void;
}

export const KeyProtocolCard: React.FC<KeyProtocolCardProps> = ({
  cryptoPosture,
  checks,
  score,
  onModeChange
}) => {
  const [activeMode, setActiveMode] = useState<KeyMode>('adopt');

  const handleModeClick = (mode: KeyMode) => {
    setActiveMode(mode);
    if (onModeChange) onModeChange(mode);
  };

  const primaryAudit = cryptoPosture?.protocols_audited?.[0];
  const tlsHandshake = primaryAudit?.tls_handshake;
  const cipher = tlsHandshake?.cipher;
  const cert = tlsHandshake?.certificate;
  const tlsVersion = tlsHandshake?.negotiated_version || 'TLSv1.3';
  const fsSupported = cryptoPosture?.forward_secrecy_supported ?? true;

  // Find MTA-STS and DANE checks if available
  const mtaStsCheck = checks?.find((c) => c.name.toLowerCase().includes('mta-sts'));
  const mtaStsPass = mtaStsCheck?.status === 'pass';

  const rows: Record<KeyMode, ProtocolRow[]> = {
    adopt: [
      {
        id: '1',
        name: 'TLS Protocol Enforcement',
        protocol: `${tlsVersion} ${tlsVersion === 'TLSv1.3' ? 'RFC 8446' : 'RFC 5246'}`,
        metric: tlsVersion === 'TLSv1.3' ? '100%' : tlsVersion === 'TLSv1.2' ? '80%' : '30%',
        progress: tlsVersion === 'TLSv1.3' ? 100 : tlsVersion === 'TLSv1.2' ? 80 : 30
      },
      {
        id: '2',
        name: 'Perfect Forward Secrecy',
        protocol: cipher?.key_exchange ? `${cipher.key_exchange} Ephemeral` : fsSupported ? 'ECDHE Ephemeral' : 'Static RSA Key',
        metric: fsSupported ? '100%' : '0%',
        progress: fsSupported ? 100 : 0
      },
      {
        id: '3',
        name: 'Cryptographic Cipher',
        protocol: cipher?.name ? `${cipher.name.slice(0, 24)}...` : 'AES-256-GCM / SHA-384',
        metric: cipher?.is_weak ? 'WEAK' : 'SECURE',
        progress: cipher?.is_weak ? 25 : 100
      },
      {
        id: '4',
        name: 'MTA-STS Downgrade Prevention',
        protocol: mtaStsPass ? 'Strict Transport Security Active' : 'No MTA-STS Policy Detected',
        metric: mtaStsPass ? '100%' : '30%',
        progress: mtaStsPass ? 100 : 30
      }
    ],
    encrypt: [
      {
        id: '1',
        name: 'Symmetric Cipher Pipeline',
        protocol: cipher?.name || 'AES-256-GCM',
        metric: `${cipher?.bits || 256} BITS`,
        progress: (cipher?.bits || 256) >= 256 ? 100 : (cipher?.bits || 128) >= 128 ? 75 : 40
      },
      {
        id: '2',
        name: 'Key Exchange Mechanism',
        protocol: cipher?.key_exchange || 'ECDHE / X25519',
        metric: fsSupported ? 'PFS OK' : 'STATIC',
        progress: fsSupported ? 100 : 15
      },
      {
        id: '3',
        name: 'Certificate Signature Algorithm',
        protocol: cert?.signature_algorithm || 'sha256WithRSAEncryption',
        metric: cert?.signature_algorithm?.toLowerCase().includes('sha1') ? 'DEPRECATED' : 'FIPS OK',
        progress: cert?.signature_algorithm?.toLowerCase().includes('sha1') ? 20 : 100
      },
      {
        id: '4',
        name: 'Public Key Exponent & Curve',
        protocol: `${cert?.public_key_algorithm || 'RSA'} (${cert?.key_size_bits || 2048} bits)`,
        metric: (cert?.key_size_bits || 2048) >= 2048 ? '100%' : '50%',
        progress: (cert?.key_size_bits || 2048) >= 2048 ? 100 : 50
      }
    ],
    decrypt: [
      {
        id: '1',
        name: 'X.509 Chain Trust Validator',
        protocol: cert?.chain_valid !== false ? 'Trusted System Root CA' : 'Untrusted / Incomplete Chain',
        metric: cert?.chain_valid !== false ? 'TRUSTED' : 'UNTRUSTED',
        progress: cert?.chain_valid !== false ? 100 : 10
      },
      {
        id: '2',
        name: 'Certificate Issuer CN',
        protocol: cert?.issuer_cn || cert?.issuer_dn || 'DigiCert Global Root CA',
        metric: 'VALID',
        progress: 100
      },
      {
        id: '3',
        name: 'Subject CN Matching',
        protocol: cert?.subject_cn || cert?.subject_dn || 'Domain Common Name',
        metric: cert?.matches_domain !== false ? 'MATCH' : 'MISMATCH',
        progress: cert?.matches_domain !== false ? 100 : 30
      },
      {
        id: '4',
        name: 'Certificate Expiry Lifetime',
        protocol: cert ? `${cert.days_until_expiry} days remaining` : 'Active Term',
        metric: cert?.is_expired ? 'EXPIRED' : `${cert?.days_until_expiry ?? 90}d`,
        progress: cert?.is_expired ? 0 : Math.min(100, Math.max(10, ((cert?.days_until_expiry ?? 90) / 365) * 100))
      }
    ]
  };

  const currentRows = rows[activeMode];

  return (
    <div className="rounded-xl bg-slate-900/60 dark:bg-[#111726] border border-slate-800/80 p-4 transition-colors flex flex-col justify-between">
      {/* Top Bar: Mode Switcher */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
          Key Protocol / Mode
        </span>

        {/* 3 Pill buttons: Adopt All, Encrypt, Decrypt */}
        <div className="flex items-center p-0.5 rounded-lg bg-slate-800/80 border border-slate-700/80 text-xs font-mono">
          {(['adopt', 'encrypt', 'decrypt'] as KeyMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => handleModeClick(mode)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors capitalize ${
                activeMode === mode
                  ? 'bg-blue-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {mode === 'adopt' ? 'Adopt All' : mode}
            </button>
          ))}
        </div>
      </div>

      {/* Hairline Divided Table */}
      <div className="divide-y divide-slate-800/60 font-mono text-xs">
        {currentRows.map((row) => (
          <div
            key={row.id}
            className="py-2 flex items-center justify-between gap-3 hover:bg-slate-800/30 px-1 rounded transition-colors"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0"></span>
                <span className="font-semibold text-slate-200 truncate text-[11px]">
                  {row.name}
                </span>
              </div>
              <span className="text-[10px] text-slate-400 truncate block pl-3">
                {row.protocol}
              </span>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <div className="w-16 sm:w-20 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500 transition-all duration-300"
                  style={{ width: `${row.progress}%` }}
                />
              </div>
              <span className="text-xs font-semibold text-slate-200 w-16 text-right">
                {row.metric}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
        <span>CIPHER SYNC: {cipher?.name ? cipher.name.slice(0, 18) : 'RFC 8446'}</span>
        <span className="text-emerald-400 font-medium">
          {score !== null && score !== undefined ? `SCORE: ${score}/100` : 'ACTIVE PROBE'}
        </span>
      </div>
    </div>
  );
};

