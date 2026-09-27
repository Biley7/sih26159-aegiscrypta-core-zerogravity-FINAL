import React, { useState } from 'react';
import { CryptographicPosture, CheckResult, ScanResponse } from '../types';
import { statusToScore } from '../scanMetrics';

export type KeyMode = 'adopt' | 'encrypt' | 'decrypt';

interface ProtocolRow {
  id: string;
  name: string;
  protocol: string;
  metric: string;
  progress: number;
  unknown: boolean;
}

interface KeyProtocolCardProps {
  className?: string;
  cryptoPosture?: CryptographicPosture | null;
  checks?: CheckResult[];
  score?: number | null;
  scanData?: ScanResponse | null;
  onModeChange?: (mode: KeyMode) => void;
}

function normalizeTlsVersion(value: string): string {
  return value.replace(/^TLSv/i, 'TLS ').replace(/^TLS(\d)/i, 'TLS $1');
}

function keyStrengthProgress(algorithm?: string | null, bits?: number | null): number | null {
  if (bits == null || !Number.isFinite(bits)) return null;
  const upper = (algorithm || '').toUpperCase();
  const isEllipticCurve = upper.includes('ECC') || upper.includes('ECDSA') || upper.includes('ED25519') || upper.includes('ED448');
  if (isEllipticCurve) return bits >= 256 ? 100 : 50;
  return bits >= 2048 ? 100 : bits >= 1024 ? 50 : 20;
}

export const KeyProtocolCard: React.FC<KeyProtocolCardProps> = ({
  className = '',
  cryptoPosture,
  checks,
  score,
  scanData,
  onModeChange
}) => {
  const [activeMode, setActiveMode] = useState<KeyMode>('adopt');

  const handleModeClick = (mode: KeyMode) => {
    setActiveMode(mode);
    if (onModeChange) onModeChange(mode);
  };

  const activeCryptoPosture = scanData?.crypto_posture ?? cryptoPosture ?? null;
  const activeChecks = scanData?.checks ?? checks ?? [];
  const activeScore = scanData?.security_score ?? scanData?.score ?? score ?? null;
  const primaryAudit = activeCryptoPosture?.protocols_audited?.[0] ?? null;
  const tlsHandshake = primaryAudit?.tls_handshake ?? null;
  const cipher = tlsHandshake?.cipher ?? null;
  const cert = tlsHandshake?.certificate ?? null;
  const rawTlsVersion = tlsHandshake?.negotiated_version || tlsHandshake?.tls_version || null;
  const tlsVersion = rawTlsVersion ? normalizeTlsVersion(rawTlsVersion) : null;
  const cipherSuite = tlsHandshake?.cipher_suite || cipher?.name || null;
  const forwardSecrecy = activeCryptoPosture ? activeCryptoPosture.forward_secrecy_supported : null;

  const mtaStsCheck = activeChecks.find((c) => c.name.toLowerCase().includes('mta-sts'));
  const mtaStsScore = statusToScore(mtaStsCheck?.status);
  const keyStrength = cert ? keyStrengthProgress(cert.public_key_algorithm, cert.key_size_bits) : null;
  const signatureAlgorithm = cert?.signature_algorithm || null;
  const issuer = cert?.issuer_cn || cert?.issuer_dn || null;
  const subject = cert?.subject_cn || cert?.subject_dn || null;

  const tlsRow: ProtocolRow = tlsVersion === 'TLS 1.3'
    ? { id: '1', name: 'TLS Protocol Enforcement', protocol: `${tlsVersion} (RFC 8446)`, metric: '100%', progress: 100, unknown: false }
    : tlsVersion === 'TLS 1.2'
      ? { id: '1', name: 'TLS Protocol Enforcement', protocol: `${tlsVersion} (RFC 5246 or earlier)`, metric: '60%', progress: 60, unknown: false }
      : tlsVersion
        ? { id: '1', name: 'TLS Protocol Enforcement', protocol: `${tlsVersion} (legacy)`, metric: 'LEGACY', progress: 25, unknown: false }
        : { id: '1', name: 'TLS Protocol Enforcement', protocol: 'No handshake telemetry reported', metric: 'N/A', progress: 0, unknown: true };

  const rows: Record<KeyMode, ProtocolRow[]> = {
    adopt: [
      tlsRow,
      {
        id: '2',
        name: 'Perfect Forward Secrecy',
        protocol: cipher?.key_exchange
          ? cipher.key_exchange
          : forwardSecrecy === true
            ? 'Forward secrecy reported by posture data'
            : forwardSecrecy === false
              ? 'Posture data reports no forward secrecy'
              : 'No key exchange data reported',
        metric: forwardSecrecy === true ? '100%' : forwardSecrecy === false ? '0%' : 'N/A',
        progress: forwardSecrecy === true ? 100 : forwardSecrecy === false ? 0 : 0,
        unknown: forwardSecrecy === null
      },
      {
        id: '3',
        name: 'Cryptographic Cipher',
        protocol: cipherSuite
          ? `${cipherSuite.slice(0, 24)}${cipherSuite.length > 24 ? '...' : ''}`
          : 'No cipher reported',
        metric: cipher ? (cipher.is_weak ? 'WEAK' : 'SECURE') : 'N/A',
        progress: cipher ? (cipher.is_weak ? 25 : 100) : 0,
        unknown: !cipher
      },
      {
        id: '4',
        name: 'MTA-STS Downgrade Prevention',
        protocol: mtaStsCheck
          ? mtaStsCheck.status === 'pass'
            ? 'Strict Transport Security Active'
            : mtaStsCheck.status === 'warn'
              ? 'Policy present but not enforcing'
              : mtaStsCheck.status === 'fail'
                ? 'No MTA-STS Policy Detected'
                : 'Check reported without status'
          : 'MTA-STS check not reported',
        metric: mtaStsScore === null ? 'N/A' : `${mtaStsScore}%`,
        progress: mtaStsScore ?? 0,
        unknown: mtaStsScore === null
      }
    ],
    encrypt: [
      {
        id: '1',
        name: 'Symmetric Cipher Pipeline',
        protocol: cipherSuite || 'No cipher reported',
        metric: cipher?.bits != null ? `${cipher.bits} BITS` : 'N/A',
        progress: cipher?.bits != null ? (cipher.bits >= 256 ? 100 : cipher.bits >= 128 ? 75 : 40) : 0,
        unknown: cipher?.bits == null
      },
      {
        id: '2',
        name: 'Key Exchange Mechanism',
        protocol: cipher?.key_exchange || 'No key exchange data reported',
        metric: forwardSecrecy === true ? 'PFS OK' : forwardSecrecy === false ? 'STATIC' : 'N/A',
        progress: forwardSecrecy === true ? 100 : forwardSecrecy === false ? 15 : 0,
        unknown: forwardSecrecy === null
      },
      {
        id: '3',
        name: 'Certificate Signature Algorithm',
        protocol: signatureAlgorithm || 'No certificate signature reported',
        metric: signatureAlgorithm
          ? signatureAlgorithm.toLowerCase().includes('sha1')
            ? 'DEPRECATED'
            : 'FIPS OK'
          : 'N/A',
        progress: signatureAlgorithm ? (signatureAlgorithm.toLowerCase().includes('sha1') ? 20 : 100) : 0,
        unknown: !signatureAlgorithm
      },
      {
        id: '4',
        name: 'Public Key Exponent & Curve',
        protocol: cert
          ? `${cert.public_key_algorithm || 'Algorithm not reported'}${cert.key_size_bits != null ? ` (${cert.key_size_bits} bits)` : ''}`
          : 'No certificate key data reported',
        metric: keyStrength === null ? 'N/A' : `${keyStrength}%`,
        progress: keyStrength ?? 0,
        unknown: keyStrength === null
      }
    ],
    decrypt: [
      {
        id: '1',
        name: 'X.509 Chain Trust Validator',
        protocol: cert
          ? cert.chain_valid === true
            ? 'Trusted System Root CA'
            : cert.chain_valid === false
              ? 'Untrusted / Incomplete Chain'
              : 'Chain validation not reported'
          : 'No certificate data reported',
        metric: cert ? (cert.chain_valid === true ? 'TRUSTED' : cert.chain_valid === false ? 'UNTRUSTED' : 'N/A') : 'N/A',
        progress: cert ? (cert.chain_valid === true ? 100 : cert.chain_valid === false ? 10 : 0) : 0,
        unknown: !cert || cert.chain_valid == null
      },
      {
        id: '2',
        name: 'Certificate Issuer CN',
        protocol: issuer || 'Issuer not reported',
        metric: issuer ? 'REPORTED' : 'N/A',
        progress: issuer ? 100 : 0,
        unknown: !issuer
      },
      {
        id: '3',
        name: 'Subject CN Matching',
        protocol: subject || 'Subject not reported',
        metric: cert ? (cert.matches_domain === true ? 'MATCH' : cert.matches_domain === false ? 'MISMATCH' : 'N/A') : 'N/A',
        progress: cert ? (cert.matches_domain === true ? 100 : cert.matches_domain === false ? 30 : 0) : 0,
        unknown: !cert || cert.matches_domain == null
      },
      {
        id: '4',
        name: 'Certificate Expiry Lifetime',
        protocol: cert
          ? cert.is_expired
            ? `Expired ${Math.abs(cert.days_until_expiry)} days ago`
            : Number.isFinite(cert.days_until_expiry)
              ? `${cert.days_until_expiry} days remaining`
              : 'Expiry not reported'
          : 'No certificate data reported',
        metric: cert ? (cert.is_expired ? 'EXPIRED' : Number.isFinite(cert.days_until_expiry) ? `${cert.days_until_expiry}d` : 'N/A') : 'N/A',
        progress: cert && !cert.is_expired && Number.isFinite(cert.days_until_expiry)
          ? Math.min(100, Math.max(10, (cert.days_until_expiry / 365) * 100))
          : 0,
        unknown: !cert || !Number.isFinite(cert.days_until_expiry)
      }
    ]
  };

  const currentRows = rows[activeMode];

  return (
    <div className={`${className} bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-md p-5 hover:border-cyan-500/50 transition-colors flex flex-col justify-between`}>
      {/* Top Bar: Mode Switcher */}
      <div className="flex items-center justify-between gap-2 mb-4">
        <span className="text-[11px] font-semibold tracking-widest text-slate-600 dark:text-slate-400 uppercase">
          Key Protocol Monitor
        </span>

        {/* 3 Pill buttons: Adopt All, Encrypt, Decrypt */}
        <div className="flex items-center p-0.5 rounded bg-slate-100 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 text-xs font-mono">
          {(['adopt', 'encrypt', 'decrypt'] as KeyMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => handleModeClick(mode)}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors tracking-wide uppercase ${
                activeMode === mode
                  ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 border border-transparent'
              }`}
            >
              {mode === 'adopt' ? 'Adopt All' : mode}
            </button>
          ))}
        </div>
      </div>

      {/* Hairline Divided Table */}
      <div className="divide-y divide-slate-200 dark:divide-slate-800 font-mono text-[11px] py-1">
        {currentRows.map((row) => {
          const barColor = row.unknown
            ? '#94a3b8'
            : row.progress >= 80
              ? '#00f0ff'
              : row.progress >= 60
                ? '#10b981'
                : row.progress >= 30
                  ? '#f59e0b'
                  : '#ef4444';
          return (
            <div
              key={row.id}
              className="py-2.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/40 px-1.5 rounded transition-colors"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ backgroundColor: barColor }}
                  ></span>
                  <span className="font-semibold text-slate-800 dark:text-slate-100 truncate text-[12px] font-sans">
                    {row.name}
                  </span>
                </div>
                <span className="text-[10px] text-cyan-700 dark:text-cyan-400/90 truncate block pl-3.5 tracking-wider">
                  {row.protocol}
                </span>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <div className="w-16 sm:w-20 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${row.unknown ? 0 : row.progress}%`,
                      background: barColor
                    }}
                  />
                </div>
                <span
                  className={`text-[11px] font-semibold w-16 text-right tracking-wider ${
                    row.unknown ? 'text-slate-400 dark:text-slate-500' : row.progress >= 80 ? 'text-cyan-700 dark:text-cyan-400/90' : row.progress >= 30 ? 'text-amber-600 dark:text-amber-400' : 'text-rose-600 dark:text-rose-400'
                  }`}
                >
                  {row.metric}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800 text-[10px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-between">
        <span className="tracking-wider uppercase">Cipher Sync: {cipherSuite ? cipherSuite.slice(0, 22) : 'Awaiting scan'}</span>
        <span className="text-emerald-700 dark:text-emerald-400 font-semibold tracking-widest uppercase">
          {activeScore !== null && activeScore !== undefined ? `Score: ${activeScore}/100` : 'No Score Reported'}
        </span>
      </div>
    </div>
  );
};
