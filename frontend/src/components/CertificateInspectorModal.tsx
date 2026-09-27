import React from 'react';
import {
  X,
  FileCheck,
  ExternalLink,
  Copy,
  Check,
  Calendar
} from 'lucide-react';
import { ScanResponse } from '../types';

interface CertificateInspectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  domain: string;
  scanData?: ScanResponse | null;
}

export const CertificateInspectorModal: React.FC<CertificateInspectorModalProps> = ({
  isOpen,
  onClose,
  domain,
  scanData
}) => {
  const [copiedFingerprint, setCopiedFingerprint] = React.useState(false);

  if (!isOpen) return null;

  // Certificate telemetry straight from the scan response. No fallback identity
  // is invented when the backend did not return a certificate.
  const realCert = scanData?.crypto_posture?.protocols_audited?.[0]?.tls_handshake?.certificate ?? null;
  const pqcEvaluated = scanData?.crypto_posture?.pqc_indicators_evaluated;

  const daysRemaining = realCert && Number.isFinite(realCert.days_until_expiry) ? realCert.days_until_expiry : null;
  const certData = realCert
    ? {
        subjectCn: realCert.subject_cn || realCert.subject_dn || 'Not reported',
        subjectDn: realCert.subject_dn || 'Not reported',
        issuerCn: realCert.issuer_cn || realCert.issuer_dn || 'Not reported',
        issuerDn: realCert.issuer_dn || 'Not reported',
        serialNumber: realCert.serial_number || 'Not reported',
        validFrom: realCert.valid_from || 'Not reported',
        validTo: realCert.valid_to || 'Not reported',
        daysRemaining,
        isExpired: realCert.is_expired,
        algorithm: realCert.public_key_algorithm
          ? `${realCert.public_key_algorithm}${realCert.key_size_bits ? ` (${realCert.key_size_bits}-bit)` : ''}`
          : 'Not reported',
        signatureAlgorithm: realCert.signature_algorithm || 'Not reported',
        fingerprintSha256: realCert.sha256_fingerprint || null,
        sans: realCert.san_list ?? [],
        pqcCompatibility: pqcEvaluated === true ? 'Evaluated by backend scan' : pqcEvaluated === false ? 'Not evaluated' : 'Not reported'
      }
    : null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFingerprint(true);
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  const panel = 'rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50';
  const label = 'text-[10px] uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400 font-bold block';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm animate-fade-in font-sans"
      role="dialog"
      aria-modal="true"
      aria-label="X.509 certificate chain audit"
    >
      <div className="relative w-full max-w-3xl rounded-lg bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 flex flex-col max-h-[90vh] overflow-hidden text-slate-900 dark:text-slate-100">
        
        {/* Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-300">
              <FileCheck size={16} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-slate-900 dark:text-white tracking-tight">
                  X.509 Certificate Chain Audit
                </span>
                {realCert?.chain_valid === true ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 font-medium">
                    CHAIN VALIDATED (ROOT TRUSTED)
                  </span>
                ) : realCert?.chain_valid === false ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 font-medium" title={realCert.chain_error || 'Untrusted chain'}>
                    CHAIN UNTRUSTED
                  </span>
                ) : realCert ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 font-medium">
                    CHAIN STATUS NOT REPORTED
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-500/10 text-slate-500 dark:text-slate-300 border border-slate-500/30 font-medium">
                    NO CERTIFICATE DATA
                  </span>
                )}
              </div>
              <span className="text-xs font-mono tracking-tight text-slate-600 dark:text-slate-400">
                Target: {domain}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Direct launch button: Inspect via Microservice (Port 8007) */}
            <button
              type="button"
              onClick={() => window.open('http://localhost:8007', '_blank')}
              className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono text-blue-700 dark:text-blue-400 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 transition-colors"
              title="Launch standalone microservice inspector on Port 8007"
            >
              <ExternalLink size={12} />
              <span>Inspect via Microservice (Port 8007)</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 overflow-y-auto custom-scrollbar font-mono text-xs text-slate-700 dark:text-slate-200">
          
          {realCert?.chain_valid === false && (
            <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 flex items-start gap-2.5">
              <span className="font-bold text-rose-600 dark:text-rose-400 shrink-0">CHAIN ERROR:</span>
              <span className="font-sans text-xs">{realCert.chain_error || 'Certificate chain failed validation to a trusted public root CA.'}</span>
            </div>
          )}

          {!certData ? (
            <div className="p-8 rounded bg-slate-50 dark:bg-slate-800/40 border border-dashed border-slate-300 dark:border-slate-700 text-center space-y-2">
              <div className="text-sm font-semibold text-slate-800 dark:text-slate-200 font-sans">Certificate Data Unavailable</div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans max-w-md mx-auto leading-relaxed">
                The latest scan of {domain} did not return X.509 certificate telemetry. No fallback certificate
                identity, serial, validity window, or fingerprint is displayed because fabricated values would
                misrepresent the audit.
              </p>
              <p className="text-[10px] text-slate-500 dark:text-slate-500 font-mono tracking-tight pt-1">
                Run a scan against a domain with an auditable MX/STARTTLS endpoint to populate this view.
              </p>
            </div>
          ) : (
            <>
              {/* Certificate Subject & Issuer Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className={`p-3.5 space-y-1.5 ${panel}`}>
                  <span className={label}>Subject Common Name (CN)</span>
                  <div className="text-xs font-bold text-slate-900 dark:text-white break-all">{certData.subjectCn}</div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-sans">{certData.subjectDn}</p>
                </div>

                <div className={`p-3.5 space-y-1.5 ${panel}`}>
                  <span className={label}>Certificate Authority (Issuer)</span>
                  <div className="text-xs font-bold text-blue-700 dark:text-blue-400 break-all">{certData.issuerCn}</div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-sans">{certData.issuerDn}</p>
                </div>
              </div>

              {/* Cryptographic Key Parameters */}
              <div className={`p-3.5 space-y-2.5 ${panel}`}>
                <span className="text-[10px] uppercase tracking-wider text-slate-600 dark:text-slate-300 font-bold block">
                  Cryptographic Key Parameters &amp; Fingerprint
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">Public Key Algorithm</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{certData.algorithm}</span>
                  </div>
                  <div>
                    <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">Signature Algorithm</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{certData.signatureAlgorithm}</span>
                  </div>
                  <div>
                    <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">PQC Compatibility</span>
                    <span className={`font-semibold ${certData.pqcCompatibility === 'Evaluated by backend scan' ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'}`}>
                      {certData.pqcCompatibility}
                    </span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-200 dark:border-slate-700">
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="text-slate-500 dark:text-slate-400">SHA-256 Fingerprint:</span>
                    {certData.fingerprintSha256 && (
                      <button
                        type="button"
                        onClick={() => handleCopy(certData.fingerprintSha256 as string)}
                        className="flex items-center gap-1 text-blue-700 dark:text-blue-400 hover:text-blue-600 dark:hover:text-blue-300"
                      >
                        {copiedFingerprint ? <Check size={12} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={12} />}
                        <span>{copiedFingerprint ? 'Copied' : 'Copy Hash'}</span>
                      </button>
                    )}
                  </div>
                  <div className="p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-300 break-all select-all font-mono">
                    {certData.fingerprintSha256 ?? 'Fingerprint not reported in scan response'}
                  </div>
                </div>
              </div>

              {/* Serial & Validity Period */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className={`p-3 min-w-0 ${panel}`}>
                  <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">Serial Number</span>
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 break-all">{certData.serialNumber}</span>
                </div>

                <div className={`p-3 min-w-0 ${panel}`}>
                  <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">Validity Period</span>
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 break-all">
                    {certData.validFrom} → {certData.validTo}
                  </span>
                </div>

                <div className={`p-3 flex items-center justify-between min-w-0 ${panel}`}>
                  <div className="min-w-0">
                    <span className="text-[10px] font-medium text-slate-600 dark:text-slate-400 block">Validity Remaining</span>
                    <span className={`text-xs font-semibold ${certData.isExpired ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-700 dark:text-emerald-400'}`}>
                      {certData.daysRemaining === null
                        ? 'Expiry not reported'
                        : certData.isExpired
                          ? `${Math.abs(certData.daysRemaining)} days past expiry`
                          : `${certData.daysRemaining} days remaining`}
                    </span>
                  </div>
                  <Calendar size={16} className="text-slate-500 dark:text-slate-400 shrink-0" />
                </div>
              </div>

              {/* Subject Alternative Names (SANs) */}
              <div className={`p-3.5 space-y-1.5 ${panel}`}>
                <span className={label}>Subject Alternative Names (SANs)</span>
                {certData.sans.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {certData.sans.map((san: string) => (
                      <span
                        key={san}
                        className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 text-xs"
                      >
                        {san}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">No SANs reported in scan response.</span>
                )}
              </div>
            </>
          )}

        </div>

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/70 flex items-center justify-between">
          <button
            type="button"
            onClick={() => window.open('http://localhost:8007', '_blank')}
            className="sm:hidden text-xs text-blue-700 dark:text-blue-400 flex items-center gap-1"
          >
            <ExternalLink size={12} />
            <span>Port 8007 Microservice</span>
          </button>
          <div className="hidden sm:block text-[11px] font-mono text-slate-500">
            {realCert
              ? `X.509 TELEMETRY // ${scanData?.scanned_at ? new Date(scanData.scanned_at).toUTCString() : 'TIMESTAMP NOT REPORTED'}`
              : 'NO CERTIFICATE TELEMETRY RECEIVED'}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-white text-xs font-semibold transition-colors border border-slate-200 dark:border-slate-700"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
