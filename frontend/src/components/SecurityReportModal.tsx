import React from 'react';
import {
  X,
  Download,
  FileJson,
  Printer,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Sparkles
} from 'lucide-react';
import { Logo } from './Logo';
import { CheckStatus, ScanResponse } from '../types';

interface SecurityReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  domain: string;
  score?: number | null;
  scanData?: ScanResponse | null;
  onExportJson?: () => void;
  onExportPdf?: () => void;
  onExportHtml?: () => void;
}

interface ReportItem {
  key: string;
  title: string;
  detail: string;
  status: CheckStatus;
}

const STATUS_BADGE: Record<CheckStatus, string> = {
  pass: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  warn: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  fail: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
  unknown: 'bg-slate-500/10 border-slate-500/30 text-slate-300'
};

export const SecurityReportModal: React.FC<SecurityReportModalProps> = ({
  isOpen,
  onClose,
  domain,
  score = null,
  scanData = null,
  onExportJson,
  onExportPdf,
  onExportHtml
}) => {
  if (!isOpen) return null;

  const hasScore = typeof score === 'number' && Number.isFinite(score);

  // Checklist is built from the checks the backend actually ran.
  const checkItems: ReportItem[] = (scanData?.checks ?? []).map((check) => ({
    key: check.name,
    title: check.name,
    detail:
      typeof check.details?.message === 'string' && check.details.message
        ? check.details.message
        : check.recommendation || `Status: ${check.status.toUpperCase()}`,
    status: check.status
  }));

  // Derived posture rows only assert what crypto_posture reports.
  const postureItems: ReportItem[] = [];
  const posture = scanData?.crypto_posture;
  if (posture) {
    const tlsStatus: CheckStatus =
      posture.protocols_audited.length === 0
        ? 'unknown'
        : posture.deprecated_tls_found || posture.weak_ciphers_found
          ? 'fail'
          : 'pass';
    postureItems.push({
      key: 'tls-posture',
      title: 'TLS / Cipher Posture',
      detail:
        posture.protocols_audited.length === 0
          ? 'No protocol endpoints were audited in this scan.'
          : `${posture.protocols_audited.length} endpoint(s) audited · forward secrecy ${
              posture.forward_secrecy_supported ? 'supported' : 'not supported'
            }${posture.deprecated_tls_found ? ' · deprecated TLS found' : ''}${
              posture.weak_ciphers_found ? ' · weak ciphers found' : ''
            }`,
      status: tlsStatus
    });
    postureItems.push({
      key: 'pqc-readiness',
      title: 'Post-Quantum Readiness (FIPS 203)',
      detail: posture.pqc_indicators_evaluated
        ? 'PQC indicators were evaluated by the backend scan.'
        : 'PQC indicators were not evaluated — readiness is not claimed.',
      status: posture.pqc_indicators_evaluated ? 'pass' : 'unknown'
    });
  }

  const reportItems = [...checkItems, ...postureItems];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-3xl rounded-md bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 flex flex-col max-h-[90vh] overflow-hidden text-slate-900 dark:text-slate-100">
        
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/80 dark:bg-slate-950/70">
          <div className="flex items-center gap-3">
            <Logo size={26} />
            <div className="border-l border-slate-300 dark:border-slate-700 pl-3">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400 font-bold block">
                Official Security Dossier
              </span>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white tracking-tight">
                Cryptographic Posture &amp; Threat Audit
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => window.print()}
              className="p-1.5 rounded text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              title="Print Dossier"
            >
              <Printer size={15} />
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

        {/* Modal Scrollable Content */}
        <div className="p-6 space-y-5 overflow-y-auto custom-scrollbar text-slate-700 dark:text-slate-200">
          {/* Executive Overview Banner */}
          <div className="p-4 rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono font-bold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">Target Domain</span>
              <div className="text-xl font-bold font-mono text-slate-900 dark:text-white">{domain}</div>
              <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 block font-mono tracking-tight">
                Audit Timestamp: {scanData?.scanned_at ? new Date(scanData.scanned_at).toUTCString() : 'No scan timestamp reported'}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div className="text-right">
                <span className="text-[10px] font-mono font-bold tracking-[0.2em] text-slate-500 dark:text-slate-400 block uppercase">Posture Grade</span>
                <span className={`text-xs font-bold font-mono ${
                  !hasScore ? 'text-slate-500 dark:text-slate-400' : score >= 80 ? 'text-emerald-500 dark:text-emerald-400' : score >= 60 ? 'text-amber-500 dark:text-amber-400' : 'text-rose-500 dark:text-rose-400'
                }`}>
                  {!hasScore ? 'UNGRADED' : score >= 80 ? 'SOC GRADE A' : score >= 60 ? 'SOC GRADE B' : 'CRITICAL'}
                </span>
              </div>
              <div className="w-14 h-14 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 flex items-center justify-center">
                <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">
                  {hasScore ? score : '—'}
                </span>
              </div>
            </div>
          </div>

          {/* Key Findings Matrix */}
          <div>
            <h3 className="uppercase tracking-[0.2em] text-[10px] sm:text-[11px] font-bold text-slate-500 dark:text-slate-400 mb-2.5">
              Protocol Compliance Checklist
            </h3>
            {reportItems.length === 0 ? (
              <div className="p-5 rounded-md bg-slate-50 dark:bg-slate-800/40 border border-dashed border-slate-300 dark:border-slate-700 text-center">
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-200">No audit checks available</div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 font-sans">
                  Run a scan to populate this checklist with the checks the backend actually executed.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 font-mono text-xs">
                {reportItems.map((item) => (
                  <div
                    key={item.key}
                    className="p-3 rounded-md bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/80 flex items-start gap-2.5"
                  >
                    {item.status === 'pass' ? (
                      <CheckCircle2 size={15} className="text-emerald-500 dark:text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle
                        size={15}
                        className={`shrink-0 mt-0.5 ${
                          item.status === 'warn'
                            ? 'text-amber-500 dark:text-amber-400'
                            : item.status === 'fail'
                              ? 'text-rose-500 dark:text-rose-400'
                              : 'text-slate-500 dark:text-slate-400'
                        }`}
                      />
                    )}
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100 truncate">{item.title}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${STATUS_BADGE[item.status]}`}>
                          {item.status.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 font-sans mt-0.5 leading-snug">
                        {item.detail}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* AI Remediation Guidance */}
          <div className="p-4 rounded-md bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/40 text-xs">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-300 font-bold mb-1">
              <Sparkles size={14} />
              <span>AI Remediation Synthesis</span>
            </div>
            {scanData ? (
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans text-xs">
                Cryptographic posture is evaluated against NIST SP 800-52r2 standards. To safeguard mail traffic against Store-Now-Decrypt-Later (SNDL) attacks, deploy post-quantum hybrid key encapsulation (ML-KEM-768) on inbound and outbound gateways.
              </p>
            ) : (
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans text-xs">
                No scan response is loaded. Remediation synthesis and compliance mapping require a completed audit.
              </p>
            )}
          </div>
        </div>

        {/* Modal Actions Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/70 flex flex-wrap items-center justify-between gap-3">
          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-500 flex items-center gap-1.5">
            <Lock size={11} />
            <span>CONFIDENTIAL // FOR INSTITUTIONAL USE ONLY</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors"
            >
              <FileJson size={13} />
              <span>JSON</span>
            </button>
            <button
              type="button"
              onClick={onExportHtml}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-cyan-600 dark:text-cyan-300 text-xs font-semibold border border-cyan-300/50 dark:border-cyan-500/40 hover:border-cyan-400 transition-colors"
            >
              <Download size={13} />
              <span>HTML Dossier</span>
            </button>
            <button
              type="button"
              onClick={onExportPdf}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors"
            >
              <Download size={13} />
              <span>Download PDF</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
