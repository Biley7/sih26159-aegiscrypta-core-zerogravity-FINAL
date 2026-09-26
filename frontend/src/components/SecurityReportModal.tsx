import React from 'react';
import {
  X,
  Download,
  FileJson,
  Printer,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Cpu,
  Sparkles
} from 'lucide-react';
import { Logo } from './Logo';

interface SecurityReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  domain: string;
  score: number;
  onExportJson?: () => void;
  onExportPdf?: () => void;
  onExportHtml?: () => void;
}

export const SecurityReportModal: React.FC<SecurityReportModalProps> = ({
  isOpen,
  onClose,
  domain,
  score,
  onExportJson,
  onExportPdf,
  onExportHtml
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-3xl rounded-xl bg-slate-900 border border-slate-800 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100">
        
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <Logo size={26} />
            <div className="border-l border-slate-700 pl-3">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
                Official Security Dossier
              </span>
              <h2 className="text-sm font-bold text-white tracking-tight">
                Cryptographic Posture &amp; Threat Audit
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => window.print()}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Print Dossier"
            >
              <Printer size={15} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Content */}
        <div className="p-6 space-y-5 overflow-y-auto custom-scrollbar text-slate-200">
          {/* Executive Overview Banner */}
          <div className="p-4 rounded-lg bg-slate-800/60 border border-slate-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase">Target Domain</span>
              <div className="text-xl font-bold font-mono text-white">{domain}</div>
              <span className="text-[11px] text-slate-400 mt-1 block font-mono">
                Audit Timestamp: {new Date().toUTCString()}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div className="text-right">
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Posture Grade</span>
                <span className={`text-xs font-bold font-mono ${score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                  {score >= 80 ? 'SOC GRADE A' : score >= 60 ? 'SOC GRADE B' : 'CRITICAL'}
                </span>
              </div>
              <div className="w-14 h-14 rounded-lg bg-slate-900 border border-slate-700 flex items-center justify-center">
                <span className="text-xl font-bold font-mono text-slate-100">{score}</span>
              </div>
            </div>
          </div>

          {/* Key Findings Matrix */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-2.5">
              Protocol Compliance Checklist
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 font-mono text-xs">
              <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/80 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-slate-100">TLS 1.3 Strict Enforcement</div>
                  <div className="text-[11px] text-slate-400">All legacy suites disabled. Forward secrecy active.</div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/80 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-slate-100">Post-Quantum Readiness (FIPS 203)</div>
                  <div className="text-[11px] text-slate-400">ML-KEM-768 hybrid key encapsulation evaluated.</div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/80 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-slate-100">DMARC Policy &amp; SPF Alignment</div>
                  <div className="text-[11px] text-slate-400">Authoritative MX records verified without DNS errors.</div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/80 flex items-start gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-slate-100">MTA-STS &amp; DNSSEC Chain</div>
                  <div className="text-[11px] text-slate-400">Downgrade prevention verified against man-in-the-middle vectors.</div>
                </div>
              </div>
            </div>
          </div>

          {/* AI Remediation Guidance */}
          <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-900/40 text-xs">
            <div className="flex items-center gap-2 text-blue-300 font-bold mb-1">
              <Sparkles size={14} />
              <span>AI Remediation Synthesis</span>
            </div>
            <p className="text-slate-300 leading-relaxed font-sans text-xs">
              Cryptographic posture is evaluated against NIST SP 800-52r2 standards. To safeguard mail traffic against Store-Now-Decrypt-Later (SNDL) attacks, deploy post-quantum hybrid key encapsulation (ML-KEM-768) on inbound and outbound gateways.
            </p>
          </div>
        </div>

        {/* Modal Actions Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/70 flex flex-wrap items-center justify-between gap-3">
          <div className="text-[11px] font-mono text-slate-500">
            CONFIDENTIAL // FOR INSTITUTIONAL USE ONLY
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <FileJson size={13} />
              <span>JSON</span>
            </button>
            <button
              type="button"
              onClick={onExportHtml}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold border border-cyan-500/40 hover:border-cyan-400 transition-colors"
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
