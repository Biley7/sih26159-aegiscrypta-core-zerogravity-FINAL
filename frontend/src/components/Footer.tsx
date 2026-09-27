import React, { useState } from 'react';
import {
  ShieldCheck,
  ExternalLink,
  Code,
  FileCheck,
  X,
  Lock,
  Cpu,
  Download,
  Activity
} from 'lucide-react';

interface FooterProps {
  onExportJson?: () => void;
  apiBaseUrl?: string;
}

type ModalType = 'nist' | 'mta-sts' | 'tls-rpt' | 'pqc' | null;

export const Footer: React.FC<FooterProps> = ({ onExportJson, apiBaseUrl = 'http://localhost:8000' }) => {
  const docsUrl = `${apiBaseUrl.replace(/\/$/, '')}/docs`;
  const [activeModal, setActiveModal] = useState<ModalType>(null);

  const handleExportClick = () => {
    if (onExportJson) {
      onExportJson();
    } else {
      const payload = {
        platform: 'AegisCrypta Forensics Platform',
        specification: 'NTRO Defense Mail Standards',
        timestamp: new Date().toISOString(),
        team: 'Team Zero Gravity',
        compliance: ['FIPS 203 (ML-KEM-768)', 'RFC 8461 (MTA-STS)', 'RFC 8460 (TLS-RPT)', 'NIST SP 800-52r2']
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegiscrypta-session-audit-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <>
      <footer className="enterprise-soc-footer border-t py-8 px-6 text-xs text-slate-600 dark:text-slate-400" aria-label="Institutional Defense Footer">
        <div className="footer-content-grid max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Column 1: Platform Identity & Institutional Standards */}
          <div className="flex flex-col justify-between space-y-3">
            <div>
              <div className="footer-brand-title flex items-center gap-2 font-bold text-slate-800 dark:text-slate-100 text-sm">
                <ShieldCheck size={16} className="text-soc-secure shrink-0" />
                <span className="font-mono tracking-wider">AEGISCRYPTA FORENSICS ENGINE</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 text-xs mt-1.5 leading-relaxed">
                Architected to National Technical Research Organisation (NTRO) Standards for Defense &amp; Critical Infrastructure Email Security.
              </p>
            </div>
            <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40">
              <span className="font-mono text-xs font-bold text-emerald-700 dark:text-emerald-400 block">
                SIH2026159
              </span>
              <p className="text-[11px] text-slate-500 leading-tight mt-0.5">
                AI-Assisted Cryptographic Posture Assessment for Critical Mail Infrastructure.
              </p>
            </div>
          </div>

          {/* Column 2: Interactive Compliance Matrix */}
          <div>
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider block mb-2.5 text-slate-500">
              Institutional Compliance References
            </span>
            <ul className="space-y-1.5 font-mono text-xs">
              <li>
                <button
                  type="button"
                  onClick={() => setActiveModal('nist')}
                  className="footer-interactive-link flex items-center gap-2 w-full p-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer text-left"
                >
                  <FileCheck size={13} className="text-soc-secure shrink-0" />
                  <span>NIST SP 800-52r2 Guidelines</span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => setActiveModal('mta-sts')}
                  className="footer-interactive-link flex items-center gap-2 w-full p-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer text-left"
                >
                  <Lock size={13} className="text-soc-secure shrink-0" />
                  <span>RFC 8461 (MTA-STS) Specification</span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => setActiveModal('tls-rpt')}
                  className="footer-interactive-link flex items-center gap-2 w-full p-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer text-left"
                >
                  <Activity size={13} className="text-soc-warning shrink-0" />
                  <span>RFC 8460 (TLS-RPT) Telemetry</span>
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => setActiveModal('pqc')}
                  className="footer-interactive-link flex items-center gap-2 w-full p-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer text-left"
                >
                  <Cpu size={13} className="text-soc-pqc shrink-0" />
                  <span>FIPS 203 ML-KEM-768 Matrix</span>
                </button>
              </li>
            </ul>
          </div>

          {/* Column 3: Engineering Team & Session Actions */}
          <div className="flex flex-col justify-between space-y-3">
            <div>
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider block mb-1 text-slate-500">
                Engineering &amp; Governance
              </span>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                Developed by <strong className="font-semibold text-slate-800 dark:text-slate-100">Team Zero Gravity</strong>
              </p>
              <p className="text-[11px] font-mono text-slate-500 mt-0.5">
                NTRO Architecture Standards • © 2026
              </p>
            </div>

            <div className="flex flex-col gap-1.5 font-mono text-xs">
              <a
                href={docsUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-center gap-2 px-3 py-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                title={`View OpenAPI / Swagger documentation at ${docsUrl}`}
              >
                <Code size={12} className="shrink-0" />
                <span>OpenAPI Interactive Docs</span>
                <ExternalLink size={10} className="opacity-60" />
              </a>

              <button
                type="button"
                onClick={handleExportClick}
                className="flex items-center justify-center gap-2 px-3 py-1.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                title="Export complete session forensic data in JSON format"
              >
                <Download size={12} className="text-soc-pqc shrink-0" />
                <span>Export Session Audit (JSON)</span>
              </button>
            </div>
          </div>
        </div>
      </footer>

      {/* Compliance / Specification Modals */}
      {activeModal && (
        <div className="compliance-modal-backdrop" onClick={() => setActiveModal(null)} role="presentation">
          <div
            className="compliance-modal-dialog"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800 p-4">
              <div className="flex items-center gap-2">
                {activeModal === 'nist' && <FileCheck size={16} className="text-soc-secure" />}
                {activeModal === 'mta-sts' && <Lock size={16} className="text-soc-secure" />}
                {activeModal === 'tls-rpt' && <Activity size={16} className="text-soc-warning" />}
                {activeModal === 'pqc' && <Cpu size={16} className="text-soc-pqc" />}
                <h3 className="font-bold text-sm text-slate-800 dark:text-slate-100">
                  {activeModal === 'nist' && 'NIST SP 800-52r2 Cryptographic Guidelines'}
                  {activeModal === 'mta-sts' && 'RFC 8461 (MTA-STS) Specification'}
                  {activeModal === 'tls-rpt' && 'RFC 8460 (TLS-RPT) Telemetry Framework'}
                  {activeModal === 'pqc' && 'FIPS 203 ML-KEM Post-Quantum Standard'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setActiveModal(null)}
                className="p-1 rounded text-slate-500 hover:text-slate-800 dark:hover:text-slate-100 transition-colors cursor-pointer"
                aria-label="Close modal"
              >
                <X size={15} />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-4 space-y-3 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              {activeModal === 'nist' && (
                <>
                  <p>
                    NIST Special Publication 800-52 Revision 2 establishes mandatory cryptographic baselines for TLS implementations in government and defense communications:
                  </p>
                  <div className="p-3 rounded border border-slate-200 dark:border-slate-800 font-mono space-y-1.5 bg-slate-50 dark:bg-slate-950">
                    <div className="text-emerald-700 dark:text-emerald-400 font-semibold">• Mandatory: TLS 1.3 (RFC 8446) / Conditional: TLS 1.2 (RFC 5246)</div>
                    <div className="text-rose-700 dark:text-rose-400">• Strict Ban: SSLv2, SSLv3, TLS 1.0, TLS 1.1</div>
                    <div>• Forward Secrecy: Mandatory ephemeral ECDHE or DHE key exchanges</div>
                    <div>• Prohibited: Static RSA key transport, 3DES, RC4, CBC-mode ciphers</div>
                  </div>
                </>
              )}

              {activeModal === 'mta-sts' && (
                <>
                  <p>
                    RFC 8461 (SMTP MTA Strict Transport Security) enables domains to declare their ability to receive encrypted mail and mandate certificate validation:
                  </p>
                  <div className="p-3 rounded border border-slate-200 dark:border-slate-800 font-mono space-y-1.5 bg-slate-50 dark:bg-slate-950">
                    <div>• DNS Record: Published at <code>_mta-sts.domain.com</code> (v=STSv1)</div>
                    <div>• HTTPS Policy: Hosted at <code>https://mta-sts.domain.com/.well-known/mta-sts.txt</code></div>
                    <div className="text-emerald-700 dark:text-emerald-400 font-semibold">• Enforcement Modes: 'enforce' (mandatory encryption), 'testing', 'none'</div>
                    <div>• Defense: Mitigates active Man-in-the-Middle (MitM) &amp; STRIPTLS attacks</div>
                  </div>
                </>
              )}

              {activeModal === 'tls-rpt' && (
                <>
                  <p>
                    RFC 8460 (SMTP TLS Reporting) establishes automated telemetry for tracking transport encryption failures:
                  </p>
                  <div className="p-3 rounded border border-slate-200 dark:border-slate-800 font-mono space-y-1.5 bg-slate-50 dark:bg-slate-950">
                    <div>• DNS Record: Published under <code>_smtp._tls.domain.com</code></div>
                    <div>• Reporting Syntax: <code>v=TLSRPTv1; rua=mailto:tls-reports@domain.com</code></div>
                    <div>• Telemetry: Discovers handshake failures, certificate expiry, and downgrade attacks</div>
                  </div>
                </>
              )}

              {activeModal === 'pqc' && (
                <>
                  <p>
                    NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768) provides quantum resistance against Cryptographically Relevant Quantum Computers (CRQCs):
                  </p>
                  <div className="p-3 rounded border border-slate-200 dark:border-slate-800 font-mono space-y-1.5 bg-slate-50 dark:bg-slate-950">
                    <div className="text-cyan-700 dark:text-cyan-400 font-semibold">• Primary Standard: ML-KEM-768 (Lattice Cryptography)</div>
                    <div>• Hybrid Architecture: Dual X25519 + ML-KEM-768 key encapsulation</div>
                    <div>• Defense: Thwarts adversary "Store Now, Decrypt Later" (SNDL) mass interception</div>
                  </div>
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex justify-end">
              <button
                type="button"
                onClick={() => setActiveModal(null)}
                className="px-3.5 py-1.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-100 text-xs font-semibold cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
