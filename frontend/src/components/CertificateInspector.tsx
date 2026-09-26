import React, { useState } from 'react';
import {
  Globe,
  Layers,
  Key,
  CheckCircle2,
  Clock,
  XCircle,
  AlertTriangle,
  Copy,
  Check
} from 'lucide-react';
import { CertificateInfo, ScanResponse } from '../types';

interface CertificateInspectorProps {
  data: ScanResponse;
}

export const CertificateInspector: React.FC<CertificateInspectorProps> = ({ data }) => {
  const [copiedSAN, setCopiedSAN] = useState(false);

  // Extract certificate from the first audited protocol with a cert
  const certificate: CertificateInfo | undefined = data.crypto_posture?.protocols_audited
    .map((p) => p.tls_handshake?.certificate)
    .find((c): c is CertificateInfo => !!c);

  if (!certificate) {
    return (
      <section className="technical-section cert-section">
        <div className="section-header">
          <h3 className="section-title">X.509 Certificate Chain & Cryptographic Trust</h3>
        </div>
        <div className="no-certificate text-center font-mono text-xs text-text-muted">
          No active X.509 certificate extracted from current mail exchange endpoints.
        </div>
      </section>
    );
  }

  const daysLeft = certificate.days_until_expiry;
  const isExpired = certificate.is_expired || daysLeft <= 0;
  const isExpiringSoon = !isExpired && daysLeft <= 60;

  const copySANs = async () => {
    if (certificate.san_list.length) {
      await navigator.clipboard.writeText(certificate.san_list.join(', '));
      setCopiedSAN(true);
      setTimeout(() => setCopiedSAN(false), 2000);
    }
  };

  return (
    <section className="technical-section cert-section" aria-label="X.509 Certificate Chain Inspection">
      <div className="section-header">
        <div>
          <h3 className="section-title">X.509 Certificate Chain & Cryptographic Trust</h3>
          <p className="section-description">
            Digital identity verification, Certificate Authority (CA) root trust, and cryptographic key parameters.
          </p>
        </div>

        {/* Expiration Badge */}
        <div>
          {isExpired ? (
            <span className="cert-status-badge expired font-mono text-xs">
              EXPIRED ({Math.abs(daysLeft)}d ago)
            </span>
          ) : isExpiringSoon ? (
            <span className="cert-status-badge expiring font-mono text-xs">
              EXPIRES SOON ({daysLeft}d left)
            </span>
          ) : (
            <span className="cert-status-badge valid font-mono text-xs">
              VALID ({daysLeft}d left)
            </span>
          )}
        </div>
      </div>

      <div className="cert-table-container">
        <table className="cert-table">
          <tbody>
            {/* Subject Identity */}
            <tr>
              <td className="cert-label">Subject CN</td>
              <td className="cert-value font-mono text-text-primary font-semibold">
                {certificate.subject_cn || 'None'}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Subject DN</td>
              <td className="cert-value font-mono text-text-secondary truncate" title={certificate.subject_dn}>
                {certificate.subject_dn}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Serial Number</td>
              <td className="cert-value font-mono text-text-muted">
                {certificate.serial_number}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Domain Match</td>
              <td className={`cert-value font-mono font-semibold ${certificate.matches_domain !== false ? 'text-soc-secure' : 'text-soc-critical'}`}>
                {certificate.matches_domain !== false ? 'Verified' : 'Mismatch'}
              </td>
            </tr>

            {/* Issuer & Validity */}
            <tr>
              <td className="cert-label">Issuer CA</td>
              <td className="cert-value font-mono text-text-primary font-semibold">
                {certificate.issuer_cn || certificate.issuer_dn}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Trust Class</td>
              <td className={`cert-value font-mono font-semibold ${certificate.is_self_signed ? 'text-soc-critical' : 'text-soc-secure'}`}>
                {certificate.is_self_signed ? 'Self-Signed' : 'Public Root CA'}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Valid From</td>
              <td className="cert-value font-mono text-text-secondary">
                {certificate.valid_from}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Valid To</td>
              <td className="cert-value font-mono text-text-secondary">
                {certificate.valid_to}
              </td>
            </tr>

            {/* Cryptographic Key */}
            <tr>
              <td className="cert-label">Public Key Algorithm</td>
              <td className="cert-value font-mono text-soc-secure">
                {certificate.public_key_algorithm}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Key Size / Curve</td>
              <td className="cert-value font-mono text-text-primary font-semibold">
                {certificate.key_size_bits ? `${certificate.key_size_bits} bits` : 'Standard Curve'}
              </td>
            </tr>
            <tr>
              <td className="cert-label">Signature Digest</td>
              <td className="cert-value font-mono text-text-secondary">
                {certificate.signature_algorithm}
              </td>
            </tr>
            <tr>
              <td className="cert-label">NIST SP 800-57</td>
              <td className="cert-value font-mono text-soc-secure font-semibold">
                {certificate.key_size_bits && certificate.key_size_bits < 2048 ? 'Deficient' : 'Compliant'}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* SAN Extensions */}
      <div className="san-section">
        <div className="san-header">
          <h4 className="san-title">Subject Alternative Names ({certificate.san_list.length})</h4>
          <button
            onClick={copySANs}
            className="san-copy-btn font-mono text-xs"
            title="Copy all SAN hostnames"
          >
            {copiedSAN ? 'Copied' : 'Copy All'}
          </button>
        </div>
        <div className="san-list">
          {certificate.san_list.map((san) => (
            <span key={san} className="san-item font-mono text-xs">
              {san}
            </span>
          ))}
        </div>
      </div>

      {/* Warnings */}
      {certificate.warnings && certificate.warnings.length > 0 && (
        <div className="cert-warnings">
          <div className="warning-header">
            <AlertTriangle size={12} className="text-soc-warning" />
            <span className="warning-title font-mono text-soc-warning text-xs">Certificate Warnings</span>
          </div>
          <ul className="warning-list text-text-secondary text-xs">
            {certificate.warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
};
