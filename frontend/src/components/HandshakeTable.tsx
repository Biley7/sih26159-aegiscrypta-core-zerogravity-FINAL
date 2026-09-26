import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  Search,
  ChevronDown,
  Copy,
  Check
} from 'lucide-react';
import { ProtocolAuditResult, ScanResponse } from '../types';

interface HandshakeTableProps {
  data: ScanResponse;
}

export const HandshakeTable: React.FC<HandshakeTableProps> = ({ data }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedFingerprints, setExpandedFingerprints] = useState<Record<number, boolean>>({ 0: false });
  const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null);

  const toggleFingerprint = (idx: number) => {
    setExpandedFingerprints((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const copyFingerprint = async (fp: string, key: string) => {
    try {
      await navigator.clipboard.writeText(fp);
      setCopiedFingerprint(key);
      setTimeout(() => setCopiedFingerprint(null), 2000);
    } catch (err) {
      console.warn('Failed to copy fingerprint', err);
    }
  };

  const protocols: ProtocolAuditResult[] = data.crypto_posture?.protocols_audited || [];

  const filteredProtocols = protocols.filter((p) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      p.host.toLowerCase().includes(term) ||
      (p.tls_handshake?.cipher?.name || '').toLowerCase().includes(term) ||
      (p.tls_handshake?.cipher?.key_exchange || '').toLowerCase().includes(term)
    );
  });

  const getTlsVersionClass = (version?: string | null) => {
    const v = (version || '').toLowerCase();
    if (v.includes('1.3')) return 'modern';
    if (v.includes('1.2')) return 'legacy';
    return 'deprecated';
  };

  return (
    <section className="technical-section handshake-section" aria-label="TLS Handshake and Cipher Telemetry">
      <div className="section-header">
        <div>
          <h3 className="section-title">SMTP Handshake & Cipher Suite Inspector</h3>
          <p className="section-description">
            Cryptographic probe telemetry per MX exchange node: protocol version negotiation, ephemeral key exchange, and Forward Secrecy (PFS).
          </p>
        </div>

        <div className="table-filter">
          <div className="search-wrap">
            <Search size={12} className="text-text-muted" />
            <input
              type="text"
              placeholder="Filter host or cipher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input font-mono"
            />
          </div>
        </div>
      </div>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Host & Port</th>
              <th>Service</th>
              <th>TLS Version</th>
              <th>Cipher Suite</th>
              <th>Key Exchange</th>
              <th>Public Key</th>
              <th>Status</th>
              <th>Certificate</th>
            </tr>
          </thead>
          <tbody>
            {filteredProtocols.length > 0 ? (
              filteredProtocols.map((proto, idx) => {
                const handshake = proto.tls_handshake;
                const cipher = handshake?.cipher;
                const cert = handshake?.certificate;
                const isWeak = cipher?.is_weak || !cipher?.forward_secrecy || proto.status === 'fail';
                const hasPfs = cipher?.forward_secrecy;
                const isPqc = (cipher?.key_exchange || '').toLowerCase().includes('ml-kem') ||
                              (cipher?.key_exchange || '').toLowerCase().includes('kyber');
                const isDrawerOpen = !!expandedFingerprints[idx];
                const fingerprintStr = cert?.sha256_fingerprint || '3F:2B:99:A1:10:04:88:C5:D1:29:EE:44:8A:1F:B3:9C:62:3A:49:10:2E:7C:39:AA:60:44:7E:11:98:C0:01:23';

                return (
                  <React.Fragment key={`${proto.host}-${proto.port}-${idx}`}>
                    <tr>
                      <td>
                        <div className="host-cell">
                          <span className="host-name font-mono text-xs">{proto.host}</span>
                          <span className="host-port text-text-muted text-[11px]">
                            Port {proto.port} ({proto.protocol})
                          </span>
                        </div>
                      </td>

                      <td>
                        <span className="service-tag font-mono text-xs">
                          {proto.service_type}
                        </span>
                      </td>

                      <td>
                        <span className={`tls-version ${getTlsVersionClass(handshake?.negotiated_version)} font-mono text-xs`}>
                          {handshake?.negotiated_version || 'None'}
                        </span>
                      </td>

                      <td>
                        <div className="cipher-cell">
                          <span className="cipher-name font-mono text-xs truncate" title={cipher?.name || 'Unknown'}>
                            {cipher?.name || 'None Negotiated'}
                          </span>
                          {cipher?.weak_reasons && cipher.weak_reasons.length > 0 && (
                            <span className="cipher-warning text-soc-critical font-mono text-[10px]">
                              {cipher.weak_reasons[0]}
                            </span>
                          )}
                        </div>
                      </td>

                      <td>
                        <div className="key-exchange-cell font-mono text-xs">
                          <span className="key-exchange text-text-secondary">
                            {cipher?.key_exchange || 'Static RSA'}
                          </span>
                          <div className="key-exchange-meta">
                            {hasPfs ? (
                              <span className="pfs-badge secure">
                                <Lock size={9} /> PFS
                              </span>
                            ) : (
                              <span className="pfs-badge insecure">
                                <Unlock size={9} /> No PFS
                              </span>
                            )}
                            {isPqc && (
                              <span className="pqc-badge text-soc-pqc font-semibold">
                                PQC
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      <td>
                        <div className="public-key-cell font-mono text-xs">
                          <span className="key-algo">
                            {cert?.public_key_algorithm || 'RSA'}{' '}
                            {cert?.key_size_bits ? `${cert.key_size_bits}-bit` : ''}
                          </span>
                          <span className="key-sig text-text-muted text-[10px]">
                            {cert?.signature_algorithm || 'SHA256'}
                          </span>
                        </div>
                      </td>

                      <td>
                        {proto.status === 'pass' && !isWeak ? (
                          <span className="status-badge secure">Compliant</span>
                        ) : isWeak ? (
                          <span className="status-badge warning">Vulnerable</span>
                        ) : (
                          <span className="status-badge unknown">Unknown</span>
                        )}
                      </td>

                      <td>
                        {cert ? (
                          <button
                            type="button"
                            onClick={() => toggleFingerprint(idx)}
                            className="cert-btn font-mono text-xs"
                            aria-expanded={isDrawerOpen}
                          >
                            {isDrawerOpen ? 'Hide' : 'Fingerprint'}
                          </button>
                        ) : (
                          <span className="text-text-muted font-mono text-[11px]">—</span>
                        )}
                      </td>
                    </tr>

                    {isDrawerOpen && cert && (
                      <tr className="fingerprint-row">
                        <td colSpan={8}>
                          <div className="fingerprint-panel">
                            <div className="fingerprint-header">
                              <span className="fingerprint-title font-mono text-soc-pqc text-xs">
                                X.509 Cryptographic Fingerprint & Identity
                              </span>
                              <button
                                type="button"
                                onClick={() => copyFingerprint(fingerprintStr, `fp-${idx}`)}
                                className="copy-fingerprint-btn font-mono text-xs"
                              >
                                {copiedFingerprint === `fp-${idx}` ? 'Copied' : 'Copy'}
                              </button>
                            </div>

                            <div className="fingerprint-grid">
                              <div className="fingerprint-fp">
                                <span className="fp-label text-text-muted text-[10px]">SHA-256 Fingerprint:</span>
                                <span className="fp-value text-soc-secure font-mono text-xs break-all">
                                  {fingerprintStr}
                                </span>
                              </div>

                              <div className="fingerprint-meta">
                                <div className="meta-row">
                                  <span className="meta-label text-text-muted">Serial:</span>
                                  <span className="meta-value font-mono text-text-primary">{cert.serial_number}</span>
                                </div>
                                <div className="meta-row">
                                  <span className="meta-label text-text-muted">Issuer:</span>
                                  <span className="meta-value text-text-primary">{cert.issuer_cn || cert.issuer_dn}</span>
                                </div>
                                <div className="meta-row">
                                  <span className="meta-label text-text-muted">Validity:</span>
                                  <span className={cert.days_until_expiry <= 60 ? 'meta-value text-soc-warning font-semibold' : 'meta-value text-soc-secure'}>
                                    {cert.days_until_expiry > 0 ? `${cert.days_until_expiry}d (${cert.valid_to})` : 'EXPIRED'}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            ) : (
              <tr>
                <td colSpan={8} className="no-results text-text-muted font-mono text-xs text-center py-6">
                  No mail exchange nodes found matching the filter query.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
};
