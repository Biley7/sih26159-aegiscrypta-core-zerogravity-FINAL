import React, { useState } from 'react';
import {
  Copy,
  Check,
  Code2,
  Sparkles
} from 'lucide-react';
import { AiDetailLevel, FindingSeverity, ScanResponse, SecurityFinding } from '../types';

interface RemediationEngineProps {
  data: ScanResponse;
  selectedSeverity: FindingSeverity | 'ALL';
  setSelectedSeverity: (sev: FindingSeverity | 'ALL') => void;
  aiDetail?: AiDetailLevel;
}

type ConfigTarget = 'DNS' | 'POSTFIX' | 'EXIM' | 'SENDMAIL' | 'SCRIPT';

export const RemediationEngine: React.FC<RemediationEngineProps> = ({
  data,
  selectedSeverity,
  setSelectedSeverity,
  aiDetail = 'verbose'
}) => {
  const [activeConfigTab, setActiveConfigTab] = useState<Record<string, ConfigTarget>>({});
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);

  const findings: SecurityFinding[] = data.prioritized_findings || [];

  // Filter findings by severity
  const filteredFindings = findings.filter((f) => {
    if (selectedSeverity === 'ALL') return true;
    return f.severity === selectedSeverity;
  });

  const getTargetTab = (findingTitle: string): ConfigTarget => {
    return activeConfigTab[findingTitle] || 'DNS';
  };

  const setTargetTab = (findingTitle: string, tab: ConfigTarget) => {
    setActiveConfigTab((prev) => ({
      ...prev,
      [findingTitle]: tab
    }));
  };

  const copySnippet = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedSnippetId(id);
      setTimeout(() => setCopiedSnippetId(null), 2000);
    } catch (err) {
      console.warn('Failed to copy snippet', err);
    }
  };

  // Generate tailored configuration snippets based on domain and finding
  const generateSnippets = (finding: SecurityFinding, domain: string) => {
    const isDmarc = finding.title.toLowerCase().includes('dmarc');
    const isSpf = finding.title.toLowerCase().includes('spf');
    const isDane = finding.title.toLowerCase().includes('tlsa') || finding.title.toLowerCase().includes('dane');
    const isTls = finding.title.toLowerCase().includes('tls') || finding.title.toLowerCase().includes('cipher') || finding.title.toLowerCase().includes('sweet32');
    const isCert = finding.title.toLowerCase().includes('cert');

    return {
      DNS: isDmarc
        ? `; DMARC Strict Enforcement Record (RFC 7489)\n_dmarc.${domain}.  3600  IN  TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${domain}; ruf=mailto:forensics@${domain}; aspf=s; adkim=s"`
        : isSpf
        ? `; Authoritative Hardened SPF Record (RFC 7208)\n${domain}.  3600  IN  TXT  "v=spf1 mx -all"`
        : isDane
        ? `; DANE TLSA Record for MX Port 25 (RFC 6698 / RFC 7672)\n_25._tcp.mail.${domain}.  3600  IN  TLSA  3 1 1 5a7f328b910488c5d129ee448a1fb39c623a49102e7c39aa60447e1198c00123`
        : isCert
        ? `; ACME DNS-01 Challenge Record for TLS Certificate Renewal\n_acme-challenge.mail.${domain}.  300  IN  TXT  "verification_token_here"`
        : `; MTA-STS Discovery Policy Record (RFC 8461)\n_mta-sts.${domain}.  3600  IN  TXT  "v=STSv1; id=20260901T000000Z;"`,

      POSTFIX: isTls
        ? `# /etc/postfix/main.cf - Defense Posture Hardening (NIST SP 800-52r2)\nsmtpd_tls_security_level = encrypt\nsmtp_tls_security_level = dane\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\nsmtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\nsmtpd_tls_mandatory_ciphers = high\nsmtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, 3DES\ntls_high_cipherlist = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\ntls_preempt_cipherlist = yes`
        : isDmarc || isSpf
        ? `# /etc/postfix/main.cf - Ingress Sender Authentication Milters\nsmtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893\nnon_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893\nmilter_default_action = accept`
        : `# /etc/postfix/main.cf - MTA-STS Policy Daemon\nsmtp_tls_policy_maps = socketmap:inet:127.0.0.1:8461:postfix\nsmtpd_tls_cert_file = /etc/ssl/certs/mail_${domain}.crt\nsmtpd_tls_key_file = /etc/ssl/private/mail_${domain}.key`,

      EXIM: isTls
        ? `# /etc/exim4/exim4.conf - Modern Cryptographic Hardening\ntls_advertise_hosts = *\ntls_require_ciphers = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\ntls_certificate = /etc/ssl/certs/${domain}.crt\ntls_privatekey = /etc/ssl/private/${domain}.key\nopenssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1 +cipher_server_preference`
        : `# /etc/exim4/exim4.conf - DKIM Signing Parameters\ndkim_domain = ${domain}\ndkim_selector = def2026\ndkim_private_key = /etc/exim4/dkim.key`,

      SENDMAIL: isTls
        ? `dnl # sendmail.mc - NIST SP 800-52r2 Compliant Ciphers\nLOCAL_CONFIG\nO CipherList=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305\nO ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1 +SSL_OP_CIPHER_SERVER_PREFERENCE\nO ClientSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1`
        : `dnl # sendmail.mc - Milter Verification Filters\nINPUT_MAIL_FILTER(\`opendkim', \`S=inet:8891@localhost')\nINPUT_MAIL_FILTER(\`opendmarc', \`S=inet:8893@localhost')`,

      SCRIPT: `#!/usr/bin/env bash
# AegisCrypta Automated Mail Infrastructure Remediation Script
# Target Domain: ${domain}
set -euo pipefail

echo "[AegisCrypta] Hardening Postfix TLS parameters per NIST SP 800-52r2..."
postconf -e "smtpd_tls_security_level = encrypt"
postconf -e "smtp_tls_security_level = dane"
postconf -e "smtpd_tls_mandatory_protocols = >=TLSv1.2"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "tls_preempt_cipherlist = yes"

echo "[AegisCrypta] Reloading MTA service..."
systemctl reload postfix
echo "[AegisCrypta] Hardening completed successfully."`
    };
  };

  const getSeverityBadgeClass = (sev: FindingSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'sev-critical';
      case 'HIGH':
        return 'sev-high';
      case 'MEDIUM':
        return 'sev-medium';
      case 'LOW':
        return 'sev-low';
      default:
        return 'sev-info';
    }
  };

  return (
    <section className="technical-section remediation-section" aria-label="AI Remediation and Configuration Engine">
      <div className="section-header">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="section-title">Interactive Remediation & Configuration Engine</h3>
            <span className="ai-tag font-mono text-[10px] flex items-center gap-1">
              <Sparkles size={10} /> Automated Playbooks
            </span>
          </div>
          <p className="section-description">
            Actionable mitigations, policy templates, and daemon configuration snippets (DNS, Postfix, Exim, Sendmail) to eliminate posture drift.
          </p>
        </div>

        {/* Severity Filter */}
        <div className="severity-filter" role="tablist" aria-label="Filter findings by severity">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
            const count = sev === 'ALL' ? findings.length : findings.filter((f) => f.severity === sev).length;
            return (
              <button
                key={sev}
                role="tab"
                aria-selected={selectedSeverity === sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`severity-tab ${selectedSeverity === sev ? 'active' : ''}`}
              >
                <span>{sev}</span>
                <span className="count-badge font-mono">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Remediation Table */}
      <div className="remediation-table-container">
        {filteredFindings.length > 0 ? (
          <div className="remediation-list">
            {filteredFindings.map((finding, idx) => {
              const currentTab = getTargetTab(finding.title);
              const snippets = generateSnippets(finding, data.domain);
              const activeCode = snippets[currentTab];
              const snippetKey = `${finding.title}-${currentTab}-${idx}`;

              return (
                <div key={idx} className={`remediation-item ${finding.severity.toLowerCase()}`}>
                  <div className="remediation-header">
                    <div className="remediation-title-group">
                      <span className={`severity-badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="category-badge font-mono text-xs">
                        {finding.category}
                      </span>
                    </div>
                    <h4 className="remediation-title">{finding.title}</h4>
                  </div>

                  <p className="remediation-description text-xs text-text-secondary">
                    {finding.description}
                  </p>

                  {finding.recommendation && (
                    <div className="remediation-action">
                      <span className="action-label font-mono text-xs font-semibold text-soc-secure">Action Required:</span>
                      <span className="action-text text-xs text-text-primary">{finding.recommendation}</span>
                    </div>
                  )}

                  {/* Configuration Generator */}
                  <div className="config-dock">
                    <div className="config-tabs">
                      {(['DNS', 'POSTFIX', 'EXIM', 'SENDMAIL', 'SCRIPT'] as const).map((tab) => (
                        <button
                          key={tab}
                          type="button"
                          onClick={() => setTargetTab(finding.title, tab)}
                          className={`config-tab ${currentTab === tab ? 'active' : ''}`}
                        >
                          {tab === 'DNS' ? 'BIND' : tab === 'POSTFIX' ? 'Postfix' : tab === 'EXIM' ? 'Exim' : tab === 'SENDMAIL' ? 'Sendmail' : 'Script'}
                        </button>
                      ))}
                    </div>

                    <div className="config-actions">
                      <button
                        type="button"
                        onClick={() => copySnippet(activeCode, snippetKey)}
                        className="config-copy-btn font-mono text-xs"
                      >
                        {copiedSnippetId === snippetKey ? 'Copied' : 'Copy'}
                      </button>
                    </div>

                    <pre className="config-code font-mono text-xs">{activeCode}</pre>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="no-findings text-center font-mono text-xs text-text-muted">
            <Check size={16} className="mx-auto mb-2 text-soc-secure" />
            <p className="text-text-primary font-semibold text-sm">No findings matching the selected filter</p>
            <p className="mt-1">
              The target domain fulfills cryptographic requirements for this filter view.
            </p>
          </div>
        )}
      </div>
    </section>
  );
};
