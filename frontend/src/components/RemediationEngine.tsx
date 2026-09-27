import React, { useState, useMemo } from 'react';
import {
  Copy,
  Check,
  Code2,
  Sparkles,
  ChevronUp,
  ChevronDown,
  AlertTriangle,
  ShieldAlert,
  Target
} from 'lucide-react';
import { AiDetailLevel, CvssMetrics, FindingSeverity, ScanResponse, SecurityFinding } from '../types';

interface RemediationEngineProps {
  data: ScanResponse;
  selectedSeverity: FindingSeverity | 'ALL';
  setSelectedSeverity: (sev: FindingSeverity | 'ALL') => void;
  aiDetail?: AiDetailLevel;
}

type ConfigTarget = 'DNS' | 'POSTFIX' | 'EXIM' | 'SENDMAIL' | 'SCRIPT';

type FindingsSortKey = 'finding' | 'category' | 'severity' | 'cvss';
type SortDir = 'asc' | 'desc';

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const SEVERITY_TO_CVSS: Record<FindingSeverity, number> = {
  CRITICAL: 9.0,
  HIGH: 7.5,
  MEDIUM: 5.0,
  LOW: 2.5,
  INFO: 0.1,
};

const cvssForFinding = (f: SecurityFinding, aggregate: CvssMetrics | undefined, idx: number): number => {
  // When backend emits per-finding CVSS in the future, read it here.
  // Today: blend aggregate scan CVSS with a per-finding severity-derived score.
  if (f.severity && SEVERITY_TO_CVSS[f.severity] !== undefined) {
    const derived = SEVERITY_TO_CVSS[f.severity];
    if (aggregate && typeof aggregate.base_score === 'number') {
      // Weight 60% finding severity + 40% aggregate posture CVSS (bounded 0.1..10)
      const blended = Math.max(0.1, Math.min(10, derived * 0.6 + aggregate.base_score * 0.4));
      return Number(blended.toFixed(1));
    }
    return derived;
  }
  return aggregate?.base_score ?? Number(idx.toFixed(1));
};

const cvssBadgeClass = (score: number): string => {
  if (score >= 9.0) return 'text-rose-700 dark:text-rose-400 bg-rose-500/10 border-rose-500/30';
  if (score >= 7.0) return 'text-orange-700 dark:text-orange-400 bg-orange-500/10 border-orange-500/30';
  if (score >= 4.0) return 'text-amber-700 dark:text-amber-400 bg-amber-500/10 border-amber-500/30';
  if (score >= 0.2) return 'text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  return 'text-slate-500 dark:text-slate-400 bg-slate-500/10 border-slate-500/30';
};

export const RemediationEngine: React.FC<RemediationEngineProps> = ({
  data,
  selectedSeverity,
  setSelectedSeverity,
  aiDetail = 'verbose'
}) => {
  const [activeConfigTab, setActiveConfigTab] = useState<Record<string, ConfigTarget>>({});
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<FindingsSortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const findings: SecurityFinding[] = data.prioritized_findings || [];
  const cvssMetrics = data.cvss_metrics;

  // Filter findings by severity
  const filteredFindings = findings.filter((f) => {
    if (selectedSeverity === 'ALL') return true;
    return f.severity === selectedSeverity;
  });

  // Sort findings based on current column + direction
  const sortedFindings = useMemo(() => {
    const rows = filteredFindings.map((f, idx) => ({ finding: f, idx }));
    const dirMul = sortDir === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'finding':
          cmp = a.finding.title.localeCompare(b.finding.title);
          break;
        case 'category':
          cmp = (a.finding.category || '').localeCompare(b.finding.category || '');
          break;
        case 'severity':
          cmp = (SEVERITY_RANK[a.finding.severity] ?? 0) - (SEVERITY_RANK[b.finding.severity] ?? 0);
          break;
        case 'cvss':
          cmp = cvssForFinding(a.finding, cvssMetrics, a.idx) - cvssForFinding(b.finding, cvssMetrics, b.idx);
          break;
      }
      if (cmp === 0) {
        // Stable tiebreak: original index order
        cmp = a.idx - b.idx;
      }
      return cmp * dirMul;
    });
    return rows.map((r) => r.finding);
  }, [filteredFindings, sortKey, sortDir, cvssMetrics]);

  const toggleSort = (key: FindingsSortKey) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'finding' || key === 'category' ? 'asc' : 'desc');
    }
  };

  const SortIndicator = ({ forKey }: { forKey: FindingsSortKey }) => {
    if (sortKey !== forKey) return <ChevronDown size={12} className="opacity-30 inline-block ml-1" />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} className="text-cyan-400 inline-block ml-1" />
      : <ChevronDown size={12} className="text-cyan-400 inline-block ml-1" />;
  };

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
      DNS: data.remediation_playbook?.bind_dns_zone ?? (isDmarc
        ? `; DMARC Strict Enforcement Record (RFC 7489)\n_dmarc.${domain}.  3600  IN  TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${domain}; ruf=mailto:forensics@${domain}; aspf=s; adkim=s"`
        : isSpf
        ? `; Authoritative Hardened SPF Record (RFC 7208)\n${domain}.  3600  IN  TXT  "v=spf1 mx -all"`
        : isDane
        ? `; DANE TLSA Record for MX Port 25 (RFC 6698 / RFC 7672)\n; IMPORTANT: Replace [TLSA_FINGERPRINT_PLACEHOLDER] with your actual certificate SHA-256 hash before publishing.\n_25._tcp.mail.${domain}.  3600  IN  TLSA  3 1 1 [TLSA_FINGERPRINT_PLACEHOLDER]`
        : isCert
        ? `; ACME DNS-01 Challenge Record for TLS Certificate Renewal\n_acme-challenge.mail.${domain}.  300  IN  TXT  "verification_token_here"`
        : `; MTA-STS Discovery Policy Record (RFC 8461)\n_mta-sts.${domain}.  3600  IN  TXT  "v=STSv1; id=20260901T000000Z;"`),

      POSTFIX: data.remediation_playbook?.postfix_main_cf ?? (isTls
        ? `# /etc/postfix/main.cf - Defense Posture Hardening (NIST SP 800-52r2)\nsmtpd_tls_security_level = encrypt\nsmtp_tls_security_level = dane\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\nsmtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\nsmtpd_tls_mandatory_ciphers = high\nsmtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, 3DES\ntls_high_cipherlist = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\ntls_preempt_cipherlist = yes`
        : isDmarc || isSpf
        ? `# /etc/postfix/main.cf - Ingress Sender Authentication Milters\nsmtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893\nnon_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893\nmilter_default_action = accept`
        : `# /etc/postfix/main.cf - MTA-STS Policy Daemon\nsmtp_tls_policy_maps = socketmap:inet:127.0.0.1:8461:postfix\nsmtpd_tls_cert_file = /etc/ssl/certs/mail_${domain}.crt\nsmtpd_tls_key_file = /etc/ssl/private/mail_${domain}.key`),

      EXIM: data.remediation_playbook?.exim_conf ?? (isTls
        ? `# /etc/exim4/exim4.conf - Modern Cryptographic Hardening\ntls_advertise_hosts = *\ntls_require_ciphers = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\ntls_certificate = /etc/ssl/certs/${domain}.crt\ntls_privatekey = /etc/ssl/private/${domain}.key\nopenssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1 +cipher_server_preference`
        : `# /etc/exim4/exim4.conf - DKIM Signing Parameters\ndkim_domain = ${domain}\ndkim_selector = def2026\ndkim_private_key = /etc/exim4/dkim.key`),

      SENDMAIL: data.remediation_playbook?.sendmail_mc ?? (isTls
        ? `dnl # sendmail.mc - NIST SP 800-52r2 Compliant Ciphers\nLOCAL_CONFIG\nO CipherList=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305\nO ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1 +SSL_OP_CIPHER_SERVER_PREFERENCE\nO ClientSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1`
        : `dnl # sendmail.mc - Milter Verification Filters\nINPUT_MAIL_FILTER(\`opendkim', \`S=inet:8891@localhost')\nINPUT_MAIL_FILTER(\`opendmarc', \`S=inet:8893@localhost')`),

      SCRIPT: data.remediation_playbook?.shell_script ?? `#!/usr/bin/env bash
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

      {/* Aggregate CVSS Metrics Banner */}
      {cvssMetrics && (
        <div className="mb-4 p-4 rounded-md bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 hover:border-cyan-500/50 transition-colors flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 flex items-center justify-center">
              <Target size={19} className="text-rose-600 dark:text-rose-400" />
            </div>
            <div>
              <div className="uppercase tracking-[0.2em] text-[10px] sm:text-[11px] font-bold text-slate-500 dark:text-slate-400">
                CVSS v3.1 Risk Metrics · Aggregate Scan Posture
              </div>
              <div className="flex items-center gap-3 mt-1">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border font-mono text-xs font-bold ${cvssBadgeClass(cvssMetrics.base_score ?? 0)}`}>
                  <ShieldAlert size={12} />
                  Base Score · {(cvssMetrics.base_score ?? 0).toFixed(1)}
                </span>
                {cvssMetrics.severity && (
                  <span className="font-mono text-xs text-cyan-700 dark:text-cyan-400/90 font-semibold uppercase tracking-wider">
                    Severity: {cvssMetrics.severity}
                  </span>
                )}
                {cvssMetrics.vector_string && (
                  <code className="hidden md:inline font-mono text-[10px] tracking-tight text-slate-600 dark:text-slate-400 ml-2 truncate max-w-xs" title={cvssMetrics.vector_string}>
                    {cvssMetrics.vector_string}
                  </code>
                )}
              </div>
            </div>
          </div>
          {(cvssMetrics.exploitability_score !== undefined || cvssMetrics.impact_score !== undefined) && (
            <div className="flex items-center gap-6 font-mono text-[11px]">
              {cvssMetrics.exploitability_score !== undefined && (
                <div className="text-right">
                  <div className="text-slate-600 dark:text-slate-400 uppercase tracking-[0.2em] text-[10px]">Exploitability</div>
                  <div className="text-amber-600 dark:text-amber-400 font-bold text-sm">{cvssMetrics.exploitability_score.toFixed(1)}</div>
                </div>
              )}
              {cvssMetrics.impact_score !== undefined && (
                <div className="text-right">
                  <div className="text-slate-600 dark:text-slate-400 uppercase tracking-[0.2em] text-[10px]">Impact</div>
                  <div className="text-rose-600 dark:text-rose-400 font-bold text-sm">{cvssMetrics.impact_score.toFixed(1)}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Sortable Findings Table */}
      <div className="mb-5 rounded-md overflow-hidden bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 hover:border-cyan-500/50 transition-colors">
        <table className="w-full text-left font-mono">
          <thead className="bg-slate-100 dark:bg-slate-950/70 text-slate-600 dark:text-slate-400 uppercase text-[10px] tracking-[0.2em] border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-5 py-3.5 w-[42%]">
                <button
                  type="button"
                  onClick={() => toggleSort('finding')}
                  className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors font-semibold"
                >
                  <AlertTriangle size={13} className="text-amber-400" />
                  Finding / Vulnerability
                  <SortIndicator forKey="finding" />
                </button>
              </th>
              <th className="px-5 py-3.5 w-[18%]">
                <button
                  type="button"
                  onClick={() => toggleSort('category')}
                  className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors font-semibold"
                >
                  <Code2 size={13} className="text-cyan-600 dark:text-cyan-400" />
                  Category
                  <SortIndicator forKey="category" />
                </button>
              </th>
              <th className="px-5 py-3.5 w-[18%]">
                <button
                  type="button"
                  onClick={() => toggleSort('severity')}
                  className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors font-semibold"
                >
                  <ShieldAlert size={13} className="text-rose-400" />
                  Severity
                  <SortIndicator forKey="severity" />
                </button>
              </th>
              <th className="px-5 py-3.5 w-[22%]">
                <button
                  type="button"
                  onClick={() => toggleSort('cvss')}
                  className="flex items-center gap-1.5 hover:text-cyan-400 transition-colors font-semibold"
                >
                  <Target size={13} className="text-emerald-400" />
                  CVSS Score
                  <SortIndicator forKey="cvss" />
                </button>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 text-[11px]">
            {sortedFindings.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-5 py-8 text-center text-slate-500 dark:text-slate-400">
                  <Check size={16} className="mx-auto mb-2 text-emerald-600 dark:text-emerald-400" />
                  <span className="font-semibold text-slate-700 dark:text-slate-300">No findings match the current severity filter.</span>
                </td>
              </tr>
            ) : (
              sortedFindings.map((finding, idx) => {
                const score = cvssForFinding(finding, cvssMetrics, idx);
                return (
                  <tr
                    key={`${finding.title}-${idx}`}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="px-5 py-3.5 align-top">
                      <div className="font-semibold text-slate-800 dark:text-slate-100 text-[12px] font-sans leading-snug">
                        {finding.title}
                      </div>
                      {finding.description && (
                        <div className="mt-1.5 text-[11px] text-slate-500 dark:text-slate-400 leading-tight line-clamp-2">
                          {finding.description}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-3.5 align-top">
                      <span className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-cyan-700 dark:text-cyan-400/90 uppercase tracking-wider text-[10px] font-semibold">
                        {finding.category || 'Uncategorized'}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 align-top">
                      <span
                        className={`inline-block px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border ${getSeverityBadgeClass(finding.severity)}`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 align-top">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-bold border ${cvssBadgeClass(score)}`}
                      >
                        <Target size={10} />
                        {score.toFixed(1)}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
        {sortedFindings.length > 0 && (
          <div className="px-5 py-2.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 text-[10px] text-slate-600 dark:text-slate-400 font-mono flex items-center justify-between">
            <span className="tracking-wider uppercase">Showing {sortedFindings.length} Finding{sortedFindings.length === 1 ? '' : 's'}</span>
            <span className="tracking-wider uppercase">Sorted by {sortKey.toUpperCase()} · {sortDir.toUpperCase()}</span>
          </div>
        )}
      </div>

      {/* Remediation Cards (drilled detail snippets) */}
      <div className="remediation-table-container">
        {filteredFindings.length > 0 ? (
          <div className="remediation-list">
            {sortedFindings.map((finding, idx) => {
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
