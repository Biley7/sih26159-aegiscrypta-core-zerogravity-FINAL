import React, { useState } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  ChevronDown,
  Copy,
  Check,
  FileCode
} from 'lucide-react';
import { CheckResult, CheckStatus, ScanResponse } from '../types';

interface ProtocolMatrixProps {
  data: ScanResponse;
}

export const ProtocolMatrix: React.FC<ProtocolMatrixProps> = ({ data }) => {
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({
    'SPF': false,
    'DKIM': false,
    'DMARC': true, // DMARC open by default to display policy
    'MTA-STS': false,
    'TLS-RPT': false,
    'DANE/TLSA': false
  });

  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const toggleExpand = (name: string) => {
    setExpandedCards((prev) => ({
      ...prev,
      [name]: !prev[name]
    }));
  };

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.warn('Clipboard write error', err);
    }
  };

  const getStatusBadge = (status: CheckStatus) => {
    switch (status) {
      case 'pass':
        return (
          <span className="status-badge-chip secure">
            <CheckCircle2 size={11} /> Secure
          </span>
        );
      case 'warn':
        return (
          <span className="status-badge-chip warning">
            <AlertTriangle size={11} /> Warning
          </span>
        );
      case 'fail':
        return (
          <span className="status-badge-chip critical">
            <XCircle size={11} /> Deficient
          </span>
        );
      default:
        return (
          <span className="status-badge-chip unknown">
            <HelpCircle size={11} /> Unknown
          </span>
        );
    }
  };

  const checks = data.checks || [];

  return (
    <section className="technical-section protocol-section" aria-label="Email Authentication & DNS Authority">
      <div className="section-header">
        <h3 className="section-title">Email Authentication & DNS Authority</h3>
        <span className="section-count font-mono">{checks.length} controls</span>
      </div>

      <div className="protocol-table-container">
        <table className="protocol-table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Status</th>
              <th>Summary</th>
              <th>Key Attributes</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((check) => {
              const isExpanded = !!expandedCards[check.name];
              const details = check.details || {};
              const recordHost = details.record_host || '@';
              const recordValue = details.record_value || details.message || 'No record published';
              const rfc = getRfcStandard(check.name);

              return (
                <React.Fragment key={check.name}>
                  <tr className={`protocol-row ${check.status}`}>
                    <td>
                      <div className="protocol-cell">
                        <span className="protocol-name font-mono">{check.name}</span>
                        <span className="protocol-rfc font-mono text-text-muted">{rfc}</span>
                      </div>
                    </td>
                    <td>{getStatusBadge(check.status)}</td>
                    <td>
                      <span className="protocol-summary text-xs text-text-secondary">
                        {details.message || check.recommendation || 'Evaluated against security standard.'}
                      </span>
                    </td>
                    <td>
                      <div className="attributes-list">
                        {Object.entries(details)
                          .filter(([k]) => !['record_value', 'message', 'record_type', 'error'].includes(k))
                          .slice(0, 2)
                          .map(([key, val]) => (
                            <span key={key} className="attribute-item font-mono text-[10px]">
                              <span className="attr-key text-text-muted">{key}:</span>
                              <span className="attr-val text-text-secondary">{String(val)}</span>
                            </span>
                          ))}
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={() => toggleExpand(check.name)}
                        className="expand-btn font-mono text-xs"
                        aria-expanded={isExpanded}
                      >
                        {isExpanded ? 'Hide' : 'Record'}
                      </button>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="protocol-expanded-row">
                      <td colSpan={5}>
                        <div className="expanded-record">
                          <div className="record-header">
                            <span className="record-host font-mono text-text-muted">Host: {recordHost}</span>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(recordValue, check.name)}
                              className="copy-btn font-mono text-xs"
                            >
                              {copiedKey === check.name ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                          <pre className="record-content font-mono text-xs">{recordValue}</pre>
                          {check.recommendation && (
                            <div className="record-remediation font-mono text-xs">
                              <span className="text-soc-warning">Remediation: </span>
                              <span className="text-text-secondary">{check.recommendation}</span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};

function getRfcStandard(name: string): string {
  switch (name) {
    case 'SPF':
      return 'RFC 7208';
    case 'DKIM':
      return 'RFC 6376';
    case 'DMARC':
      return 'RFC 7489';
    case 'MTA-STS':
      return 'RFC 8461';
    case 'TLS-RPT':
      return 'RFC 8460';
    case 'DANE/TLSA':
      return 'RFC 6698 / 7672';
    default:
      return 'RFC STD';
  }
}
