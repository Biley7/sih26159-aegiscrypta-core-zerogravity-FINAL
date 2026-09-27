import { CheckResult, CheckStatus, CryptographicPosture, ProtocolAuditResult } from './types';

/**
 * A 0-100 chart signal derived from a real backend field, or null when the
 * backend did not report enough data. Callers must render an explicit
 * "N/A" state for null instead of an optimistic default.
 */
export type ScanSignal = number | null;

/** Maps a backend check status onto a chart signal. Unknown stays null. */
export function statusToScore(status: CheckStatus | null | undefined): ScanSignal {
  switch (status) {
    case 'pass':
      return 100;
    case 'warn':
      return 60;
    case 'fail':
      return 0;
    default:
      return null;
  }
}

/**
 * Maps an audited protocol probe onto a chart signal using only fields the
 * scan actually returned. Returns null when there is no handshake telemetry.
 */
export function protocolToScore(protocol: ProtocolAuditResult): ScanSignal {
  if (protocol.status === 'fail' || protocol.starttls_negotiated === false) return 0;
  const handshake = protocol.tls_handshake;
  if (handshake?.success === false) return 0;
  if (handshake?.cipher?.is_weak === true) return 30;
  if (handshake?.success === true) return protocol.status === 'warn' ? 60 : 100;
  return null;
}

const SHORT_CHECK_LABELS: Record<string, string> = {
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMRC',
  'mta-sts': 'STS',
  'tls-rpt': 'RPT',
  'dane/tlsa': 'DANE',
  dane: 'DANE',
  tlsa: 'TLSA'
};

/** Compact, stable label for a backend check name. */
export function shortCheckLabel(name: string): string {
  const key = name.trim().toLowerCase();
  if (SHORT_CHECK_LABELS[key]) return SHORT_CHECK_LABELS[key];
  const compact = name.replace(/[^a-z0-9]/gi, '').toUpperCase();
  return compact.slice(0, 5) || 'N/A';
}

/** Formats a signal for display; null becomes "N/A". */
export function formatSignal(score: ScanSignal): string {
  return score === null ? 'N/A' : `${score}%`;
}

/** Colour ramp shared by SVG/CSS fills. Null (unknown) is always neutral grey. */
export function signalColor(score: ScanSignal): string {
  if (score === null) return '#64748b';
  if (score >= 80) return '#00f0ff';
  if (score >= 60) return '#10b981';
  if (score >= 30) return '#f59e0b';
  return '#ef4444';
}

export interface SignalRow {
  key: string;
  label: string;
  value: ScanSignal;
  tooltip: string;
}

/**
 * Builds bar-chart rows exclusively from checks and protocol probes present in
 * the scan response. An empty scan yields an empty array (no synthetic rows).
 */
export function buildSignalRows(
  checks?: CheckResult[] | null,
  posture?: CryptographicPosture | null
): SignalRow[] {
  const rows: SignalRow[] = [];

  (checks ?? []).forEach((check, index) => {
    rows.push({
      key: `check-${check.name}-${index}`,
      label: shortCheckLabel(check.name),
      value: statusToScore(check.status),
      tooltip: `${check.name}: ${check.status.toUpperCase()}`
    });
  });

  (posture?.protocols_audited ?? []).forEach((probe, index) => {
    const value = protocolToScore(probe);
    rows.push({
      key: `probe-${probe.host}-${probe.port}-${index}`,
      label: `${(probe.protocol || 'TLS').slice(0, 3).toUpperCase()}:${probe.port}`,
      value,
      tooltip: `${probe.protocol} ${probe.host}:${probe.port} — ${
        value === null ? 'no handshake telemetry' : probe.status.toUpperCase()
      }`
    });
  });

  return rows;
}
