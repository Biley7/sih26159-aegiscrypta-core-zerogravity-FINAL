export type CheckStatus = 'pass' | 'warn' | 'fail' | 'unknown';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanState = 'IDLE' | 'SCANNING' | 'SUCCESS' | 'ERROR';

export interface SecurityFinding {
  title: string;
  severity: FindingSeverity;
  category: string;
  description: string;
  recommendation?: string;
}

export interface CertificateInfo {
  subject_cn?: string | null;
  issuer_cn?: string | null;
  subject_dn: string;
  issuer_dn: string;
  serial_number: string;
  valid_from: string;
  valid_to: string;
  days_until_expiry: number;
  is_expired: boolean;
  is_self_signed: boolean;
  public_key_algorithm: string;
  key_size_bits?: number | null;
  signature_algorithm: string;
  sha256_fingerprint?: string;
  san_list: string[];
  matches_domain?: boolean | null;
  warnings: string[];
  chain_valid?: boolean | null;
  chain_error?: string | null;
}

export interface CipherSuiteInfo {
  name: string;
  tls_version: string;
  key_exchange: string;
  forward_secrecy: boolean;
  encryption: string;
  mac?: string | null;
  bits?: number | null;
  is_weak: boolean;
  weak_reasons: string[];
}

export interface TlsHandshakeResult {
  success: boolean;
  negotiated_version?: string | null;
  cipher?: CipherSuiteInfo | null;
  certificate?: CertificateInfo | null;
  alpn_selected?: string | null;
  error_message?: string | null;
}

export interface ProtocolAuditResult {
  protocol: string;
  host: string;
  port: number;
  service_type: string;
  banner?: string | null;
  starttls_advertised?: boolean | null;
  starttls_negotiated?: boolean | null;
  tls_handshake?: TlsHandshakeResult | null;
  findings: SecurityFinding[];
  status: CheckStatus;
}

export interface CryptographicPosture {
  crypto_score: number;
  grade: string;
  protocols_audited: ProtocolAuditResult[];
  forward_secrecy_supported: boolean;
  weak_ciphers_found: boolean;
  deprecated_tls_found: boolean;
  certificate_issues_found: boolean;
  prioritized_findings: SecurityFinding[];
}

export interface AiRiskScore {
  risk_score: number;
  risk_level: string;
  confidence: number;
  risk_factors: string[];
  mitigation_priority: string[];
}

export interface TlsAnomalyDetectionResult {
  anomaly_detected: boolean;
  anomaly_score: number;
  confidence: number;
  detected_anomalies: string[];
  suspicious_indicators: string[];
}

export interface CheckResult {
  name: string;
  status: CheckStatus;
  details: Record<string, any>;
  recommendation?: string;
}

export interface ScanResponse {
  domain: string;
  score: number;
  checks: CheckResult[];
  crypto_posture?: CryptographicPosture;
  ai_risk_score?: AiRiskScore;
  anomaly_detection?: TlsAnomalyDetectionResult;
  prioritized_findings?: SecurityFinding[];
  scanned_at: string;
  // Fuzzy logic extension fields
  fuzzy_score?: number;
  linguistic_classification?: 'EXCELLENT' | 'GOOD' | 'ACCEPTABLE' | 'POOR' | 'CRITICAL';
  antecedent_scores?: {
    tls_compliance: number;
    cipher_strength: number;
    certificate_health: number;
    pqc_readiness: number;
    email_auth_posture: number;
    exploitation_likelihood: number;
  };
  activated_rules?: string[];
  defuzzification_confidence?: number;
  cvss_metrics?: CvssMetrics;
  remediation_playbook?: RemediationPlaybook;
}

export interface CvssMetrics {
  base_score: number;
  vector_string: string;
  severity: string;
  exploitability_score?: number;
  impact_score?: number;
}

export interface RemediationPlaybook {
  postfix_main_cf?: string;
  exim_conf?: string;
  sendmail_mc?: string;
  bind_dns_zone?: string;
  shell_script?: string;
}

export interface TcpStreamSummary {
  stream_id: number;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  protocol: string;
  packet_count: number;
  client_bytes: number;
  server_bytes: number;
  starttls_detected: boolean;
  tls_handshake_detected: boolean;
  tls_version?: string | null;
  cipher_suite?: string | null;
  certificate_extracted: boolean;
  certificate_info?: CertificateInfo | null;
  findings: SecurityFinding[];
}

export interface PcapAnalysisResponse {
  filename: string;
  total_packets: number;
  total_tcp_streams: number;
  identified_protocols: string[];
  streams: TcpStreamSummary[];
  summary_findings: SecurityFinding[];
  processed_at: string;
  fuzzy_score?: number;
  linguistic_classification?: 'EXCELLENT' | 'GOOD' | 'ACCEPTABLE' | 'POOR' | 'CRITICAL';
  antecedent_scores?: {
    tls_compliance: number;
    cipher_strength: number;
    certificate_health: number;
    pqc_readiness: number;
    email_auth_posture: number;
    exploitation_likelihood: number;
  };
}

export type AppTheme = 'dark' | 'light' | 'high-contrast';
export type TelemetryDensity = 'normal' | 'compact';
export type AiDetailLevel = 'verbose' | 'executive';

export interface AppSettings {
  theme: AppTheme;
  density: TelemetryDensity;
  aiDetail: AiDetailLevel;
  apiBaseUrl: string;
}

