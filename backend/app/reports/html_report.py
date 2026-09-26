from datetime import datetime, timezone
from typing import List, Optional
import jinja2

from app.models import (
    CheckResult,
    CryptographicPosture,
    AiRiskScore,
    TlsAnomalyDetectionResult,
    SecurityFinding
)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Mail Security Posture Audit - {{ domain }}</title>
<style>
  :root {
    --bg-primary: #0b0f19;
    --bg-card: #131b2e;
    --bg-card-alt: #1a243d;
    --border: #233052;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --critical: #dc2626;
    --info: #6366f1;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
  body { background-color: var(--bg-primary); color: var(--text-primary); padding: 32px 16px; line-height: 1.5; }
  .container { max-width: 1100px; margin: 0 auto; }
  
  /* Header */
  .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
  .header-left h1 { font-size: 26px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
  .header-left p { color: var(--text-secondary); font-size: 14px; margin-top: 4px; }
  .header-right { text-align: right; }
  .timestamp { color: var(--text-secondary); font-size: 13px; }
  
  /* Score Hero */
  .score-grid { display: grid; grid-template-columns: 280px 1fr; gap: 24px; margin-bottom: 32px; }
  .score-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 28px; text-align: center; }
  .score-number { font-size: 64px; font-weight: 800; color: {% if score >= 80 %}var(--success){% elif score >= 50 %}var(--warning){% else %}var(--danger){% endif %}; line-height: 1; }
  .score-grade { display: inline-block; font-size: 16px; font-weight: 700; padding: 4px 14px; border-radius: 9999px; background: rgba(56, 189, 248, 0.15); color: var(--accent); margin-top: 12px; }
  .metrics-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
  .metric-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
  .metric-label { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
  .metric-val { font-size: 20px; font-weight: 700; margin-top: 6px; color: #fff; }
  
  /* Sections */
  .section { margin-bottom: 36px; }
  .section-title { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  
  /* Tables */
  .table-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
  th { background: var(--bg-card-alt); color: var(--text-secondary); font-weight: 600; padding: 12px 16px; border-bottom: 1px solid var(--border); }
  td { padding: 14px 16px; border-bottom: 1px solid var(--border); }
  tr:last-child td { border-bottom: none; }
  
  /* Badges */
  .badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; text-transform: uppercase; }
  .badge-pass { background: rgba(16, 185, 129, 0.2); color: var(--success); }
  .badge-warn { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
  .badge-fail { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
  .badge-critical { background: rgba(220, 38, 38, 0.25); color: #fca5a5; }
  .badge-high { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
  .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
  .badge-low { background: rgba(99, 102, 241, 0.2); color: var(--info); }
  
  /* Findings List */
  .finding-item { background: var(--bg-card); border-left: 4px solid; border-radius: 0 8px 8px 0; border: 1px solid var(--border); border-left-width: 4px; padding: 16px; margin-bottom: 12px; }
  .finding-CRITICAL { border-left-color: var(--critical); }
  .finding-HIGH { border-left-color: var(--danger); }
  .finding-MEDIUM { border-left-color: var(--warning); }
  .finding-LOW { border-left-color: var(--info); }
  .finding-title { font-weight: 600; font-size: 15px; color: #fff; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center; }
  .finding-desc { color: var(--text-secondary); font-size: 13px; margin-bottom: 8px; }
  .finding-rec { font-size: 12px; background: rgba(255, 255, 255, 0.04); padding: 8px 12px; border-radius: 6px; color: #38bdf8; }
  
  /* Certificate Card */
  .cert-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .cert-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; font-size: 13px; }
  .cert-field { display: flex; flex-direction: column; }
  .cert-field-label { color: var(--text-secondary); font-size: 11px; text-transform: uppercase; margin-bottom: 2px; }
  .cert-field-val { font-weight: 600; color: #fff; word-break: break-all; }

  @media print {
    body { background: #fff; color: #000; padding: 0; }
    .score-card, .metric-card, .table-wrap, .finding-item, .cert-card { background: #fff; border-color: #e2e8f0; color: #000; }
    .section-title, .finding-title, .metric-val, .cert-field-val { color: #000 !important; }
    .header { border-color: #e2e8f0; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>Cryptographic & Email Security Posture Report</h1>
      <p>Target Domain: <strong>{{ domain }}</strong> &bull; SIH 26 159 Forensic Assessment</p>
    </div>
    <div class="header-right">
      <div class="timestamp">Generated: {{ scanned_at }}</div>
    </div>
  </div>

  <!-- Score & Hero Grid -->
  <div class="score-grid">
    <div class="score-card">
      <div class="score-number">{{ score }}</div>
      <div style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">Security Score / 100</div>
      <div class="score-grade">GRADE {{ crypto_grade }}</div>
    </div>
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">AI Cryptographic Risk</div>
        <div class="metric-val" style="color: {% if ai_risk.risk_level == 'LOW' %}var(--success){% elif ai_risk.risk_level == 'MEDIUM' %}var(--warning){% else %}var(--danger){% endif %};">
          {{ ai_risk.risk_score }}/100 ({{ ai_risk.risk_level }})
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Perfect Forward Secrecy</div>
        <div class="metric-val" style="color: {% if forward_secrecy %}var(--success){% else %}var(--danger){% endif %};">
          {{ "Enforced" if forward_secrecy else "Not Enforced" }}
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">TLS Session Anomaly</div>
        <div class="metric-val" style="color: {% if anomaly.anomaly_detected %}var(--danger){% else %}var(--success){% endif %};">
          {{ "Suspicious Activity" if anomaly.anomaly_detected else "Nominal / Clean" }}
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Protocol Coverage</div>
        <div class="metric-val">{{ protocols_count }} Endpoint(s) Audited</div>
      </div>
    </div>
  </div>

  <!-- Prioritized Security Findings -->
  <div class="section">
    <div class="section-title">Prioritized Security Findings ({{ findings|length }})</div>
    {% if findings %}
      {% for f in findings %}
      <div class="finding-item finding-{{ f.severity.value }}">
        <div class="finding-title">
          <span>{{ f.title }}</span>
          <span class="badge badge-{{ f.severity.value.lower() }}">{{ f.severity.value }}</span>
        </div>
        <div class="finding-desc">{{ f.description }}</div>
        {% if f.recommendation %}
        <div class="finding-rec"><strong>Recommendation:</strong> {{ f.recommendation }}</div>
        {% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div style="color: var(--success); font-size: 14px; background: var(--bg-card); padding: 16px; border-radius: 8px;">
        No critical or high security posture issues identified. All checks passed nominal thresholds.
      </div>
    {% endif %}
  </div>

  <!-- Protocol & Cryptographic Inspection Matrix -->
  <div class="section">
    <div class="section-title">Active Protocol & TLS Handshake Inspection</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Host & Port</th>
            <th>Service Type</th>
            <th>STARTTLS Status</th>
            <th>TLS Version</th>
            <th>Cipher Suite</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {% for p in protocols %}
          <tr>
            <td><strong>{{ p.protocol }}</strong></td>
            <td>{{ p.host }}:{{ p.port }}</td>
            <td>{{ p.service_type }}</td>
            <td>
              {% if p.starttls_negotiated %}
                <span class="badge badge-pass">Negotiated</span>
              {% elif p.starttls_advertised %}
                <span class="badge badge-warn">Advertised</span>
              {% elif p.service_type == "Direct TLS" %}
                <span class="badge badge-pass">Implicit TLS</span>
              {% else %}
                <span class="badge badge-fail">Missing</span>
              {% endif %}
            </td>
            <td>{{ p.tls_handshake.negotiated_version if p.tls_handshake and p.tls_handshake.negotiated_version else "N/A" }}</td>
            <td>{{ p.tls_handshake.cipher.name if p.tls_handshake and p.tls_handshake.cipher else "N/A" }}</td>
            <td><span class="badge badge-{{ p.status.value }}">{{ p.status.value }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- X.509 Certificate Chain Forensics -->
  <div class="section">
    <div class="section-title">X.509 Certificate Hierarchy & Cryptographic Telemetry</div>
    {% for p in protocols %}
      {% if p.tls_handshake and p.tls_handshake.certificate %}
      {% set cert = p.tls_handshake.certificate %}
      <div class="cert-card">
        <div style="margin-bottom: 12px; font-weight: 700; color: var(--accent);">
          Endpoint Certificate: {{ p.host }}:{{ p.port }} ({{ p.protocol }})
        </div>
        <div class="cert-grid">
          <div class="cert-field">
            <span class="cert-field-label">Subject Common Name</span>
            <span class="cert-field-val">{{ cert.subject_cn or "N/A" }}</span>
          </div>
          <div class="cert-field">
            <span class="cert-field-label">Issuer Authority</span>
            <span class="cert-field-val">{{ cert.issuer_cn or cert.issuer_dn }}</span>
          </div>
          <div class="cert-field">
            <span class="cert-field-label">Validity Window</span>
            <span class="cert-field-val">{{ cert.valid_from[:10] }} to {{ cert.valid_to[:10] }} ({{ cert.days_until_expiry }} days left)</span>
          </div>
          <div class="cert-field">
            <span class="cert-field-label">Public Key Algorithm</span>
            <span class="cert-field-val">{{ cert.public_key_algorithm }} ({{ cert.key_size_bits }}-bit)</span>
          </div>
          <div class="cert-field">
            <span class="cert-field-label">Signature Digest Algorithm</span>
            <span class="cert-field-val">{{ cert.signature_algorithm }}</span>
          </div>
          <div class="cert-field">
            <span class="cert-field-label">Trust Status</span>
            <span class="cert-field-val" style="color: {% if cert.is_self_signed %}var(--danger){% else %}var(--success){% endif %};">
              {{ "Self-Signed (Untrusted)" if cert.is_self_signed else "CA Trusted" }}
            </span>
          </div>
        </div>
      </div>
      {% endif %}
    {% endfor %}
  </div>

  <!-- DNS Authentication Summary -->
  <div class="section">
    <div class="section-title">DNS Security & Sender Authentication Checks</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Diagnostic Findings</th>
          </tr>
        </thead>
        <tbody>
          {% for c in checks %}
          <tr>
            <td><strong>{{ c.name }}</strong></td>
            <td><span class="badge badge-{{ c.status.value }}">{{ c.status.value }}</span></td>
            <td>{{ c.details.message if c.details and c.details.message else c.details }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Hierarchical Fuzzy Logic Risk Assessment -->
  {% if linguistic_classification or antecedent_scores %}
  <div class="section">
    <div class="section-title">Hierarchical Fuzzy Logic Risk Assessment (Mamdani FIS Tier 1 & 2)</div>
    <div class="table-wrap" style="padding: 20px; background: var(--bg-card);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <span style="font-size: 14px; color: var(--text-secondary);">Linguistic Posture Classification:</span>
          <strong style="font-size: 18px; margin-left: 8px; color: {% if linguistic_classification in ['EXCELLENT', 'GOOD'] %}var(--success){% elif linguistic_classification == 'ACCEPTABLE' %}var(--warning){% else %}var(--danger){% endif %};">
            {{ linguistic_classification or "NOMINAL" }}
          </strong>
        </div>
        {% if fuzzy_score is not none %}
        <div style="font-size: 14px;">
          <span style="color: var(--text-secondary);">Defuzzified Posture Score:</span>
          <strong style="color: #38bdf8; font-size: 18px; margin-left: 6px;">{{ fuzzy_score }}/100</strong>
        </div>
        {% endif %}
      </div>

      {% if antecedent_scores %}
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px;">
        {% for key, val in antecedent_scores.items() %}
        <div style="background: var(--bg-card-alt); padding: 12px; border-radius: 8px; border: 1px solid var(--border);">
          <div style="font-size: 11px; text-transform: uppercase; color: var(--text-secondary);">{{ key.replace('_', ' ') }}</div>
          <div style="font-size: 18px; font-weight: 700; color: #fff; margin-top: 4px;">{{ (val * 100)|round(1) }}%</div>
          <div style="width: 100%; height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 6px; overflow: hidden;">
            <div style="width: {{ (val * 100)|round }}%; height: 100%; background: {% if val >= 0.75 %}var(--success){% elif val >= 0.5 %}var(--warning){% else %}var(--danger){% endif %};"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% endif %}

      {% if activated_rules %}
      <div style="margin-top: 14px;">
        <span style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Activated Fuzzy Rules (Explainability Trace):</span>
        <ul style="margin-top: 8px; padding-left: 20px; font-size: 12px; color: var(--text-primary); font-family: monospace;">
          {% for r in activated_rules %}
          <li style="margin-bottom: 4px;">{{ r }}</li>
          {% endfor %}
        </ul>
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- Automated Remediation Playbooks -->
  {% if playbook %}
  <div class="section">
    <div class="section-title">Automated Remediation & Hardening Playbooks</div>
    
    {% if playbook.postfix_main_cf %}
    <div style="margin-bottom: 16px;">
      <h3 style="font-size: 13px; color: #38bdf8; margin-bottom: 6px; font-family: monospace;">Postfix Hardening Configuration (/etc/postfix/main.cf)</h3>
      <pre style="background: #060911; border: 1px solid var(--border); padding: 14px; border-radius: 8px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #93c5fd;">{{ playbook.postfix_main_cf }}</pre>
    </div>
    {% endif %}

    {% if playbook.exim_conf %}
    <div style="margin-bottom: 16px;">
      <h3 style="font-size: 13px; color: #38bdf8; margin-bottom: 6px; font-family: monospace;">Exim Hardening Directives (/etc/exim/exim.conf)</h3>
      <pre style="background: #060911; border: 1px solid var(--border); padding: 14px; border-radius: 8px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #93c5fd;">{{ playbook.exim_conf }}</pre>
    </div>
    {% endif %}

    {% if playbook.bind_dns_zone %}
    <div style="margin-bottom: 16px;">
      <h3 style="font-size: 13px; color: #38bdf8; margin-bottom: 6px; font-family: monospace;">Authoritative BIND DNS Zone Directives (SPF, DMARC, TLSA, MTA-STS)</h3>
      <pre style="background: #060911; border: 1px solid var(--border); padding: 14px; border-radius: 8px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #86efac;">{{ playbook.bind_dns_zone }}</pre>
    </div>
    {% endif %}

    {% if playbook.shell_script %}
    <div>
      <h3 style="font-size: 13px; color: #38bdf8; margin-bottom: 6px; font-family: monospace;">Automated Remediation Bash Script (apply_remediation.sh)</h3>
      <pre style="background: #060911; border: 1px solid var(--border); padding: 14px; border-radius: 8px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #fde047;">{{ playbook.shell_script }}</pre>
    </div>
    {% endif %}

  </div>
  {% endif %}

</div>
</body>
</html>
"""


def generate_html_forensic_report(
    domain: str,
    score: int,
    checks: List[CheckResult],
    crypto_posture: Optional[CryptographicPosture],
    ai_risk: AiRiskScore,
    anomaly: TlsAnomalyDetectionResult,
    scanned_at: str,
    fuzzy_score: Optional[float] = None,
    linguistic_classification: Optional[str] = None,
    antecedent_scores: Optional[dict] = None,
    activated_rules: Optional[List[str]] = None,
    playbook: Optional[object] = None,
    cvss_metrics: Optional[object] = None
) -> str:
    """Renders comprehensive HTML forensic audit report using Jinja2."""
    template = jinja2.Template(HTML_TEMPLATE)

    protocols = crypto_posture.protocols_audited if crypto_posture else []
    findings = crypto_posture.prioritized_findings if crypto_posture else []
    crypto_grade = crypto_posture.grade if crypto_posture else "B"
    forward_secrecy = crypto_posture.forward_secrecy_supported if crypto_posture else False

    return template.render(
        domain=domain,
        score=score,
        crypto_grade=crypto_grade,
        checks=checks,
        protocols=protocols,
        protocols_count=len(protocols),
        findings=findings,
        forward_secrecy=forward_secrecy,
        ai_risk=ai_risk,
        anomaly=anomaly,
        scanned_at=scanned_at,
        fuzzy_score=fuzzy_score,
        linguistic_classification=linguistic_classification,
        antecedent_scores=antecedent_scores,
        activated_rules=activated_rules,
        playbook=playbook,
        cvss_metrics=cvss_metrics
    )
