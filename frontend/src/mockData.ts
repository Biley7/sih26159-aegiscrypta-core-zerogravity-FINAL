import { PcapAnalysisResponse, ScanResponse } from './types';

export const mockGovIn: ScanResponse = {
  domain: 'gov.in',
  score: 87,
  scanned_at: new Date().toISOString(),
  checks: [
    {
      name: 'SPF',
      status: 'pass',
      details: {
        record_type: 'TXT',
        record_host: '@',
        record_value: 'v=spf1 include:_spf.gov.in ip4:164.100.0.0/16 -all',
        lookups: 2,
        policy: 'strict (-all)',
        message: 'SPF record published with hard fail policy and validated CIDR prefixes.'
      },
      recommendation: 'Maintain SPF include path discipline and keep DNS lookups below RFC 7208 limits.'
    },
    {
      name: 'DKIM',
      status: 'warn',
      details: {
        selector: 'nic2024',
        record_host: 'nic2024._domainkey.gov.in',
        record_value: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7b6...',
        key_size: 2048,
        status: 'active',
        message: 'DKIM key is RSA-2048. Selector key rotation overdue (>180 days).'
      },
      recommendation: 'Rotate DKIM selector keys bi-annually and consider dual-signing with Ed25519.'
    },
    {
      name: 'DMARC',
      status: 'pass',
      details: {
        record_host: '_dmarc.gov.in',
        record_value: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@gov.in; ruf=mailto:forensics@gov.in; aspf=s; adkim=s',
        policy: 'reject (100%)',
        enforcement: 'full',
        alignment: 'strict (aspf=s, adkim=s)',
        message: 'DMARC record is enforcing full reject policy with forensic aggregate reporting.'
      },
      recommendation: 'Continue monitoring DMARC forensic and aggregate feeds for alignment drifts.'
    },
    {
      name: 'MTA-STS',
      status: 'pass',
      details: {
        record_host: '_mta-sts.gov.in',
        record_value: 'v=STSv1; id=20260901T000000Z; mode=enforce; mx=mail.gov.in; mx=backup.gov.in; max_age=604800',
        mode: 'enforce',
        max_age: '604800s (7 days)',
        message: 'MTA-STS policy published in strict enforce mode to prevent TLS downgrade.'
      },
      recommendation: 'Ensure MTA-STS certificate expiration matches TLS endpoint renewals.'
    },
    {
      name: 'TLS-RPT',
      status: 'pass',
      details: {
        record_host: '_smtp._tls.gov.in',
        record_value: 'v=TLSRPTv1; rua=mailto:tls-reports@gov.in',
        message: 'SMTP TLS reporting enabled and accepting failure telemetry.'
      },
      recommendation: 'Regularly ingest TLS-RPT payloads into SOC SIEM for downgrade detection.'
    },
    {
      name: 'DANE/TLSA',
      status: 'warn',
      details: {
        record_host: '_25._tcp.mail.gov.in',
        record_value: '3 1 1 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        dnssec: 'enabled',
        message: 'TLSA published for primary MX, but secondary MX host lacks TLSA record.'
      },
      recommendation: 'Publish TLSA records for all secondary and backup MX gateways.'
    }
  ],
  crypto_posture: {
    crypto_score: 87,
    grade: 'A',
    protocols_audited: [
      {
        protocol: 'SMTP',
        host: 'mail.gov.in',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 mail.gov.in ESMTP Postfix (NIC Secure Gateway)',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.3',
          cipher: {
            name: 'TLS_AES_256_GCM_SHA384',
            tls_version: 'TLS 1.3',
            key_exchange: 'ECDHE (X25519)',
            forward_secrecy: true,
            encryption: 'AES-256-GCM',
            mac: 'AEAD',
            bits: 256,
            is_weak: false,
            weak_reasons: []
          },
          certificate: {
            subject_cn: 'mail.gov.in',
            issuer_cn: 'National Informatics Centre CA',
            subject_dn: 'CN=mail.gov.in, O=National Informatics Centre, C=IN',
            issuer_dn: 'CN=NIC Sub-CA 2024, O=NIC, C=IN',
            serial_number: '5A:7F:32:8B:91:04',
            valid_from: '2025-01-10',
            valid_to: '2027-01-10',
            days_until_expiry: 485,
            is_expired: false,
            is_self_signed: false,
            public_key_algorithm: 'RSA',
            key_size_bits: 2048,
            signature_algorithm: 'SHA256withRSA',
            sha256_fingerprint: '5A:7F:32:8B:91:04:88:C5:D1:29:EE:44:8A:1F:B3:9C:62:3A:49:10:2E:7C:39:AA:60:44:7E:11:98:C0:01:23',
            san_list: ['mail.gov.in', 'smtp.gov.in', 'mx.gov.in'],
            matches_domain: true,
            warnings: []
          }
        },
        findings: [],
        status: 'pass'
      },
      {
        protocol: 'SMTP',
        host: 'backup.gov.in',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 backup.gov.in ESMTP Postfix',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.2',
          cipher: {
            name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tls_version: 'TLS 1.2',
            key_exchange: 'ECDHE (secp256r1)',
            forward_secrecy: true,
            encryption: 'AES-128-GCM',
            mac: 'AEAD',
            bits: 128,
            is_weak: false,
            weak_reasons: []
          },
          certificate: {
            subject_cn: 'backup.gov.in',
            issuer_cn: 'National Informatics Centre CA',
            subject_dn: 'CN=backup.gov.in, O=NIC, C=IN',
            issuer_dn: 'CN=NIC Sub-CA 2024, O=NIC, C=IN',
            serial_number: '12:89:BC:DE:45:67',
            valid_from: '2024-11-01',
            valid_to: '2026-11-01',
            days_until_expiry: 50,
            is_expired: false,
            is_self_signed: false,
            public_key_algorithm: 'RSA',
            key_size_bits: 2048,
            signature_algorithm: 'SHA256withRSA',
            sha256_fingerprint: '12:89:BC:DE:45:67:88:A1:02:44:33:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
            san_list: ['backup.gov.in'],
            matches_domain: true,
            warnings: ['Certificate expires within 60 days']
          }
        },
        findings: [],
        status: 'warn'
      }
    ],
    forward_secrecy_supported: true,
    weak_ciphers_found: false,
    deprecated_tls_found: false,
    certificate_issues_found: false,
    prioritized_findings: [
      {
        title: 'Secondary MX Lacks TLSA / DANE Record',
        severity: 'MEDIUM',
        category: 'DNS / DANE',
        description: 'Zone DNSSEC is active but backup.gov.in lacks TLSA binding, leaving opportunistic STARTTLS vulnerable to downgrade on failover.',
        recommendation: 'Generate TLSA 3 1 1 record for _25._tcp.backup.gov.in signed by zone KSK.'
      }
    ]
  },
  ai_risk_score: {
    risk_score: 13,
    risk_level: 'LOW',
    confidence: 0.94,
    risk_factors: ['Secondary MX TLS 1.2 fallback', 'Expiring certificate on backup host (50 days)'],
    mitigation_priority: ['Renew backup.gov.in certificate', 'Enforce TLS 1.3 across all MX nodes']
  },
  anomaly_detection: {
    anomaly_detected: false,
    anomaly_score: -0.85,
    confidence: 0.91,
    detected_anomalies: [],
    suspicious_indicators: []
  },
  prioritized_findings: [
    {
      title: 'Secondary MX Lacks TLSA / DANE Record',
      severity: 'MEDIUM',
      category: 'DNS / DANE',
      description: 'backup.gov.in lacks TLSA publication on port 25, permitting STRIPTLS on fallback relay.',
      recommendation: 'Publish TLSA 3 1 1 record for backup.gov.in in DNSSEC signed zone.'
    },
    {
      title: 'Backup Node Certificate Expiring Soon (50 Days)',
      severity: 'LOW',
      category: 'Certificate',
      description: 'X.509 certificate for backup.gov.in expires within 50 days.',
      recommendation: 'Automate ACME / internal PKI renewal for all mail relay nodes.'
    }
  ]
};

export const mockDefenseNicIn: ScanResponse = {
  domain: 'defense.nic.in',
  score: 96,
  scanned_at: new Date().toISOString(),
  checks: [
    {
      name: 'SPF',
      status: 'pass',
      details: {
        record_type: 'TXT',
        record_host: '@',
        record_value: 'v=spf1 ip4:164.100.24.0/24 -all',
        lookups: 0,
        policy: 'strict (-all)',
        message: 'Hardened SPF record with zero nested DNS lookups and explicit CIDR allocation.'
      },
      recommendation: 'Optimal SPF posture maintained.'
    },
    {
      name: 'DKIM',
      status: 'pass',
      details: {
        selector: 'def2026',
        record_host: 'def2026._domainkey.defense.nic.in',
        record_value: 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIwOfARScc=',
        key_size: 256,
        status: 'active',
        message: 'Modern Ed25519 cryptographic curve DKIM signing active.'
      },
      recommendation: 'Maintain dual Ed25519/RSA-2048 signing for backward interop.'
    },
    {
      name: 'DMARC',
      status: 'pass',
      details: {
        record_host: '_dmarc.defense.nic.in',
        record_value: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:soc-dmarc@defense.nic.in; ruf=mailto:soc-forensics@defense.nic.in; aspf=s; adkim=s',
        policy: 'reject (100%)',
        enforcement: 'full',
        alignment: 'strict',
        message: 'Full reject enforcement with dual forensic routing.'
      },
      recommendation: 'Optimal DMARC defense active.'
    },
    {
      name: 'MTA-STS',
      status: 'pass',
      details: {
        record_host: '_mta-sts.defense.nic.in',
        record_value: 'v=STSv1; id=20260910T120000Z; mode=enforce; mx=milgw1.defense.nic.in; max_age=1209600',
        mode: 'enforce',
        max_age: '1209600s (14 days)',
        message: 'MTA-STS policy enforced with high max_age.'
      },
      recommendation: 'Policy fully compliant.'
    },
    {
      name: 'TLS-RPT',
      status: 'pass',
      details: {
        record_host: '_smtp._tls.defense.nic.in',
        record_value: 'v=TLSRPTv1; rua=mailto:tls-soc@defense.nic.in',
        message: 'Automated telemetry ingestion active.'
      },
      recommendation: 'Ingest into real-time SIEM.'
    },
    {
      name: 'DANE/TLSA',
      status: 'pass',
      details: {
        record_host: '_25._tcp.milgw1.defense.nic.in',
        record_value: '3 1 1 a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
        dnssec: 'enabled (NSEC3RSASHA1)',
        message: 'DNSSEC secured TLSA certificate pinning active on MX.'
      },
      recommendation: 'Maintain DANE rollover discipline prior to cert renewal.'
    }
  ],
  crypto_posture: {
    crypto_score: 96,
    grade: 'A+',
    protocols_audited: [
      {
        protocol: 'SMTP',
        host: 'milgw1.defense.nic.in',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 milgw1.defense.nic.in ESMTP Defense Shield v4.2',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.3',
          cipher: {
            name: 'TLS_CHACHA20_POLY1305_SHA256',
            tls_version: 'TLS 1.3',
            key_exchange: 'X25519 / ML-KEM-768 (PQC Hybrid)',
            forward_secrecy: true,
            encryption: 'CHACHA20-POLY1305',
            mac: 'AEAD',
            bits: 256,
            is_weak: false,
            weak_reasons: []
          },
          certificate: {
            subject_cn: 'milgw1.defense.nic.in',
            issuer_cn: 'Defense Security PKI Root CA',
            subject_dn: 'CN=milgw1.defense.nic.in, O=Ministry of Defence, C=IN',
            issuer_dn: 'CN=Defense Root CA, C=IN',
            serial_number: '9B:4C:11:AA:5E:20',
            valid_from: '2026-01-01',
            valid_to: '2028-01-01',
            days_until_expiry: 658,
            is_expired: false,
            is_self_signed: false,
            public_key_algorithm: 'ECC (Ed25519)',
            key_size_bits: 256,
            signature_algorithm: 'Ed25519',
            sha256_fingerprint: '9B:4C:11:AA:5E:20:CC:77:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0',
            san_list: ['milgw1.defense.nic.in', 'mail.defense.nic.in'],
            matches_domain: true,
            warnings: []
          }
        },
        findings: [],
        status: 'pass'
      }
    ],
    forward_secrecy_supported: true,
    weak_ciphers_found: false,
    deprecated_tls_found: false,
    certificate_issues_found: false,
    prioritized_findings: []
  },
  ai_risk_score: {
    risk_score: 4,
    risk_level: 'LOW',
    confidence: 0.98,
    risk_factors: [],
    mitigation_priority: ['Maintain active DNSSEC validation on outbound resolvers']
  },
  anomaly_detection: {
    anomaly_detected: false,
    anomaly_score: -0.95,
    confidence: 0.97,
    detected_anomalies: [],
    suspicious_indicators: []
  },
  prioritized_findings: []
};

export const mockGmailCom: ScanResponse = {
  domain: 'gmail.com',
  score: 93,
  scanned_at: new Date().toISOString(),
  checks: [
    {
      name: 'SPF',
      status: 'pass',
      details: {
        record_type: 'TXT',
        record_host: '@',
        record_value: 'v=spf1 redirect=_spf.google.com',
        lookups: 1,
        policy: 'redirect',
        message: 'SPF record delegates to centralized Google mail sender pools.'
      },
      recommendation: 'Standard Google SPF delegation.'
    },
    {
      name: 'DKIM',
      status: 'pass',
      details: {
        selector: '20230601',
        record_host: '20230601._domainkey.gmail.com',
        record_value: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',
        key_size: 2048,
        status: 'active',
        message: 'DKIM RSA-2048 signing fully operational.'
      },
      recommendation: 'Standard DKIM configuration.'
    },
    {
      name: 'DMARC',
      status: 'pass',
      details: {
        record_host: '_dmarc.gmail.com',
        record_value: 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com',
        policy: 'reject',
        enforcement: 'full',
        message: 'Strict reject policy enforced.'
      },
      recommendation: 'Policy fully compliant.'
    },
    {
      name: 'MTA-STS',
      status: 'pass',
      details: {
        record_host: '_mta-sts.gmail.com',
        record_value: 'v=STSv1; id=20190429T010101; mode=enforce; mx=*.google.com; max_age=86400',
        mode: 'enforce',
        max_age: '86400s',
        message: 'MTA-STS enforce mode prevents cleartext downgrade.'
      },
      recommendation: 'Increase max_age to >604800s for enterprise durability.'
    },
    {
      name: 'TLS-RPT',
      status: 'pass',
      details: {
        record_host: '_smtp._tls.gmail.com',
        record_value: 'v=TLSRPTv1; rua=mailto:smtp-tls-reporting@google.com',
        message: 'SMTP TLS failure reporting active.'
      },
      recommendation: 'Standard TLS-RPT configuration.'
    },
    {
      name: 'DANE/TLSA',
      status: 'warn',
      details: {
        record_host: '_25._tcp.gmail-smtp-in.l.google.com',
        record_value: 'no TLSA record',
        dnssec: 'not deployed on l.google.com zone',
        message: 'Google relies primarily on MTA-STS rather than DANE/TLSA.'
      },
      recommendation: 'Complement MTA-STS with DANE TLSA records on DNSSEC signed zones.'
    }
  ],
  crypto_posture: {
    crypto_score: 93,
    grade: 'A',
    protocols_audited: [
      {
        protocol: 'SMTP',
        host: 'gmail-smtp-in.l.google.com',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 mx.google.com ESMTP',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.3',
          cipher: {
            name: 'TLS_AES_256_GCM_SHA384',
            tls_version: 'TLS 1.3',
            key_exchange: 'X25519 (Hybrid Kyber ready)',
            forward_secrecy: true,
            encryption: 'AES-256-GCM',
            mac: 'AEAD',
            bits: 256,
            is_weak: false,
            weak_reasons: []
          },
          certificate: {
            subject_cn: 'mx.google.com',
            issuer_cn: 'GTS CA 1C3',
            subject_dn: 'CN=mx.google.com, O=Google Trust Services LLC, C=US',
            issuer_dn: 'CN=GTS CA 1C3, O=Google Trust Services LLC, C=US',
            serial_number: '3F:2B:99:A1:10:04',
            valid_from: '2026-08-01',
            valid_to: '2026-11-01',
            days_until_expiry: 68,
            is_expired: false,
            is_self_signed: false,
            public_key_algorithm: 'ECC',
            key_size_bits: 256,
            signature_algorithm: 'SHA256withECDSA',
            sha256_fingerprint: '3F:2B:99:A1:10:04:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78',
            san_list: ['mx.google.com', '*.google.com'],
            matches_domain: true,
            warnings: []
          }
        },
        findings: [],
        status: 'pass'
      }
    ],
    forward_secrecy_supported: true,
    weak_ciphers_found: false,
    deprecated_tls_found: false,
    certificate_issues_found: false,
    prioritized_findings: []
  },
  ai_risk_score: {
    risk_score: 7,
    risk_level: 'LOW',
    confidence: 0.95,
    risk_factors: ['Lack of DANE/TLSA records'],
    mitigation_priority: ['Publish DANE TLSA records on DNSSEC signed mail hosts']
  },
  anomaly_detection: {
    anomaly_detected: false,
    anomaly_score: -0.92,
    confidence: 0.94,
    detected_anomalies: [],
    suspicious_indicators: []
  },
  prioritized_findings: [
    {
      title: 'MTA-STS Policy Max Age Below 7 Days',
      severity: 'LOW',
      category: 'Protocol',
      description: 'max_age is set to 86400 (1 day), creating potential cache expiration windows during extended network disruption.',
      recommendation: 'Extend MTA-STS max_age parameter to at least 604800 (7 days).'
    }
  ]
};

export const mockLegacyBank: ScanResponse = {
  domain: 'legacy-bank-test.local',
  score: 32,
  scanned_at: new Date().toISOString(),
  checks: [
    {
      name: 'SPF',
      status: 'warn',
      details: {
        record_type: 'TXT',
        record_host: '@',
        record_value: 'v=spf1 +all',
        lookups: 0,
        policy: 'permissive (+all)',
        message: 'Critical SPF misconfiguration: "+all" permits ANY host in the world to spoof mail.'
      },
      recommendation: 'Change "+all" to "-all" immediately and define authorized relay IPs.'
    },
    {
      name: 'DKIM',
      status: 'fail',
      details: {
        selector: 'default',
        record_host: 'default._domainkey.legacy-bank-test.local',
        record_value: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3...',
        key_size: 1024,
        status: 'insecure',
        message: 'DKIM key uses insecure 1024-bit RSA key length factorable with commodity compute.'
      },
      recommendation: 'Re-generate DKIM keys with minimum 2048-bit RSA or Ed25519.'
    },
    {
      name: 'DMARC',
      status: 'fail',
      details: {
        record_host: '_dmarc.legacy-bank-test.local',
        record_value: 'v=DMARC1; p=none',
        policy: 'none (monitoring only)',
        enforcement: 'none',
        message: 'DMARC policy is set to "p=none", providing ZERO spoofing protection.'
      },
      recommendation: 'Transition policy from "p=none" to "p=quarantine" and then "p=reject".'
    },
    {
      name: 'MTA-STS',
      status: 'fail',
      details: {
        record_host: '_mta-sts.legacy-bank-test.local',
        record_value: 'NXDOMAIN',
        mode: 'missing',
        message: 'No MTA-STS DNS record or HTTPS policy daemon configured.'
      },
      recommendation: 'Deploy MTA-STS policy to prevent active MiTM cleartext downgrade attacks.'
    },
    {
      name: 'TLS-RPT',
      status: 'fail',
      details: {
        record_host: '_smtp._tls.legacy-bank-test.local',
        record_value: 'NXDOMAIN',
        message: 'No TLS reporting configured. Handshake failures will go undetected.'
      },
      recommendation: 'Publish _smtp._tls TXT record for automated failure telemetry.'
    },
    {
      name: 'DANE/TLSA',
      status: 'fail',
      details: {
        record_host: '_25._tcp.mail.legacy-bank-test.local',
        record_value: 'NXDOMAIN',
        dnssec: 'disabled',
        message: 'Zone lacks DNSSEC and TLSA verification.'
      },
      recommendation: 'Sign zone with DNSSEC and publish TLSA record for port 25.'
    }
  ],
  crypto_posture: {
    crypto_score: 32,
    grade: 'F',
    protocols_audited: [
      {
        protocol: 'SMTP',
        host: 'mail.legacy-bank-test.local',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 mail.legacy-bank-test.local ESMTP Sendmail 8.14.4',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.0',
          cipher: {
            name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            tls_version: 'TLS 1.0',
            key_exchange: 'RSA (No Forward Secrecy)',
            forward_secrecy: false,
            encryption: '3DES-EDE-CBC',
            mac: 'HMAC-SHA1',
            bits: 112,
            is_weak: true,
            weak_reasons: [
              'Deprecated TLS 1.0 protocol (RFC 8996)',
              'Sweet32 vulnerable 64-bit block cipher (3DES)',
              'No Forward Secrecy (PFS): passive recorded traffic can be retroactively decrypted',
              'Deprecated SHA-1 hashing algorithm'
            ]
          },
          certificate: {
            subject_cn: 'mail.legacy-bank-test.local',
            issuer_cn: 'Self-Signed Untrusted CA',
            subject_dn: 'CN=mail.legacy-bank-test.local, O=Legacy Bank, C=IN',
            issuer_dn: 'CN=mail.legacy-bank-test.local, O=Legacy Bank, C=IN',
            serial_number: '00:01:FE:23:45',
            valid_from: '2020-01-01',
            valid_to: '2022-01-01',
            days_until_expiry: -1715,
            is_expired: true,
            is_self_signed: true,
            public_key_algorithm: 'RSA',
            key_size_bits: 1024,
            signature_algorithm: 'SHA1withRSA',
            sha256_fingerprint: '00:01:FE:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB',
            san_list: ['mail.legacy-bank-test.local'],
            matches_domain: false,
            warnings: [
              'Certificate is EXPIRED for over 4 years',
              'Untrusted self-signed certificate authority',
              'Weak 1024-bit RSA key length',
              'Obsolete SHA-1 signature algorithm'
            ]
          }
        },
        findings: [
          {
            title: 'Critical Sweet32 Block Cipher (3DES-CBC)',
            severity: 'CRITICAL',
            category: 'Cipher',
            description: '3DES block cipher is susceptible to collision plaintext recovery attacks (CVE-2016-2183).',
            recommendation: 'Disable 3DES and all CBC mode suites immediately.'
          },
          {
            title: 'Deprecated TLS 1.0 Protocol Negotiated',
            severity: 'CRITICAL',
            category: 'TLS',
            description: 'TLS 1.0 was deprecated by RFC 8996 in 2021 due to BEAST and POODLE downgrade vectors.',
            recommendation: 'Enforce minimum TLS 1.2, preferably TLS 1.3.'
          },
          {
            title: 'Self-Signed and Expired Certificate in Production',
            severity: 'CRITICAL',
            category: 'Certificate',
            description: 'X.509 certificate expired over 4 years ago and is self-signed, causing mail relays to reject or fall back to plaintext.',
            recommendation: 'Replace with valid CA certificate issued by a trusted public root.'
          }
        ],
        status: 'fail'
      }
    ],
    forward_secrecy_supported: false,
    weak_ciphers_found: true,
    deprecated_tls_found: true,
    certificate_issues_found: true,
    prioritized_findings: [
      {
        title: 'Sweet32 Vulnerable 3DES-EDE-CBC Cipher',
        severity: 'CRITICAL',
        category: 'Cipher',
        description: 'Legacy 3DES cipher suite active on port 25 STARTTLS negotiation.',
        recommendation: 'Disable 3DES and enforce AES-GCM or ChaCha20 suites.'
      },
      {
        title: 'Expired & Self-Signed X.509 Certificate',
        severity: 'CRITICAL',
        category: 'Certificate',
        description: 'Production mail gateway using expired self-signed certificate with 1024-bit RSA key.',
        recommendation: 'Issue compliant certificate from trusted PKI with RSA >= 2048 or ECC >= 256.'
      },
      {
        title: 'Deprecated TLS 1.0 Active (No Forward Secrecy)',
        severity: 'CRITICAL',
        category: 'TLS',
        description: 'Server permits TLS 1.0 without ephemeral Diffie-Hellman key exchange.',
        recommendation: 'Set smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1.'
      },
      {
        title: 'Permissive SPF Policy (+all)',
        severity: 'HIGH',
        category: 'DNS',
        description: 'SPF policy ends in "+all", permitting malicious actors to spoof sender identity.',
        recommendation: 'Update TXT record to include authorized relays and end in "-all".'
      },
      {
        title: 'DMARC Policy Set to None (p=none)',
        severity: 'HIGH',
        category: 'DNS',
        description: 'No enforcement against forged emails received by downstream mail servers.',
        recommendation: 'Escalate policy to p=reject.'
      }
    ]
  },
  ai_risk_score: {
    risk_score: 94,
    risk_level: 'CRITICAL',
    confidence: 0.99,
    risk_factors: [
      'Zero Forward Secrecy: recorded encrypted sessions can be decrypted retroactively',
      'Sweet32 64-bit block collision vulnerability (CVE-2016-2183)',
      'Expired and self-signed certificate invalidates identity verification',
      'No spoofing defense: SPF +all and DMARC p=none permit trivial impersonation'
    ],
    mitigation_priority: [
      'Enforce TLS 1.3 / TLS 1.2 with ECDHE PFS suites',
      'Replace expired self-signed certificate with trusted CA certificate',
      'Fix SPF to "-all" and escalate DMARC to "p=reject"'
    ]
  },
  anomaly_detection: {
    anomaly_detected: true,
    anomaly_score: 0.88,
    confidence: 0.96,
    detected_anomalies: [
      'Extreme protocol obsolescence (TLS 1.0)',
      'Legacy 64-bit block cipher in production gateway',
      'Permissive SPF wildcards detected'
    ],
    suspicious_indicators: [
      'Potential STRIPTLS cleartext fallback exposure',
      'High likelihood of nation-state or adversary spoofing exploitation'
    ]
  },
  prioritized_findings: [
    {
      title: 'Sweet32 Vulnerable 3DES-EDE-CBC Cipher',
      severity: 'CRITICAL',
      category: 'Cipher',
      description: 'Legacy 3DES cipher suite active on port 25 STARTTLS negotiation.',
      recommendation: 'Disable 3DES and enforce AES-GCM or ChaCha20 suites.'
    },
    {
      title: 'Expired & Self-Signed X.509 Certificate',
      severity: 'CRITICAL',
      category: 'Certificate',
      description: 'Production mail gateway using expired self-signed certificate with 1024-bit RSA key.',
      recommendation: 'Issue compliant certificate from trusted PKI with RSA >= 2048 or ECC >= 256.'
    },
    {
      title: 'Deprecated TLS 1.0 Active (No Forward Secrecy)',
      severity: 'CRITICAL',
      category: 'TLS',
      description: 'Server permits TLS 1.0 without ephemeral Diffie-Hellman key exchange.',
      recommendation: 'Set smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1.'
    },
    {
      title: 'Permissive SPF Policy (+all)',
      severity: 'HIGH',
      category: 'DNS',
      description: 'SPF policy ends in "+all", permitting malicious actors to spoof sender identity.',
      recommendation: 'Update TXT record to include authorized relays and end in "-all".'
    },
    {
      title: 'DMARC Policy Set to None (p=none)',
      severity: 'HIGH',
      category: 'DNS',
      description: 'No enforcement against forged emails received by downstream mail servers.',
      recommendation: 'Escalate policy to p=reject.'
    }
  ]
};

export const mockPcapAnalysis: PcapAnalysisResponse = {
  filename: 'mail_traffic_forensics_sample.pcap',
  total_packets: 1428,
  total_tcp_streams: 4,
  identified_protocols: ['SMTP (Port 25)', 'STARTTLS', 'TLS 1.3', 'IMAP (Port 993)'],
  processed_at: new Date().toISOString(),
  streams: [
    {
      stream_id: 0,
      client_ip: '198.51.100.42',
      client_port: 48922,
      server_ip: '164.100.24.10',
      server_port: 25,
      protocol: 'SMTP / STARTTLS',
      packet_count: 312,
      client_bytes: 14208,
      server_bytes: 84210,
      starttls_detected: true,
      tls_handshake_detected: true,
      tls_version: 'TLS 1.3',
      cipher_suite: 'TLS_AES_256_GCM_SHA384',
      certificate_extracted: true,
      certificate_info: {
        subject_cn: 'mailgw1.defense.nic.in',
        issuer_cn: 'Defense Security Root CA',
        subject_dn: 'CN=mailgw1.defense.nic.in, O=Ministry of Defence, C=IN',
        issuer_dn: 'CN=Defense Root CA, C=IN',
        serial_number: '9B:4C:11:AA:5E:20',
        valid_from: '2026-01-01',
        valid_to: '2028-01-01',
        days_until_expiry: 658,
        is_expired: false,
        is_self_signed: false,
        public_key_algorithm: 'Ed25519',
        key_size_bits: 256,
        signature_algorithm: 'Ed25519',
        sha256_fingerprint: '9B:4C:11:AA:5E:20:CC:77:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0',
        san_list: ['mailgw1.defense.nic.in'],
        matches_domain: true,
        warnings: []
      },
      findings: [
        {
          title: 'Protected STARTTLS Negotiation (TLS 1.3 AEAD)',
          severity: 'INFO',
          category: 'PCAP / Forensic',
          description: 'Stream negotiated modern TLS 1.3 with ChaCha20/AES-GCM. No protocol tampering detected.'
        }
      ]
    },
    {
      stream_id: 1,
      client_ip: '203.0.113.88',
      client_port: 52104,
      server_ip: '192.0.2.14',
      server_port: 25,
      protocol: 'SMTP (STRIPTLS MitM)',
      packet_count: 88,
      client_bytes: 4210,
      server_bytes: 5120,
      starttls_detected: false,
      tls_handshake_detected: false,
      tls_version: null,
      cipher_suite: null,
      certificate_extracted: false,
      certificate_info: null,
      findings: [
        {
          title: 'ACTIVE STRIPTLS DOWNGRADE ATTACK DETECTED',
          severity: 'CRITICAL',
          category: 'Network Forensic Anomaly',
          description: 'Server advertised "250-STARTTLS" in original banner packet, but intermediate router stripped the keyword before client delivery. Email credentials and message headers transmitted in CLEARTEXT.',
          recommendation: 'Enforce MTA-STS and DANE TLSA to instruct sending MTAs to refuse cleartext transmission upon STARTTLS stripping.'
        }
      ]
    },
    {
      stream_id: 2,
      client_ip: '198.51.100.15',
      client_port: 39120,
      server_ip: '164.100.0.25',
      server_port: 993,
      protocol: 'IMAPS (Direct TLS)',
      packet_count: 480,
      client_bytes: 28400,
      server_bytes: 142050,
      starttls_detected: false,
      tls_handshake_detected: true,
      tls_version: 'TLS 1.3',
      cipher_suite: 'TLS_CHACHA20_POLY1305_SHA256',
      certificate_extracted: true,
      findings: []
    },
    {
      stream_id: 3,
      client_ip: '198.51.100.77',
      client_port: 44102,
      server_ip: '192.0.2.99',
      server_port: 25,
      protocol: 'SMTP (Weak TLS 1.0)',
      packet_count: 548,
      client_bytes: 24100,
      server_bytes: 88900,
      starttls_detected: true,
      tls_handshake_detected: true,
      tls_version: 'TLS 1.0',
      cipher_suite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      certificate_extracted: true,
      findings: [
        {
          title: 'Passive Capture of Deprecated 3DES/TLS 1.0 Session',
          severity: 'HIGH',
          category: 'Cipher Forensic',
          description: 'Captured TCP stream utilizes deprecated Sweet32 CBC cipher without forward secrecy.',
          recommendation: 'Upgrade remote mail transfer agent cipher policy.'
        }
      ]
    }
  ],
  summary_findings: [
    {
      title: 'Active STRIPTLS Downgrade Attack in Stream #1',
      severity: 'CRITICAL',
      category: 'Forensic Anomaly',
      description: 'Network-level inspection revealed STARTTLS stripping between client 203.0.113.88 and server 192.0.2.14.',
      recommendation: 'Deploy MTA-STS enforce policy to prevent unencrypted mail transfer.'
    },
    {
      title: 'Legacy TLS 1.0 & Sweet32 Session in Stream #3',
      severity: 'HIGH',
      category: 'Crypto Posture',
      description: 'Cleartext/legacy encryption identified on port 25 exchange.',
      recommendation: 'Disallow TLS versions < 1.2 across all ingress gateways.'
    }
  ]
};

export const mockRbiOrgIn: ScanResponse = {
  domain: 'rbi.org.in',
  score: 91,
  scanned_at: new Date().toISOString(),
  checks: [
    {
      name: 'SPF',
      status: 'pass',
      details: {
        record_type: 'TXT',
        record_host: '@',
        record_value: 'v=spf1 ip4:164.100.12.0/24 ip4:115.112.22.0/24 -all',
        lookups: 0,
        policy: 'strict (-all)',
        message: 'Strict SPF policy enforced for Reserve Bank of India gateway IPs.'
      },
      recommendation: 'Maintain strict IP prefix list.'
    },
    {
      name: 'DKIM',
      status: 'pass',
      details: {
        selector: 'rbi2025',
        record_host: 'rbi2025._domainkey.rbi.org.in',
        record_value: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',
        key_size: 2048,
        status: 'active',
        message: 'DKIM RSA-2048 signing active and aligned.'
      },
      recommendation: 'Scheduled rotation recommended bi-annually.'
    },
    {
      name: 'DMARC',
      status: 'pass',
      details: {
        record_host: '_dmarc.rbi.org.in',
        record_value: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@rbi.org.in; ruf=mailto:forensics@rbi.org.in; aspf=s; adkim=s',
        policy: 'reject',
        enforcement: 'full',
        message: 'DMARC strict reject policy active with forensic and aggregate feeds.'
      },
      recommendation: 'Maintain zero-tolerance reject policy.'
    },
    {
      name: 'MTA-STS',
      status: 'pass',
      details: {
        record_host: '_mta-sts.rbi.org.in',
        record_value: 'v=STSv1; id=20260901; mode=enforce; mx=mailgw1.rbi.org.in; max_age=1209600',
        mode: 'enforce',
        max_age: '1209600s',
        message: 'MTA-STS enforce mode prevents cleartext downgrade.'
      },
      recommendation: 'Policy fully compliant.'
    },
    {
      name: 'TLS-RPT',
      status: 'pass',
      details: {
        record_host: '_smtp._tls.rbi.org.in',
        record_value: 'v=TLSRPTv1; rua=mailto:tlsrpt@rbi.org.in',
        message: 'SMTP TLS reporting accepting failure reports.'
      },
      recommendation: 'Monitor automated TLS reports.'
    },
    {
      name: 'DANE/TLSA',
      status: 'pass',
      details: {
        record_host: '_25._tcp.mailgw1.rbi.org.in',
        record_value: '3 1 1 7A88BC21490D3365B299FE10145ACC346789120145903465B78899AACDEF1234',
        dnssec: 'enabled',
        message: 'DANE TLSA certificate binding verified with DNSSEC chain of trust.'
      },
      recommendation: 'Coordinate TLSA rollover with certificate renewals.'
    }
  ],
  crypto_posture: {
    crypto_score: 91,
    grade: 'A',
    protocols_audited: [
      {
        protocol: 'SMTP',
        host: 'mailgw1.rbi.org.in',
        port: 25,
        service_type: 'STARTTLS',
        banner: '220 mailgw1.rbi.org.in ESMTP Banking Core Shield',
        starttls_advertised: true,
        starttls_negotiated: true,
        tls_handshake: {
          success: true,
          negotiated_version: 'TLS 1.3',
          cipher: {
            name: 'TLS_AES_256_GCM_SHA384',
            tls_version: 'TLS 1.3',
            key_exchange: 'ECDHE (X25519)',
            forward_secrecy: true,
            encryption: 'AES-256-GCM',
            mac: 'AEAD',
            bits: 256,
            is_weak: false,
            weak_reasons: []
          },
          certificate: {
            subject_cn: 'mailgw1.rbi.org.in',
            issuer_cn: 'Reserve Bank Public Key Authority',
            subject_dn: 'CN=mailgw1.rbi.org.in, O=Reserve Bank of India, C=IN',
            issuer_dn: 'CN=RBI Root CA, C=IN',
            serial_number: '7A:88:BC:21:49:0D',
            valid_from: '2025-06-01',
            valid_to: '2027-06-01',
            days_until_expiry: 627,
            is_expired: false,
            is_self_signed: false,
            public_key_algorithm: 'ECC',
            key_size_bits: 256,
            signature_algorithm: 'SHA384withECDSA',
            sha256_fingerprint: '7A:88:BC:21:49:0D:33:65:B2:99:FE:10:14:5A:CC:34:67:89:12:01:45:90:34:65:B7:88:99:AA:CD:EF:12:34',
            san_list: ['mailgw1.rbi.org.in', 'mail.rbi.org.in'],
            matches_domain: true,
            warnings: []
          }
        },
        findings: [],
        status: 'pass'
      }
    ],
    forward_secrecy_supported: true,
    weak_ciphers_found: false,
    deprecated_tls_found: false,
    certificate_issues_found: false,
    prioritized_findings: []
  },
  ai_risk_score: {
    risk_score: 9,
    risk_level: 'LOW',
    confidence: 0.96,
    risk_factors: ['High-value financial target posture'],
    mitigation_priority: ['Transition to hybrid PQC KEM (ML-KEM-768) ahead of 2027 mandates']
  },
  anomaly_detection: {
    anomaly_detected: false,
    anomaly_score: -0.9,
    confidence: 0.95,
    detected_anomalies: [],
    suspicious_indicators: []
  },
  prioritized_findings: [
    {
      title: 'PQC Lattice Hybrid Transition Advised',
      severity: 'LOW',
      category: 'PQC / Crypto',
      description: 'While classical TLS 1.3 is securely deployed, high-value financial routing requires evaluation of NIST FIPS 203 (ML-KEM) hybrid key exchange.',
      recommendation: 'Pilot X25519MLKEM768 hybrid key encapsulation for inter-bank gateway relays.'
    }
  ]
};

export function getMockScanData(domain: string): ScanResponse {
  const cleanDomain = domain.toLowerCase().trim();
  if (cleanDomain.includes('defense') || cleanDomain.includes('nic.in')) {
    return { ...mockDefenseNicIn, domain: cleanDomain, scanned_at: new Date().toISOString() };
  }
  if (cleanDomain.includes('rbi')) {
    return { ...mockRbiOrgIn, domain: cleanDomain, scanned_at: new Date().toISOString() };
  }
  if (cleanDomain.includes('gmail') || cleanDomain.includes('google')) {
    return { ...mockGmailCom, domain: cleanDomain, scanned_at: new Date().toISOString() };
  }
  if (cleanDomain.includes('legacy') || cleanDomain.includes('insecure') || cleanDomain.includes('bank') || cleanDomain.includes('test')) {
    return { ...mockLegacyBank, domain: cleanDomain, scanned_at: new Date().toISOString() };
  }
  return { ...mockGovIn, domain: cleanDomain, scanned_at: new Date().toISOString() };
}

export const mockScanResponse = mockGovIn;
