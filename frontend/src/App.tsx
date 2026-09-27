import axios from 'axios';
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Download,
  FileJson,
  RefreshCw,
  Shield,
  Layers,
  ChevronRight,
  Sparkles,
  Info
} from 'lucide-react';
import {
  ScanResponse,
  ScanState,
  FindingSeverity,
  AppSettings,
  PcapAnalysisResponse
} from './types';
import {
  scanDomain,
  getBackendHealth,
  fetchPdfReport,
  fetchHtmlReport,
  scanPcap,
  setApiBaseUrl
} from './api';

// Component imports
import { Sidebar, NavItemKey } from './components/Sidebar';
import { HeaderBar } from './components/HeaderBar';
import { CryptoSessionsCard } from './components/CryptoSessionsCard';
import { KeyProtocolCard, KeyMode } from './components/KeyProtocolCard';
import { ThreatCenter } from './components/ThreatCenter';
import { ActiveReportCard } from './components/ActiveReportCard';
import { AuditVolumeCard } from './components/AuditVolumeCard';
import { EmailCredentialsCard } from './components/EmailCredentialsCard';
import { ChallengeRouteCard } from './components/ChallengeRouteCard';
import { ActivityTrendCard } from './components/ActivityTrendCard';
import { DockedTerminal, TerminalLog } from './components/DockedTerminal';
import { SecurityReportModal } from './components/SecurityReportModal';
import { CertificateInspectorModal } from './components/CertificateInspectorModal';
import { SettingsModal } from './components/SettingsModal';
import { PcapForensicsView } from './components/PcapForensicsView';
import { Toast } from './components/Toast';
import { Footer } from './components/Footer';

export function App() {
  const [activeTab, setActiveTab] = useState<NavItemKey>('overview');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('gmail.com');
  const [pcapData, setPcapData] = useState<PcapAnalysisResponse | null>(null);
  const [isPcapLoading, setIsPcapLoading] = useState(false);
  const [currentDomain, setCurrentDomain] = useState('gmail.com');
  const [scanState, setScanState] = useState<ScanState>('IDLE');
  
  // Real scan response from backend (null if initial or error)
  const [scanData, setScanData] = useState<ScanResponse | null>(null);
  const [score, setScore] = useState<number | null>(null);
  
  // Modals
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isCertModalOpen, setIsCertModalOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Terminal Height & Drag Resizing State (48px collapsed to 550px max)
  const [terminalHeight, setTerminalHeight] = useState(220);
  const isResizingRef = useRef(false);

  // Terminal Logs state (clean, real telemetry, no fake tick timers)
  const [logs, setLogs] = useState<TerminalLog[]>([
    {
      id: 'init-1',
      timestamp: new Date().toTimeString().split(' ')[0],
      tag: 'SYSTEM',
      message: 'Aegiscripta Enterprise SOC Engine initialized.',
    }
  ]);

  // Global Settings with persistence
  const [settings, setSettings] = useState<AppSettings>(() => {
    const saved = localStorage.getItem('aegis_console_settings');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // fallback
      }
    }
    return {
      theme: 'dark',
      density: 'normal',
      aiDetail: 'verbose',
      apiBaseUrl: 'http://localhost:8000'
    };
  });

  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [toastType, setToastType] = useState<'amber' | 'rose' | 'emerald' | 'cyan'>('amber');
  const [isPinging, setIsPinging] = useState(false);

  // Append log entry helper
  const addLog = useCallback((tag: TerminalLog['tag'], message: string, hash?: string) => {
    const now = new Date();
    const timeStr = `${now.toTimeString().split(' ')[0]}.${String(now.getMilliseconds()).padStart(3, '0')}`;
    setLogs((prev) => [
      ...prev.slice(-200),
      {
        id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        timestamp: timeStr,
        tag,
        message,
        hash
      }
    ]);
  }, []);

  // Sync theme to root element on mount and update
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', settings.theme);
    if (settings.theme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  }, [settings.theme]);

  // Execute a real domain audit through the configured FastAPI endpoint
  const handleTriggerScan = useCallback(async (targetDomain: string) => {
    const target = targetDomain.trim();
    if (!target) return;

    setCurrentDomain(target);
    setSearchQuery(target);
    setScanState('SCANNING');

    addLog('DNS', `Querying authoritative DNS zone (MX, SPF, DMARC, MTA-STS, TLSA) for ${target}...`);

    try {
      const res = await scanDomain(target);
      const data = res.data;
      setScanData(data);
      setScore(data.score);
      setScanState('SUCCESS');
      setBackendOnline(true);
      setToastMessage(null);

      // Stream only what the response actually reported into the terminal
      const handshake = data.crypto_posture?.protocols_audited?.[0]?.tls_handshake;
      if (handshake?.success && handshake.cipher?.name) {
        const negotiated = handshake.negotiated_version || handshake.tls_version || 'unreported TLS version';
        addLog(
          'TLS',
          `Negotiated ${negotiated} with ${handshake.cipher.name}${handshake.cipher.forward_secrecy ? ' (forward secrecy reported)' : ' (no forward secrecy reported)'}.`
        );
      } else if (handshake?.success === false) {
        addLog('TLS', `TLS handshake failed: ${handshake.error_message || 'no error message reported'}.`);
      } else {
        addLog('TLS', 'No TLS handshake telemetry was returned for this scan.');
      }

      const pqcEvaluated = data.crypto_posture?.pqc_indicators_evaluated === true;
      addLog(
        'PQC',
        pqcEvaluated
          ? 'PQC indicators were evaluated by the backend for this scan.'
          : 'PQC indicators were not evaluated by the backend for this scan — no compliance claim available.'
      );
      addLog('SUCCESS', `Audit completed for ${target}. Deterministic Posture Score: ${data.score}/100.`);
    } catch (err: unknown) {
      setScanState('ERROR');

      if (axios.isAxiosError(err)) {
        const status = err.response?.status;
        const diagnostic = err.response?.data?.detail ?? err.message ?? 'Unknown scan error';
        console.error('[AegisCrypta] Scan request failed', { domain: target, status, diagnostic });
        setBackendOnline(Boolean(err.response));
      } else {
        const diagnostic = err instanceof Error ? err.message : 'Unknown scan error';
        console.error('[AegisCrypta] Scan failed', { domain: target, diagnostic });
        setBackendOnline(false);
      }

      addLog('ERROR', `Scan failed for ${target}. Diagnostic details were written to the terminal logs.`);
      setToastMessage('Scan failed. Check terminal logs for diagnostic details.');
    }
  }, [addLog]);

  // Initial Health Probe & First Scan on Mount
  const handleCheckHealth = useCallback(async () => {
    setCheckingHealth(true);
    const health = await getBackendHealth();
    setBackendOnline(health.online);
    setCheckingHealth(false);

    if (health.online) {
      addLog('SYSTEM', `Daemon connected: GET ${health.endpoint} → ${health.detail}. Live probing ready.`);
      // Auto-run real scan for initial domain
      handleTriggerScan('gmail.com');
    } else {
      addLog('ERROR', `Daemon unreachable: GET ${health.endpoint} → ${health.detail}.`);
    }
  }, [addLog, handleTriggerScan]);

  useEffect(() => {
    handleCheckHealth();
  }, [handleCheckHealth]);

  // Console settings update handler with persistence
  const handleUpdateSettings = (newSettings: Partial<AppSettings>) => {
    if (newSettings.apiBaseUrl) {
      setApiBaseUrl(newSettings.apiBaseUrl);
    }
    setSettings((prev) => {
      const updated = { ...prev, ...newSettings };
      try {
        localStorage.setItem('aegis_console_settings', JSON.stringify(updated));
      } catch (err) {
        console.warn('Failed to persist settings', err);
      }
      return updated;
    });
  };

  const handleTestPing = async () => {
    setIsPinging(true);
    try {
      const health = await getBackendHealth();
      setBackendOnline(health.online);
      setToastType(health.online ? 'emerald' : 'rose');
      setToastMessage(`GET ${health.endpoint} → ${health.detail}`);
      addLog(
        health.online ? 'SUCCESS' : 'ERROR',
        `${health.online ? 'Endpoint probe OK' : 'Endpoint probe failed'}: GET ${health.endpoint} → ${health.detail}.`
      );
    } finally {
      setIsPinging(false);
    }
  };

  // Sidebar "Status" button: always performs a fresh live health probe and
  // reports the configured endpoint plus the actual response.
  const handleStatusPing = useCallback(async () => {
    setIsPinging(true);
    try {
      const health = await getBackendHealth();
      setBackendOnline(health.online);
      setToastType(health.online ? 'emerald' : 'rose');
      setToastMessage(`GET ${health.endpoint} → ${health.detail}`);
      addLog(
        health.online ? 'SUCCESS' : 'ERROR',
        `Status check: GET ${health.endpoint} → ${health.detail}.`
      );
    } finally {
      setIsPinging(false);
    }
  }, [addLog]);

  // Draggable Mouse Resize for Docked Terminal (Limits: 48px to 550px)
  const startResizing = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    isResizingRef.current = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';

    const handleMouseMove = (moveEvent: MouseEvent) => {
      if (!isResizingRef.current) return;
      const newHeight = window.innerHeight - moveEvent.clientY;
      if (newHeight >= 48 && newHeight <= 550) {
        setTerminalHeight(newHeight);
      }
    };

    const handleMouseUp = () => {
      isResizingRef.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  }, []);

  // CLI Command Interpreter
  const handleExecuteCommand = (rawCmd: string) => {
    const parts = rawCmd.split(' ');
    const cmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(' ').trim();

    addLog('INFO', `aegis> ${rawCmd}`);

    switch (cmd) {
      case 'help':
        addLog('INFO', 'Available Aegiscripta CLI commands:');
        addLog('INFO', '  help              - List all available commands');
        addLog('INFO', '  status            - Print current mesh posture & system score');
        addLog('INFO', '  verify            - Run cryptographic certificate & key verification');
        addLog('PQC',  '  pqc               - Audit NIST FIPS-203 / ML-KEM quantum readiness');
        addLog('TLS',  '  scan <domain>     - Initiate real-time cryptographic posture scan');
        addLog('AUTH', '  nodes             - Inspect active identity mesh nodes');
        addLog('INFO', '  report            - Trigger official Security Report synthesis');
        addLog('INFO', '  clear             - Clear terminal display buffer');
        break;

      case 'status':
        if (backendOnline && score !== null) {
          addLog('SUCCESS', `Target Domain: ${currentDomain} | Posture Score: ${score}/100`);
          addLog('INFO', `Endpoint: ${settings.apiBaseUrl} (ONLINE) | Checks: ${scanData?.checks?.length ?? 0} | Protocols audited: ${scanData?.crypto_posture?.protocols_audited?.length ?? 0}`);
        } else if (backendOnline) {
          addLog('INFO', `Endpoint: ${settings.apiBaseUrl} (ONLINE) | No posture score available yet.`);
        } else {
          addLog('ERROR', `Daemon is currently DISCONNECTED at ${settings.apiBaseUrl}.`);
        }
        break;

      case 'verify': {
        addLog('AUTH', `Verifying public key chain for ${currentDomain}...`);
        const cert = scanData?.crypto_posture?.protocols_audited?.[0]?.tls_handshake?.certificate;
        if (cert) {
          addLog('AUTH', `✓ Subject: ${cert.subject_cn || cert.subject_dn}`);
          addLog('AUTH', `✓ Fingerprint SHA-256: ${cert.sha256_fingerprint || 'not reported'}`);
          addLog('AUTH', `✓ Chain status: ${cert.chain_valid === true ? 'validated' : cert.chain_valid === false ? 'UNTRUSTED' : 'not reported'}`);
        } else {
          addLog('ERROR', `No certificate telemetry available for ${currentDomain}. Run a scan first.`);
        }
        break;
      }

      case 'pqc':
        addLog('PQC', '=== NIST POST-QUANTUM CRYPTOGRAPHY STATUS ===');
        if (scanData?.crypto_posture?.pqc_indicators_evaluated === true) {
          addLog('PQC', 'PQC indicators were evaluated by the backend for the latest scan.');
          addLog('PQC', 'Review the AI forensic report for the evaluated key-exchange posture.');
        } else {
          addLog('PQC', 'PQC indicators were not evaluated by the backend for the latest scan.');
          addLog('PQC', 'No compliance claim is available until the evaluator returns data.');
        }
        break;

      case 'scan':
        const target = arg || currentDomain;
        handleTriggerScan(target);
        break;

      case 'nodes': {
        addLog('AUTH', 'Credential nodes reported by the latest scan:');
        const nodeCert = scanData?.crypto_posture?.protocols_audited?.[0]?.tls_handshake?.certificate;
        const dkimCheck = scanData?.checks?.find((c) => c.name.toLowerCase().includes('dkim'));
        if (nodeCert) {
          addLog('AUTH', `  [CERT] ${nodeCert.subject_cn || nodeCert.subject_dn} — chain ${nodeCert.chain_valid === true ? 'validated' : nodeCert.chain_valid === false ? 'UNTRUSTED' : 'not reported'}`);
        } else {
          addLog('AUTH', '  [CERT] No certificate telemetry in the latest scan response.');
        }
        if (dkimCheck) {
          addLog('AUTH', `  [DKIM] ${dkimCheck.name} — status ${dkimCheck.status.toUpperCase()}`);
        } else {
          addLog('AUTH', '  [DKIM] No DKIM check in the latest scan response.');
        }
        break;
      }

      case 'report':
        setIsReportModalOpen(true);
        break;

      case 'clear':
        setLogs([]);
        break;

      default:
        addLog('ERROR', `Unknown command: '${cmd}'. Type 'help' for available commands.`);
        break;
    }
  };

  // Report Export
  const handleExportJson = () => {
    if (!scanData) {
      setToastType('amber');
      setToastMessage('No scan response available to export yet. Run an audit first.');
      addLog('ERROR', 'JSON export skipped: no scan response in state.');
      return;
    }
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Aegiscripta_Security_Report_${currentDomain.replace(/\./g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addLog('SUCCESS', `Exported raw audit JSON for ${currentDomain}.`);
  };

  const handleExportHtml = async () => {
    addLog('INFO', `Generating official HTML forensic dossier for ${currentDomain}...`);
    try {
      const html = await fetchHtmlReport(currentDomain);
      if (html && html.length > 0) {
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Aegiscripta_Security_Report_${currentDomain.replace(/\./g, '_')}.html`;
        a.click();
        URL.revokeObjectURL(url);
        addLog('SUCCESS', `Official HTML forensic dossier downloaded.`);
      }
    } catch (err: unknown) {
      const diagnostic = err instanceof Error ? err.message : 'Unknown HTML report error';
      console.error('[AegisCrypta] Failed to generate HTML report', { domain: currentDomain, diagnostic });
      addLog('ERROR', 'Failed to generate HTML report. Check terminal logs.');
      setToastMessage('Failed to generate HTML report. Check terminal logs.');
    }
  };

  const handleExportPdf = async () => {
    addLog('INFO', `Generating official PDF audit report for ${currentDomain}...`);
    try {
      const blob = await fetchPdfReport(currentDomain);
      if (blob && blob.size > 0) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Aegiscripta_Security_Report_${currentDomain.replace(/\./g, '_')}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        addLog('SUCCESS', `Official PDF dossier downloaded.`);
      } else {
        window.print();
        addLog('INFO', 'Launched client-side print layout.');
      }
    } catch {
      window.print();
    }
  };

  const handleUploadPcap = async (file: File) => {
    setIsPcapLoading(true);
    addLog('SYSTEM', `Ingesting PCAP network capture: ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`);
    try {
      const res = await scanPcap(file);
      setPcapData(res.data);
      addLog('SUCCESS', `Reassembled ${res.data.total_tcp_streams} streams from ${res.data.total_packets} frames in ${file.name}.`);
      if (res.data.summary_findings?.length > 0) {
        addLog('ALERT', `${res.data.summary_findings.length} security threats/anomalies detected in capture.`);
      } else {
        addLog('SUCCESS', 'All reconstructed TCP sessions verified clean without cleartext credential leaks.');
      }
    } catch (err: unknown) {
      const diagnostic = err instanceof Error ? err.message : 'Unknown PCAP analysis error';
      console.error('[AegisCrypta] PCAP analysis failed', { fileName: file.name, diagnostic });
      addLog('ERROR', 'PCAP analysis failed. Check terminal for details.');
      setToastMessage('PCAP analysis failed. Check terminal for details.');
    } finally {
      setIsPcapLoading(false);
    }
  };

  // Real counts for the sidebar, sourced from the latest scan response.
  const sessionCount = scanData?.crypto_posture?.protocols_audited?.length ?? null;
  const certificateCount =
    scanData?.crypto_posture?.protocols_audited?.filter((p) => p.tls_handshake?.certificate).length ?? null;
  const selectedCert = scanData?.crypto_posture?.protocols_audited?.[0]?.tls_handshake?.certificate ?? null;
  const selectedDkimCheck = scanData?.checks?.find((c) => c.name.toLowerCase().includes('dkim')) ?? null;
  const credentialNodeDetail =
    selectedNodeId === 'cred-1'
      ? selectedCert
        ? `X.509 Certificate — ${selectedCert.subject_cn || selectedCert.subject_dn} (chain ${
            selectedCert.chain_valid === true ? 'validated' : selectedCert.chain_valid === false ? 'untrusted' : 'not reported'
          })`
        : 'No certificate telemetry in the latest scan response'
      : selectedDkimCheck
        ? `${selectedDkimCheck.name} — status ${selectedDkimCheck.status.toUpperCase()}`
        : 'No DKIM check in the latest scan response';

  return (
    <div
      className="flex h-screen w-screen overflow-hidden bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans selection:bg-blue-500/30 selection:text-blue-200 selection:dark:bg-blue-500/20"
      data-theme={settings.theme}
    >
      {/* 1. LEFT SIDEBAR: Pinned left, full height, strictly separated from terminal */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenCertificates={() => setIsCertModalOpen(true)}
        onStatusClick={handleStatusPing}
        backendOnline={backendOnline}
        isOpenMobile={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
        sessionCount={sessionCount}
        certificateCount={certificateCount}
        isStatusChecking={isPinging}
      />

      {/* 2. MAIN WORKSPACE: Flex column containing Topbar + Scrollable Dashboard + Bottom Docked Terminal */}
      <div className="flex-1 flex flex-col h-full overflow-hidden relative z-10">
        
        {/* Top Header Bar with Run Audit CTA */}
        <HeaderBar
          onToggleMobileMenu={() => setIsMobileMenuOpen(true)}
          onOpenReportModal={() => setIsReportModalOpen(true)}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onTriggerScan={handleTriggerScan}
          isScanning={scanState === 'SCANNING'}
          backendOnline={backendOnline}
        />

        {/* Scrollable Main Dashboard Canvas */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-5 lg:p-6 space-y-5 custom-scrollbar">
          
          {/* Active Tab Notice (if filtered) */}
          {activeTab !== 'overview' && activeTab !== 'sessions' && (
            <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <Shield size={14} className="text-blue-500 dark:text-blue-400" />
                <span className="font-semibold text-slate-800 dark:text-slate-200 uppercase tracking-wider">
                  FILTERED TELEMETRY: {activeTab.toUpperCase()}
                </span>
                <span className="text-slate-500 dark:text-slate-400 hidden sm:inline">
                  — Focused posture mode active.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                className="text-blue-400 hover:text-white underline text-[11px]"
              >
                Return to Full Overview
              </button>
            </div>
          )}

          {/* SESSIONS TAB: Passive PCAP Forensics Stream Reassembly */}
          {activeTab === 'sessions' ? (
            <div className="space-y-5">
              <section className="bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-md p-5 hover:border-cyan-500/50 transition-colors">
                <div className="flex items-center justify-between mb-5 pb-4 border-b border-slate-200 dark:border-slate-800/60">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Shield size={18} className="text-cyan-600 dark:text-cyan-400" />
                      Passive PCAP Network Forensics &amp; Stream Reassembly
                    </h2>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                      Forensic passive analysis of network packet captures (.pcap / .pcapng). Reconstructs TCP streams, detects STARTTLS stripping attacks, and extracts cryptographic handshake parameters.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('overview')}
                    className="px-3.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-900/60 hover:bg-slate-200 dark:hover:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-mono text-cyan-700 dark:text-cyan-400/90 transition-colors"
                  >
                    Back to Overview
                  </button>
                </div>
                <PcapForensicsView
                  pcapData={pcapData}
                  onUploadPcap={handleUploadPcap}
                  isLoading={isPcapLoading}
                />
              </section>
            </div>
          ) : (
            /* UNIFIED 12-COLUMN SIH 26159 CYBER-SOC DASHBOARD */
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch auto-rows-fr">

              {/* ROW 1 · 12 Cols: Telemetry Header + 3-Card Top Row (4 / 5 / 3 split) */}

              {/* Card 1 · Email Cryptographic Sessions (4/12) */}
              <div className="xl:col-span-4 flex">
                <CryptoSessionsCard
                  className="flex-1"
                  score={scanData ? (scanData.security_score ?? scanData.score) : null}
                  checks={scanData?.checks}
                  cryptoPosture={scanData?.crypto_posture}
                  onExplore={() => setActiveTab('sessions')}
                />
              </div>

              {/* Card 2 · Key Protocol / Mode Monitor (5/12) */}
              <div className="xl:col-span-5 flex">
                <KeyProtocolCard
                  className="flex-1"
                  cryptoPosture={scanData?.crypto_posture}
                  checks={scanData?.checks}
                  score={score}
                  scanData={scanData}
                  onModeChange={(mode: KeyMode) => {
                    addLog('INFO', `Switched protocol monitor mode to [${mode.toUpperCase()}].`);
                  }}
                />
              </div>

              {/* Card 3 · Active Security Report / Posture (3/12) */}
              <div className="xl:col-span-3 flex">
                <ActiveReportCard
                  className="flex-1"
                  checks={scanData?.checks}
                  score={score}
                  cryptoPosture={scanData?.crypto_posture}
                  scanData={scanData}
                  onExpand={() => setIsReportModalOpen(true)}
                />
              </div>

              {/* ROW 2 · 12 Cols: HERO — Threat Center spans full width with speedometer + CVSS + explainability */}
              <div className="xl:col-span-12 flex">
                <ThreatCenter
                  className="flex-1 w-full"
                  score={scanData ? (scanData.security_score ?? scanData.score) : null}
                  scanData={scanData}
                  domain={currentDomain}
                  fuzzyScore={scanData?.fuzzy_score}
                  linguisticClassification={scanData?.linguistic_classification}
                  antecedentScores={scanData?.antecedent_scores}
                  activatedRules={scanData?.activated_rules}
                  defuzzificationConfidence={scanData?.defuzzification_confidence}
                  cvssMetrics={scanData?.cvss_metrics}
                  onOpenReportModal={() => setIsReportModalOpen(true)}
                  onSelectCredentialNode={(id) => {
                    setSelectedNodeId(id);
                    addLog('AUTH', `Inspecting credential node [${id}] from the latest scan response.`);
                  }}
                  onOpenAiFindings={() => setIsReportModalOpen(true)}
                />
              </div>

              {/* ROW 3 · 12 Cols: Email Credentials (4) + Challenge Routes (5) + Audit Volume + Activity Stack (3) */}

              {/* Card 4 · Email Credentials / Identity Chain (4/12) */}
              <div className="xl:col-span-4 flex">
                <EmailCredentialsCard
                  className="flex-1"
                  checks={scanData?.checks}
                  cryptoPosture={scanData?.crypto_posture}
                  onExpand={() => setIsCertModalOpen(true)}
                />
              </div>

              {/* Card 5 · Challenge Routes / Ingress Probes (5/12) */}
              <div className="xl:col-span-5 flex">
                <ChallengeRouteCard
                  className="flex-1"
                  checks={scanData?.checks}
                  cryptoPosture={scanData?.crypto_posture}
                  onExpand={() => setActiveTab('verification')}
                />
              </div>

              {/* Cards 6+7 Stacked · Audit Volume + Activity Trend (3/12) */}
              <div className="xl:col-span-3 flex flex-col gap-5">
                <AuditVolumeCard
                  className="flex-1 min-h-0"
                  checks={scanData?.checks}
                  cryptoPosture={scanData?.crypto_posture}
                  onExpand={() => setActiveTab('sessions')}
                />
                <ActivityTrendCard
                  className="flex-1 min-h-0"
                  checks={scanData?.checks}
                  score={score}
                  cryptoPosture={scanData?.crypto_posture}
                  antecedentScores={scanData?.antecedent_scores}
                  onExpand={() => setIsReportModalOpen(true)}
                />
              </div>

            </div>
          )}

          {/* Selected Credential Node Detail Drawer */}
          {selectedNodeId && (
            <div className="p-3.5 rounded-md bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4 font-mono text-xs animate-fade-in">
              <div className="flex items-center gap-2.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <div>
                  <span className="font-bold text-slate-800 dark:text-slate-200">INSPECTING CREDENTIAL NODE: </span>
                  <span className="text-slate-600 dark:text-slate-300">
                    {credentialNodeDetail}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setIsCertModalOpen(true)}
                  className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-white transition-colors"
                >
                  View Full Chain
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedNodeId(null)}
                  className="px-2 py-1 rounded text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800 transition-colors"
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {/* Institutional Defense Footer */}
          <div className="mt-2 -mx-4 sm:-mx-5 lg:-mx-6 overflow-hidden border-t border-slate-200 dark:border-slate-800 bg-transparent">
            <Footer
              onExportJson={handleExportJson}
              apiBaseUrl={settings.apiBaseUrl}
            />
          </div>

        </main>

        {/* 3. DOCKED TERMINAL PANEL: Resizable between 48px and 550px, strictly inside main column */}
        <DockedTerminal
          logs={logs}
          onClearLogs={() => setLogs([])}
          onExecuteCommand={handleExecuteCommand}
          height={terminalHeight}
          onStartResize={startResizing}
          onToggleHeight={(h) => setTerminalHeight(h)}
          backendOnline={backendOnline}
          domain={currentDomain}
          score={score}
          apiBaseUrl={settings.apiBaseUrl}
        />

      </div>

      {/* SECURITY REPORT MODAL */}
      <SecurityReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        domain={currentDomain}
        score={score}
        scanData={scanData}
        onExportJson={handleExportJson}
        onExportPdf={handleExportPdf}
        onExportHtml={handleExportHtml}
      />

      {/* CERTIFICATES & X.509 CHAIN AUDIT MODAL */}
      <CertificateInspectorModal
        isOpen={isCertModalOpen}
        onClose={() => setIsCertModalOpen(false)}
        domain={currentDomain}
        scanData={scanData}
      />

      {/* SETTINGS MODAL */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        settings={settings}
        onUpdateSettings={handleUpdateSettings}
        backendOnline={backendOnline}
        onTestPing={handleTestPing}
        isPinging={isPinging}
      />

      {/* NOTIFICATION TOAST */}
      {toastMessage && (
        <Toast
          message={toastMessage}
          type={toastType}
          onDismiss={() => setToastMessage(null)}
          onRetry={handleCheckHealth}
          isRetrying={checkingHealth}
        />
      )}
    </div>
  );
}

export default App;
