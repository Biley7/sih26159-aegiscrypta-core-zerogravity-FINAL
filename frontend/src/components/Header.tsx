import React, { useState } from 'react';
import {
  Search,
  UploadCloud,
  RefreshCw,
  Zap,
  Settings,
  ExternalLink,
  Cpu,
  FileText
} from 'lucide-react';
import { ScanState } from '../types';

interface HeaderProps {
  domain: string;
  setDomain: (domain: string) => void;
  onScan: (targetDomain?: string) => void;
  scanState: ScanState;
  currentPhaseText: string;
  activeMode: 'domain' | 'pcap';
  setActiveMode: (mode: 'domain' | 'pcap') => void;
  backendOnline: boolean | null;
  checkingHealth: boolean;
  onCheckHealth: () => void;
  isSimulatedMode: boolean;
  onOpenSettings: () => void;
}

export const PRESET_DOMAINS = [
  { domain: 'defense.gov.in', label: 'defense.gov.in', tag: 'Apex Zone' },
  { domain: 'rbi.org.in', label: 'rbi.org.in', tag: 'BFSI Strict' },
  { domain: 'gmail.com', label: 'gmail.com', tag: 'Global Tech' }
];

export const Header: React.FC<HeaderProps> = ({
  domain,
  setDomain,
  onScan,
  scanState,
  currentPhaseText,
  activeMode,
  setActiveMode,
  backendOnline,
  checkingHealth,
  onCheckHealth,
  isSimulatedMode,
  onOpenSettings
}) => {
  const [localInput, setLocalInput] = useState(domain);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (localInput.trim()) {
      setDomain(localInput.trim());
      onScan(localInput.trim());
    }
  };

  const handlePresetClick = (target: string) => {
    setLocalInput(target);
    setDomain(target);
    onScan(target);
  };

  const isLoading = scanState === 'SCANNING';

  return (
    <header className="aegis-header sticky top-0 z-40 px-4 py-2 transition-colors border-b border-border-primary bg-surface-primary">
      {/* Header Grid */}
      <div className="header-grid">
        {/* Left: Logo & Brand */}
        <div className="header-brand">
          <img
            src="/logo.png"
            alt="AegisCrypta Logo"
            className="h-10 w-10 shrink-0 object-contain cursor-pointer"
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          />
          <div className="brand-info">
            <div className="brand-title">AEGISCRYPTA</div>
            <div className="brand-meta">
              <span className="version-tag">v2.4 SEC-OPS</span>
              <span className="meta-separator">•</span>
              <span className="connection-status">
                {backendOnline ? (
                  <span className="status-indicator online">● Connected</span>
                ) : (
                  <span className="status-indicator offline">● Offline</span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Center: Command Bar */}
        <div className="header-command">
          {/* Mode Selector */}
          <div className="mode-selector" role="tablist">
            <button
              role="tab"
              aria-selected={activeMode === 'domain'}
              onClick={() => setActiveMode('domain')}
              className={`mode-tab ${activeMode === 'domain' ? 'active' : ''}`}
            >
              <Search size={12} />
              <span>Domain Audit</span>
            </button>
            <button
              role="tab"
              aria-selected={activeMode === 'pcap'}
              onClick={() => setActiveMode('pcap')}
              className={`mode-tab ${activeMode === 'pcap' ? 'active' : ''}`}
            >
              <UploadCloud size={12} />
              <span>PCAP Analysis</span>
            </button>
          </div>

          {activeMode === 'domain' && (
            <form onSubmit={handleSubmit} className="command-form">
              <div className="command-input-group">
                <Search size={13} className="command-icon" />
                <input
                  type="text"
                  value={localInput}
                  onChange={(e) => setLocalInput(e.target.value)}
                  placeholder="Target domain..."
                  className="command-input"
                  disabled={isLoading}
                  spellCheck={false}
                />
                {localInput && !isLoading && (
                  <button
                    type="button"
                    onClick={() => setLocalInput('')}
                    className="clear-btn"
                  >
                    ×
                  </button>
                )}
              </div>
              <button
                type="submit"
                disabled={isLoading || !localInput.trim()}
                className="audit-btn"
              >
                {isLoading ? (
                  <>
                    <RefreshCw size={11} className="animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Zap size={11} />
                    <span>Audit</span>
                  </>
                )}
              </button>
            </form>
          )}
        </div>

        {/* Right: Controls */}
        <div className="header-controls">
          <button
            type="button"
            onClick={onCheckHealth}
            disabled={checkingHealth}
            className="control-btn"
            title="Check backend status"
          >
            <RefreshCw size={12} className={checkingHealth ? 'animate-spin' : ''} />
          </button>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="control-btn"
            title="API documentation"
          >
            <FileText size={12} />
          </a>
          <button
            type="button"
            onClick={onOpenSettings}
            className="control-btn"
            title="Settings"
          >
            <Settings size={12} />
          </button>
        </div>
      </div>

      {/* Quick Targets Row */}
      {activeMode === 'domain' && (
        <div className="quick-targets-row">
          <span className="quick-targets-label">Quick Targets:</span>
          {PRESET_DOMAINS.map((item) => (
            <button
              key={item.domain}
              type="button"
              onClick={() => handlePresetClick(item.domain)}
              className="quick-target-link"
              disabled={isLoading}
            >
              <span className="font-mono">{item.label}</span>
              <span className="target-tag">{item.tag}</span>
            </button>
          ))}
        </div>
      )}
    </header>
  );
};
