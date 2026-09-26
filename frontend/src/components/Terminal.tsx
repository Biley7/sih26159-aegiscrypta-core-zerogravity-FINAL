import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal as TerminalIcon,
  Pause,
  Play,
  Trash2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export interface LogEntry {
  id: string;
  timestamp: string;
  phase?: string;
  text: string;
  level?: 'info' | 'warn' | 'success' | 'error';
}

export interface TerminalProps {
  logs: LogEntry[];
  isLoading: boolean;
  onClearLogs: () => void;
}

export const Terminal: React.FC<TerminalProps> = ({
  logs,
  isLoading,
  onClearLogs
}) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [copied, setCopied] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when logs update unless paused
  useEffect(() => {
    if (!isPaused && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, isPaused]);

  const handleCopyLogs = async () => {
    const rawText = logs
      .map((l) => `[${l.timestamp}] ${l.phase ? `[${l.phase}] ` : ''}${l.text}`)
      .join('\n');

    try {
      await navigator.clipboard.writeText(rawText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.warn('Failed to copy logs', err);
    }
  };

  return (
    <aside
      className={`terminal-drawer-container ${isCollapsed ? 'collapsed' : ''} ${
        isLoading ? 'active-scanning' : ''
      }`}
      aria-label="Live Telemetry & Forensic Stream"
    >
      {/* Terminal Titlebar */}
      <div className="terminal-titlebar">
        <div className="terminal-ident">
          <TerminalIcon size={14} className="terminal-prompt-icon text-cyan-400" />
          <span className="terminal-title-text font-mono">
            live_telemetry_stream.log
          </span>
          {isLoading && (
            <span className="terminal-live-tag font-mono text-[10px]">
              <span className="ping-dot" /> STREAMING
            </span>
          )}
          <span className="log-count-indicator font-mono text-[11px] text-slate-500">
            ({logs.length} entries)
          </span>
        </div>

        {/* Action Controls */}
        <div className="terminal-controls-group">
          {/* Pause / Resume Button */}
          <button
            type="button"
            onClick={() => setIsPaused(!isPaused)}
            className={`term-ctrl-btn ${isPaused ? 'active-pause' : ''}`}
            title={isPaused ? 'Resume auto-scrolling' : 'Pause log stream'}
          >
            {isPaused ? <Play size={12} /> : <Pause size={12} />}
            <span className="font-mono text-xs">{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>

          {/* Clear Logs Button */}
          <button
            type="button"
            onClick={onClearLogs}
            className="term-ctrl-btn"
            title="Clear terminal buffer"
          >
            <Trash2 size={12} />
            <span className="font-mono text-xs">Clear Terminal</span>
          </button>

          {/* Copy Logs Button */}
          <button
            type="button"
            onClick={handleCopyLogs}
            className="term-ctrl-btn"
            title="Copy log terminal content to clipboard"
          >
            {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
            <span className="font-mono text-xs">{copied ? 'Copied' : 'Copy Log to Clipboard'}</span>
          </button>

          {/* Minimize / Expand Toggle */}
          <button
            type="button"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="term-ctrl-btn term-collapse-btn"
            title={isCollapsed ? 'Expand terminal drawer' : 'Minimize terminal drawer'}
          >
            {isCollapsed ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>
      </div>

      {/* Terminal Log Console */}
      {!isCollapsed && (
        <div
          ref={logContainerRef}
          className="terminal-log-console"
          tabIndex={0}
          role="log"
          aria-live="polite"
        >
          {logs.length === 0 ? (
            <div className="empty-logs-placeholder font-mono text-xs text-slate-600">
              $ aegis-engine --monitor-mode=active ... awaiting target input
            </div>
          ) : (
            logs.map((log) => (
              <div key={log.id} className={`log-entry-row ${log.level || 'info'}`}>
                <span className="log-timestamp font-mono">[{log.timestamp}]</span>
                {log.phase && (
                  <span className="log-phase-tag font-mono">[{log.phase}]</span>
                )}
                <span className="log-text font-mono">{log.text}</span>
              </div>
            ))
          )}
        </div>
      )}
    </aside>
  );
};
