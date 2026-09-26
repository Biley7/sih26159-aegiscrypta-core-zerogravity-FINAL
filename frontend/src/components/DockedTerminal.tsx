import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal as TerminalIcon,
  ChevronDown,
  ChevronUp,
  Maximize2,
  Minimize2,
  Trash2,
  Copy,
  Check,
  CornerDownLeft,
  Circle,
  Wifi,
  WifiOff
} from 'lucide-react';

export interface TerminalLog {
  id: string;
  timestamp: string;
  tag: 'INFO' | 'AUTH' | 'ALERT' | 'PQC' | 'TLS' | 'DNS' | 'SUCCESS' | 'ERROR' | 'SYSTEM';
  message: string;
  hash?: string;
}

interface DockedTerminalProps {
  logs: TerminalLog[];
  onClearLogs: () => void;
  onExecuteCommand: (command: string) => void;
  height: number;
  onStartResize: (e: React.MouseEvent) => void;
  onToggleHeight: (targetHeight: number) => void;
  backendOnline?: boolean | null;
  domain?: string;
  score?: number | null;
}

export const DockedTerminal: React.FC<DockedTerminalProps> = ({
  logs,
  onClearLogs,
  onExecuteCommand,
  height,
  onStartResize,
  onToggleHeight,
  backendOnline = true,
  domain = 'gmail.com',
  score = null
}) => {
  const [copied, setCopied] = useState(false);
  const [commandInput, setCommandInput] = useState('');
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const isCollapsed = height <= 52;
  const isMaximized = height >= 500;

  // Auto-scroll when new logs arrive, only if not collapsed
  useEffect(() => {
    if (!isCollapsed) {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isCollapsed]);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const rawCmd = commandInput.trim();
    if (!rawCmd) return;

    setCommandHistory((prev) => [...prev, rawCmd]);
    setHistoryIndex(-1);
    setCommandInput('');
    onExecuteCommand(rawCmd);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length === 0) return;
      const nextIdx = historyIndex + 1 < commandHistory.length ? historyIndex + 1 : historyIndex;
      setHistoryIndex(nextIdx);
      setCommandInput(commandHistory[commandHistory.length - 1 - nextIdx] || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setCommandInput(commandHistory[commandHistory.length - 1 - nextIdx] || '');
      } else {
        setHistoryIndex(-1);
        setCommandInput('');
      }
    }
  };

  const handleCopyLogs = () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.tag}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getTagBadge = (tag: TerminalLog['tag']) => {
    switch (tag) {
      case 'INFO':
        return <span className="text-slate-300 font-semibold">[INFO]</span>;
      case 'AUTH':
        return <span className="text-emerald-400 font-semibold">[AUTH]</span>;
      case 'ALERT':
        return <span className="text-amber-400 font-semibold">[ALERT]</span>;
      case 'PQC':
        return <span className="text-indigo-400 font-semibold">[PQC]</span>;
      case 'TLS':
        return <span className="text-blue-400 font-semibold">[TLS]</span>;
      case 'DNS':
        return <span className="text-teal-400 font-semibold">[DNS]</span>;
      case 'SUCCESS':
        return <span className="text-emerald-400 font-semibold">[SUCCESS]</span>;
      case 'ERROR':
        return <span className="text-rose-400 font-semibold">[ERROR]</span>;
      case 'SYSTEM':
        return <span className="text-slate-400 font-semibold">[SYSTEM]</span>;
      default:
        return <span className="text-slate-400">[{tag}]</span>;
    }
  };

  return (
    <div
      style={{ height }}
      className="terminal-drawer shrink-0 border-t border-slate-800 bg-[#070B12] flex flex-col font-mono select-none relative z-20"
    >
      {/* Draggable Resize Handle */}
      <div
        onMouseDown={onStartResize}
        className="h-1.5 w-full cursor-row-resize hover:bg-slate-700 active:bg-blue-500 transition-colors flex items-center justify-center shrink-0 group"
        title="Drag up/down to resize terminal height (48px - 550px)"
      >
        <div className="w-12 h-1 bg-slate-700 rounded-full group-hover:bg-slate-500 transition-colors" />
      </div>

      {/* Terminal Header Bar */}
      <div className="h-9 px-4 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between gap-3 shrink-0">
        
        {/* Left: Terminal status indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'}`}></span>
              <TerminalIcon size={13} className="text-slate-300" />
              <span className="text-xs font-bold text-slate-100 tracking-wider">
                AUDIT TERMINAL
              </span>
            </span>

            {/* Subtle Daemon Status Pill */}
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              backendOnline
                ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                : 'text-rose-400 border-rose-500/30 bg-rose-500/10'
            }`}>
              {backendOnline ? '🟢 DAEMON CONNECTED (PORT 8000)' : '🔴 DAEMON DISCONNECTED (PORT 8000)'}
            </span>
          </div>

          <div className="hidden lg:flex items-center gap-2 pl-3 border-l border-slate-800 text-[11px] text-slate-400">
            <span>PORT 443</span>
            <span className="text-slate-600">//</span>
            <span className="text-slate-300">TLS 1.3 / ML-KEM-768</span>
            <span className="text-slate-600">//</span>
            <span className="text-slate-400">SESSION: #AEG-8492</span>
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-1.5">
          {/* Clear Logs */}
          <button
            type="button"
            onClick={onClearLogs}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Clear terminal buffer"
          >
            <Trash2 size={13} />
          </button>

          {/* Copy Logs */}
          <button
            type="button"
            onClick={handleCopyLogs}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors flex items-center gap-1"
            title="Copy logs to clipboard"
          >
            {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
            {copied && <span className="text-[10px] text-emerald-400 font-mono">COPIED</span>}
          </button>

          {/* Maximize / Standard Toggle */}
          <button
            type="button"
            onClick={() => onToggleHeight(isMaximized ? 220 : 540)}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors hidden sm:block"
            title={isMaximized ? 'Restore standard height' : 'Maximize terminal'}
          >
            {isMaximized ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>

          {/* Collapse / Expand Toggle */}
          <button
            type="button"
            onClick={() => onToggleHeight(isCollapsed ? 220 : 48)}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title={isCollapsed ? 'Expand terminal drawer' : 'Collapse terminal drawer'}
          >
            {isCollapsed ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Terminal Body & CLI input (Rendered when expanded) */}
      {!isCollapsed && (
        <>
          {/* Scrollable log stream */}
          <div className="flex-1 overflow-y-auto p-3 space-y-1 text-xs text-slate-300 custom-scrollbar select-text bg-[#070B12]">
            {logs.length === 0 ? (
              <div className="py-4 text-center text-slate-600 text-xs italic">
                Terminal output buffer is empty. Type 'help' below or enter a target domain above.
              </div>
            ) : (
              logs.map((log) => (
                <div
                  key={log.id}
                  className="flex items-start gap-2 hover:bg-slate-900/60 px-1 py-0.5 rounded leading-relaxed"
                >
                  <span className="text-[11px] text-slate-500 shrink-0 select-none">
                    {log.timestamp}
                  </span>
                  <span className="shrink-0 select-none">
                    {getTagBadge(log.tag)}
                  </span>
                  <span className="flex-1 break-all text-slate-200">
                    {log.message}
                  </span>
                  {log.hash && (
                    <span className="text-[10px] text-slate-400 bg-slate-900 px-1 rounded border border-slate-800 shrink-0 select-all">
                      {log.hash}
                    </span>
                  )}
                </div>
              ))
            )}
            <div ref={terminalEndRef} />
          </div>

          {/* Interactive CLI Input Line */}
          <form
            onSubmit={handleFormSubmit}
            className="h-9 px-4 bg-slate-900/90 border-t border-slate-800 flex items-center gap-2 shrink-0"
          >
            <div className="flex items-center gap-1.5 text-blue-400 font-bold text-xs select-none">
              <span>aegis</span>
              <span className="text-emerald-400">&gt;</span>
            </div>

            <input
              ref={inputRef}
              type="text"
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="type 'help', 'status', 'verify', 'pqc', 'scan gmail.com', 'report'..."
              className="flex-1 bg-transparent text-xs text-white placeholder-slate-600 focus:outline-none font-mono"
              autoComplete="off"
              spellCheck={false}
            />

            <button
              type="submit"
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Execute Command (Enter)"
            >
              <CornerDownLeft size={13} />
            </button>
          </form>
        </>
      )}
    </div>
  );
};
