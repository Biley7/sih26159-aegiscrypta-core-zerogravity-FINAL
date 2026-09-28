import React, { useState } from 'react';
import {
  Search,
  Download,
  ExternalLink,
  ShieldCheck,
  Menu,
  Play,
  RotateCcw,
  Sparkles,
  Command
} from 'lucide-react';

interface HeaderBarProps {
  onToggleMobileMenu: () => void;
  onOpenReportModal: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onTriggerScan: (target: string) => void;
  onEmptySearch?: () => void;
  isScanning?: boolean;
  isCustomerFacing?: boolean;
  onToggleCustomerFacing?: () => void;
  backendOnline?: boolean | null;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  onToggleMobileMenu,
  onOpenReportModal,
  searchQuery,
  onSearchChange,
  onTriggerScan,
  onEmptySearch,
  isScanning = false,
  isCustomerFacing = true,
  onToggleCustomerFacing,
  backendOnline = null
}) => {
  const [isFocused, setIsFocused] = useState(false);

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = searchQuery.trim();
    if (trimmed && !isScanning) {
      onTriggerScan(trimmed);
    } else if (!trimmed && onEmptySearch) {
      onEmptySearch();
    }
  };

  return (
    <header className="py-3 px-5 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4 shrink-0 z-20">
      {/* Left: Mobile Menu Toggle & Search Bar with Run Audit CTA */}
      <div className="flex items-center gap-3 flex-1 max-w-2xl">
        <button
          type="button"
          onClick={onToggleMobileMenu}
          className="lg:hidden p-2 rounded text-slate-500 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors"
          aria-label="Toggle Navigation"
        >
          <Menu size={20} />
        </button>

        {/* Cyber Search & Audit Trigger Form */}
        <form onSubmit={handleSubmit} className="flex items-center gap-2 w-full">
          <div
            className={`flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-slate-50 dark:bg-slate-900 border transition-colors flex-1 ${
              isFocused
                ? 'border-cyan-500 ring-1 ring-cyan-500/40'
                : 'border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-600'
            }`}
          >
            <Search size={16} className={`transition-colors shrink-0 ${isFocused ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-400'}`} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setIsFocused(false)}
              placeholder="e.g., enterprise-target.com or gmail.com"
              className="bg-transparent text-xs sm:text-sm font-mono tracking-tight text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 font-mono text-sm focus:outline-none w-full"
              disabled={isScanning}
            />
            {isScanning ? (
              <RotateCcw size={14} className="text-cyan-600 dark:text-cyan-400 animate-spin shrink-0" />
            ) : (
              <div className="hidden sm:flex items-center gap-1 text-[10px] font-mono tracking-tight text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800/80 px-2 py-0.5 rounded-full border border-slate-200 dark:border-slate-700 shrink-0">
                <Command size={10} />
                <span>K</span>
              </div>
            )}
          </div>

          {/* Explicit "Run Audit" Button */}
          <button
            type="submit"
            disabled={isScanning || !searchQuery.trim()}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded text-[11px] font-semibold font-mono tracking-wider uppercase text-white bg-cyan-700 hover:bg-cyan-600 dark:bg-cyan-600 dark:hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shrink-0"
            title="Execute Real-time Posture Audit"
          >
            {isScanning ? (
              <>
                <RotateCcw size={12} className="animate-spin" />
                <span className="hidden sm:inline">AUDITING</span>
              </>
            ) : (
              <>
                <Play size={12} className="fill-white" />
                <span>RUN AUDIT</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Right Side: Backend Status Badge & Security Report Button */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Backend reachability. The dot carries the state — pulsing only while there is
            something to act on — and the label stays muted so it never shouts. */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[10px] font-mono tracking-wider">
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              backendOnline === true
                ? 'bg-emerald-500'
                : backendOnline === false
                  ? 'bg-rose-500 animate-pulse'
                  : 'bg-amber-500 animate-pulse'
            }`}
            aria-hidden="true"
          ></span>
          <span className="text-slate-500 dark:text-slate-400">ENGINE:</span>
          <span className="font-semibold text-slate-600 dark:text-slate-300">
            {backendOnline === true ? 'ONLINE' : backendOnline === false ? 'OFFLINE' : 'CHECKING'}
          </span>
        </div>

        {/* Asset Criticality Toggle: Customer-Facing vs Internal */}
        <button
          type="button"
          onClick={onToggleCustomerFacing}
          className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-mono font-semibold tracking-wider transition-colors ${
            isCustomerFacing
              ? 'bg-amber-500/10 border-amber-500/40 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20'
              : 'bg-slate-100 dark:bg-slate-800/60 border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-slate-400'
          }`}
          title={isCustomerFacing ? 'Asset: Customer-Facing (higher exploitation likelihood)' : 'Asset: Internal (lower exploitation likelihood)'}
        >
          <ShieldCheck size={10} />
          {isCustomerFacing ? 'EXT' : 'INT'}
        </button>

        {/* Primary CTA: "Security Report" */}
        <button
          type="button"
          onClick={onOpenReportModal}
          className="inline-flex items-center gap-2 px-3.5 sm:px-4 py-1.5 rounded text-xs font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-600 transition-colors"
        >
          <Download size={14} className="text-slate-500 dark:text-slate-400" />
          <span className="font-sans tracking-tight">Security Report</span>
          <ExternalLink size={12} className="text-slate-500 dark:text-slate-400" />
        </button>
      </div>
    </header>
  );
};
