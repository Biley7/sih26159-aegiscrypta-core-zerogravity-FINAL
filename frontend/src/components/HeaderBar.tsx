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
  isScanning?: boolean;
  backendOnline?: boolean | null;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({
  onToggleMobileMenu,
  onOpenReportModal,
  searchQuery,
  onSearchChange,
  onTriggerScan,
  isScanning = false,
  backendOnline = null
}) => {
  const [isFocused, setIsFocused] = useState(false);

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (searchQuery.trim() && !isScanning) {
      onTriggerScan(searchQuery.trim());
    }
  };

  return (
    <header className="h-16 px-4 md:px-6 bg-[#080D1A]/90 backdrop-blur-md border-b border-[#1E293B]/70 flex items-center justify-between gap-4 shrink-0 z-20">
      {/* Left: Mobile Menu Toggle & Search Bar with Run Audit CTA */}
      <div className="flex items-center gap-3 flex-1 max-w-2xl">
        <button
          type="button"
          onClick={onToggleMobileMenu}
          className="lg:hidden p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
          aria-label="Toggle Navigation"
        >
          <Menu size={20} />
        </button>

        {/* Cyber Search & Audit Trigger Form */}
        <form onSubmit={handleSubmit} className="flex items-center gap-2 w-full">
          <div
            className={`flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-[#0F172A]/90 border transition-all duration-300 flex-1 shadow-[inset_0_1px_2px_rgba(0,0,0,0.5)] ${
              isFocused
                ? 'border-cyan-400 shadow-[0_0_15px_rgba(0,242,254,0.3)] ring-1 ring-cyan-400/40'
                : 'border-slate-700/70 hover:border-slate-600'
            }`}
          >
            <Search size={16} className={`transition-colors shrink-0 ${isFocused ? 'text-cyan-400' : 'text-slate-400'}`} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setIsFocused(false)}
              placeholder="Target domain (e.g. gmail.com, defense.gov.in)..."
              className="bg-transparent text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none w-full font-sans"
              disabled={isScanning}
            />
            {isScanning ? (
              <RotateCcw size={14} className="text-cyan-400 animate-spin shrink-0" />
            ) : (
              <div className="hidden sm:flex items-center gap-1 text-[10px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded-full border border-slate-700/60 shrink-0">
                <Command size={10} />
                <span>K</span>
              </div>
            )}
          </div>

          {/* Explicit "Run Audit" Button */}
          <button
            type="submit"
            disabled={isScanning || !searchQuery.trim()}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold font-mono tracking-tight text-black bg-gradient-to-r from-cyan-400 to-teal-400 hover:brightness-110 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_12px_rgba(0,242,254,0.35)] transition-all shrink-0"
            title="Execute Real-time Posture Audit"
          >
            {isScanning ? (
              <>
                <RotateCcw size={12} className="animate-spin" />
                <span className="hidden sm:inline">AUDITING</span>
              </>
            ) : (
              <>
                <Play size={12} className="fill-black" />
                <span>RUN AUDIT</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Right Side: Backend Status Badge & Security Report Button */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Backend Online/Offline Status Indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-300">
          <span className={`w-2 h-2 rounded-full ${backendOnline === true ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]' : backendOnline === false ? 'bg-rose-400' : 'bg-amber-400'}`}></span>
          <span className="text-slate-400">ENGINE:</span>
          <span className={`font-semibold ${backendOnline === true ? 'text-cyan-300' : backendOnline === false ? 'text-rose-300' : 'text-amber-300'}`}>
            {backendOnline === true ? 'ONLINE' : backendOnline === false ? 'OFFLINE' : 'CHECKING'}
          </span>
        </div>

        {/* Primary CTA: "Security Report" */}
        <button
          type="button"
          onClick={onOpenReportModal}
          className="group relative inline-flex items-center gap-2 px-3.5 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold text-white transition-all duration-300 overflow-hidden bg-gradient-to-r from-[#00F2FE]/20 via-[#38BDF8]/20 to-[#10B981]/20 hover:from-[#00F2FE]/30 hover:via-[#38BDF8]/30 hover:to-[#10B981]/30 border border-cyan-400/50 hover:border-cyan-300 shadow-[0_0_15px_rgba(0,242,254,0.25)] hover:shadow-[0_0_25px_rgba(0,242,254,0.45)] active:scale-95"
        >
          <span className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          
          <Download size={14} className="text-cyan-300 group-hover:scale-110 transition-transform" />
          <span className="relative font-sans tracking-tight">Security Report</span>
          <ExternalLink size={12} className="text-cyan-400/80 group-hover:text-cyan-300 transition-colors" />
        </button>
      </div>
    </header>
  );
};
