import React from 'react';
import {
  LayoutDashboard,
  Shield,
  KeyRound,
  FileCheck,
  Settings,
  Activity,
  ChevronDown,
  ChevronRight,
  Radio,
  ExternalLink
} from 'lucide-react';
import { Logo } from './Logo';

export type NavItemKey = 'overview' | 'sessions' | 'verification' | 'certificates';

interface SidebarProps {
  activeTab: NavItemKey;
  onSelectTab: (tab: NavItemKey) => void;
  onOpenSettings: () => void;
  onOpenCertificates?: () => void;
  backendOnline?: boolean | null;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  onOpenSettings,
  onOpenCertificates,
  backendOnline = true,
  isOpenMobile = false,
  onCloseMobile
}) => {
  const [isVerificationExpanded, setIsVerificationExpanded] = React.useState(true);

  const navItems = [
    {
      id: 'overview' as NavItemKey,
      label: 'Overview',
      icon: LayoutDashboard,
      badge: 'Live'
    },
    {
      id: 'sessions' as NavItemKey,
      label: 'Cryptographic Sessions',
      icon: Shield,
      count: '300'
    },
    {
      id: 'verification' as NavItemKey,
      label: 'Key Verification',
      icon: KeyRound,
      hasChildren: true,
      children: [
        { id: 'pqc-keys', label: 'ML-KEM-768 / Kyber' },
        { id: 'x509-ca', label: 'X.509 Chain Audit', isCert: true },
        { id: 'ephemeral', label: 'X25519 Ephemeral' }
      ]
    },
    {
      id: 'certificates' as NavItemKey,
      label: 'Certificates',
      icon: FileCheck,
      count: '12'
    }
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={onCloseMobile}
        />
      )}

      {/* Pinned left flex sidebar: full height, no overlapping bottom terminal */}
      <aside
        className={`w-64 h-full flex flex-col shrink-0 bg-[#0B132B]/95 lg:bg-[#0B132B]/90 backdrop-blur-xl border-r border-[#1E293B]/80 z-30 transition-transform duration-300 ease-in-out ${
          isOpenMobile
            ? 'fixed top-0 bottom-0 left-0 translate-x-0'
            : 'max-lg:fixed max-lg:top-0 max-lg:bottom-0 max-lg:left-0 max-lg:-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-5 py-3 border-b border-[#1E293B]/70 flex items-center justify-between shrink-0">
          <Logo size={28} />
        </div>

        {/* Navigation Section */}
        <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto custom-scrollbar">
          <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
            Operations Matrix
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <div key={item.id} className="space-y-0.5">
                <button
                  type="button"
                  onClick={() => {
                    if (item.id === 'certificates' && onOpenCertificates) {
                      onOpenCertificates();
                    }
                    if (item.hasChildren) {
                      setIsVerificationExpanded(!isVerificationExpanded);
                    }
                    onSelectTab(item.id);
                    if (onCloseMobile) onCloseMobile();
                  }}
                  className={`w-full group flex items-center justify-between px-3.5 py-2 rounded-lg text-sm font-medium transition-all duration-200 relative ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/15 to-transparent text-cyan-300 font-semibold shadow-[inset_0_1px_1px_rgba(255,255,255,0.08)] border-l-2 border-cyan-400'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/50 border-l-2 border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon
                      size={17}
                      className={`transition-colors ${
                        isActive
                          ? 'text-cyan-400 drop-shadow-[0_0_8px_rgba(0,242,254,0.5)]'
                          : 'text-slate-400 group-hover:text-cyan-300'
                      }`}
                    />
                    <span className="tracking-tight text-xs sm:text-sm">{item.label}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {item.badge && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                        {item.badge}
                      </span>
                    )}
                    {item.count && (
                      <span className="text-[11px] font-mono text-slate-400">
                        {item.count}
                      </span>
                    )}
                    {item.hasChildren && (
                      <span className="text-slate-400 group-hover:text-cyan-300 transition-transform">
                        {isVerificationExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      </span>
                    )}
                  </div>
                </button>

                {/* Submenu for Key Verification */}
                {item.hasChildren && isVerificationExpanded && (
                  <div className="pl-8 pr-2 py-0.5 space-y-0.5 border-l border-slate-700/50 ml-5 my-0.5">
                    {item.children?.map((sub) => (
                      <button
                        key={sub.id}
                        type="button"
                        onClick={() => {
                          if (sub.isCert && onOpenCertificates) {
                            onOpenCertificates();
                          }
                          onSelectTab('verification');
                          if (onCloseMobile) onCloseMobile();
                        }}
                        className="w-full text-left py-1 px-2 text-xs font-mono text-slate-400 hover:text-cyan-300 hover:bg-slate-800/40 rounded transition-colors flex items-center justify-between"
                      >
                        <span className="truncate">{sub.label}</span>
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/80"></span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          {/* Microservices Port 8007 Direct Link */}
          <div className="pt-3 px-1">
            <button
              type="button"
              onClick={() => window.open('http://localhost:8007', '_blank')}
              className="w-full py-2 px-3 rounded-lg text-xs font-mono text-cyan-300 bg-cyan-950/20 hover:bg-cyan-950/40 border border-cyan-500/30 hover:border-cyan-400/60 transition-all flex items-center justify-between group shadow-sm"
              title="Open Raw Forensic Inspector on Port 8007"
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>Raw Inspector (8007)</span>
              </div>
              <ExternalLink size={12} className="text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>
        </div>

        {/* Bottom Status & Settings */}
        <div className="p-3.5 border-t border-[#1E293B]/80 bg-[#0B132B]/95 space-y-2.5 shrink-0">
          {/* System Status Pill */}
          <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  backendOnline ? 'bg-emerald-400' : 'bg-amber-400'
                }`}></span>
                <span className={`relative inline-flex rounded-full h-2 w-2 ${
                  backendOnline ? 'bg-emerald-500' : 'bg-amber-500'
                }`}></span>
              </span>
              <div className="flex flex-col">
                <span className="text-[11px] font-semibold text-slate-200">Mesh Security</span>
                <span className={`text-[9px] font-mono ${backendOnline ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {backendOnline ? '99.98% HEALTHY' : 'STANDBY MODE'}
                </span>
              </div>
            </div>
            <Radio size={13} className={backendOnline ? 'text-cyan-400 animate-pulse' : 'text-slate-500'} />
          </div>

          {/* Settings & Status Buttons */}
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={onOpenSettings}
              className="flex items-center justify-center gap-1.5 py-1.5 px-2.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800/60 hover:bg-slate-800 hover:text-white border border-slate-700/60 active:scale-95 transition-all"
            >
              <Settings size={13} className="text-slate-400" />
              <span>Settings</span>
            </button>
            <button
              type="button"
              onClick={() => onSelectTab('overview')}
              className="flex items-center justify-center gap-1.5 py-1.5 px-2.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800/60 hover:bg-slate-800 hover:text-white border border-slate-700/60 active:scale-95 transition-all"
            >
              <Activity size={13} className="text-cyan-400" />
              <span>Status</span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
