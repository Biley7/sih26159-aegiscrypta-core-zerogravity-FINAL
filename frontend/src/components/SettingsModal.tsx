import React, { useState } from 'react';
import {
  X,
  Moon,
  Sun,
  Shield,
  Sliders,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Check
} from 'lucide-react';
import { AppSettings } from '../types';
import { setApiKey } from '../api';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  settings: AppSettings;
  onUpdateSettings: (newSettings: Partial<AppSettings>) => void;
  backendOnline: boolean | null;
  onTestPing: () => Promise<void>;
  isPinging: boolean;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  settings,
  onUpdateSettings,
  backendOnline,
  onTestPing,
  isPinging
}) => {
  const [localApiUrl, setLocalApiUrl] = useState(settings.apiBaseUrl);
  const [localApiKey, setLocalApiKey] = useState(() => sessionStorage.getItem('aegis_api_key') || '');
  const [urlSaved, setUrlSaved] = useState(false);
  const [apiKeySaved, setApiKeySaved] = useState(false);
  if (!isOpen) return null;

  // Tailwind's dark: utilities are driven strictly by the `.dark` class
  // (`darkMode: 'class'`). The data-theme attribute only feeds the CSS variable
  // palette; Pure Black keeps data-theme="high-contrast" for its OLED overrides.
  const handleThemeChange = (newTheme: 'dark' | 'light' | 'high-contrast') => {
    onUpdateSettings({ theme: newTheme });
    document.documentElement.setAttribute('data-theme', newTheme);
    if (newTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  };

  const handleSaveApiUrl = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdateSettings({ apiBaseUrl: localApiUrl });
    setUrlSaved(true);
    setTimeout(() => setUrlSaved(false), 2000);
  };

  const handleSaveApiKey = (e: React.FormEvent) => {
    e.preventDefault();
    setApiKey(localApiKey.trim());
    setApiKeySaved(true);
    setTimeout(() => setApiKeySaved(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/75 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-xl rounded-md bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 flex flex-col max-h-[90vh] overflow-hidden text-slate-900 dark:text-slate-100">
        
        {/* Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/80 dark:bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-600 dark:text-slate-300">
              <Sliders size={16} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white tracking-tight">
                Console Settings &amp; Preferences
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Configure operational theme and backend endpoints.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5 overflow-y-auto custom-scrollbar text-xs">
          
          {/* 1. Global Theme Toggle */}
          <section className="space-y-2">
            <div>
              <span className="font-semibold text-slate-700 dark:text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                Visual Theme &amp; Contrast
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Select your display mode. Transitions the entire dashboard instantaneously.
              </p>
            </div>

            <div className="grid grid-cols-3 gap-2.5">
              {/* Deep Dark */}
              <button
                type="button"
                onClick={() => handleThemeChange('dark')}
                className={`p-3 rounded-md border text-left transition-colors font-mono ${
                  settings.theme === 'dark'
                    ? 'border-cyan-500 bg-cyan-500/10 text-slate-900 dark:text-white font-semibold'
                    : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Moon size={13} className="text-indigo-400 dark:text-slate-400" />
                    <span>Deep Dark</span>
                  </div>
                  {settings.theme === 'dark' && <Check size={12} className="text-cyan-600 dark:text-cyan-400" />}
                </div>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 block">#090D16 SOC Base</span>
              </button>

              {/* Slate Light */}
              <button
                type="button"
                onClick={() => handleThemeChange('light')}
                className={`p-3 rounded-md border text-left transition-colors font-mono ${
                  settings.theme === 'light'
                    ? 'border-cyan-500 bg-cyan-500/10 text-slate-900 dark:text-white font-semibold'
                    : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Sun size={13} className="text-amber-500 dark:text-amber-400" />
                    <span>Slate Light</span>
                  </div>
                  {settings.theme === 'light' && <Check size={12} className="text-cyan-600 dark:text-cyan-400" />}
                </div>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 block">#F8FAFC Daylight</span>
              </button>

              {/* High Contrast OLED */}
              <button
                type="button"
                onClick={() => handleThemeChange('high-contrast')}
                className={`p-3 rounded-md border text-left transition-colors font-mono ${
                  settings.theme === 'high-contrast'
                    ? 'border-cyan-500 bg-cyan-500/10 text-slate-900 dark:text-white font-semibold'
                    : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Shield size={13} className="text-emerald-500 dark:text-emerald-400" />
                    <span>Pure Black</span>
                  </div>
                  {settings.theme === 'high-contrast' && <Check size={12} className="text-cyan-600 dark:text-cyan-400" />}
                </div>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 block">OLED High-Contrast</span>
              </button>
            </div>
          </section>

          {/* 2. FastAPI Backend Gateway Endpoint */}
          <section className="space-y-2 pt-3 border-t border-slate-200 dark:border-slate-800">
            <div>
              <span className="font-semibold text-slate-700 dark:text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                Backend Daemon Endpoint
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Configured REST endpoint for cryptographic scans and live probes.
              </p>
            </div>

            <form onSubmit={handleSaveApiUrl} className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700">
                  <Server size={14} className="text-slate-500 dark:text-slate-400" />
                  <input
                    type="text"
                    value={localApiUrl}
                    onChange={(e) => setLocalApiUrl(e.target.value)}
                    placeholder="http://localhost:8000"
                    className="flex-1 bg-transparent border-none outline-none font-mono text-xs text-slate-900 dark:text-slate-100"
                    spellCheck={false}
                  />
                </div>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-cyan-700 hover:bg-cyan-600 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white font-mono text-xs font-semibold transition-colors"
                >
                  {urlSaved ? 'Saved ✓' : 'Save'}
                </button>
              </div>

              <div className="flex items-center justify-between text-xs font-mono pt-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 dark:text-slate-400">Daemon Status:</span>
                  <span className={`inline-flex items-center gap-1 font-semibold ${backendOnline ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500 dark:text-amber-400'}`}>
                    {backendOnline ? (
                      <>
                        <CheckCircle2 size={12} />
                        <span className="truncate max-w-[180px]" title={settings.apiBaseUrl}>
                          Connected ({settings.apiBaseUrl})
                        </span>
                      </>
                    ) : (
                      <>
                        <AlertCircle size={12} />
                        <span>Daemon Offline</span>
                      </>
                    )}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={onTestPing}
                  disabled={isPinging}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 transition-colors disabled:opacity-50"
                >
                  <RefreshCw size={11} className={isPinging ? 'animate-spin' : ''} />
                  <span>{isPinging ? 'Probing...' : 'Ping Test'}</span>
                </button>
              </div>
            </form>
          </section>

          <section className="space-y-2 pt-3 border-t border-slate-200 dark:border-slate-800">
            <div>
              <span className="font-semibold text-slate-700 dark:text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                API Shared Key
              </span>
            </div>
            <form onSubmit={handleSaveApiKey} className="flex items-center gap-2">
              <input
                type="password"
                value={localApiKey}
                onChange={(e) => setLocalApiKey(e.target.value)}
                placeholder="AEGIS_API_KEY"
                autoComplete="off"
                className="flex-1 min-w-0 px-3 py-1.5 rounded-lg bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 outline-none font-mono text-xs text-slate-900 dark:text-slate-100"
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-cyan-700 hover:bg-cyan-600 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white font-mono text-xs font-semibold transition-colors"
              >
                {apiKeySaved ? 'Saved' : 'Set Key'}
              </button>
            </form>
          </section>

        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/70 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-500 dark:text-slate-400 text-[11px]">
            Aegiscripta Enterprise SOC v2.4
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-white font-semibold transition-colors border border-slate-200 dark:border-transparent"
          >
            Done
          </button>
        </div>

      </div>
    </div>
  );
};
