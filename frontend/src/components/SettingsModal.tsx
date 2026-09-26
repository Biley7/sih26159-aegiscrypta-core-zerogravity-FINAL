import React, { useState } from 'react';
import {
  X,
  Moon,
  Sun,
  Shield,
  Sliders,
  Sparkles,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Eye,
  FileText,
  Check,
  Upload,
  RotateCcw
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
  const [logoUploaded, setLogoUploaded] = useState(false);

  if (!isOpen) return null;

  const handleThemeChange = (newTheme: 'dark' | 'light' | 'high-contrast') => {
    onUpdateSettings({ theme: newTheme });
    document.documentElement.setAttribute('data-theme', newTheme);
    if (newTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  };

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const base64 = event.target?.result as string;
        localStorage.setItem('aegis_custom_logo', base64);
        setLogoUploaded(true);
        setTimeout(() => {
          setLogoUploaded(false);
          window.location.reload();
        }, 1000);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleResetLogo = () => {
    localStorage.removeItem('aegis_custom_logo');
    window.location.reload();
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-xl rounded-xl bg-slate-900 border border-slate-800 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden text-slate-100">
        
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center text-slate-300">
              <Sliders size={16} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Console Settings &amp; Preferences
              </h3>
              <p className="text-[11px] text-slate-400">
                Configure operational theme, custom branding, and backend endpoints.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5 overflow-y-auto custom-scrollbar text-xs">
          
          {/* 1. Global Theme Toggle */}
          <section className="space-y-2">
            <div>
              <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                Visual Theme &amp; Contrast
              </span>
              <p className="text-[11px] text-slate-400">
                Select your display mode. Transitions the entire dashboard instantaneously.
              </p>
            </div>

            <div className="grid grid-cols-3 gap-2.5">
              {/* Deep Dark */}
              <button
                type="button"
                onClick={() => handleThemeChange('dark')}
                className={`p-3 rounded-lg border text-left transition-colors font-mono ${
                  settings.theme === 'dark'
                    ? 'border-blue-500 bg-blue-500/10 text-white font-semibold'
                    : 'border-slate-800 bg-slate-800/40 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Moon size={13} className="text-slate-400" />
                    <span>Deep Dark</span>
                  </div>
                  {settings.theme === 'dark' && <Check size={12} className="text-blue-400" />}
                </div>
                <span className="text-[10px] text-slate-500 block">#090D16 SOC Base</span>
              </button>

              {/* Slate Light */}
              <button
                type="button"
                onClick={() => handleThemeChange('light')}
                className={`p-3 rounded-lg border text-left transition-colors font-mono ${
                  settings.theme === 'light'
                    ? 'border-blue-500 bg-blue-500/10 text-white font-semibold'
                    : 'border-slate-800 bg-slate-800/40 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Sun size={13} className="text-amber-400" />
                    <span>Slate Light</span>
                  </div>
                  {settings.theme === 'light' && <Check size={12} className="text-blue-400" />}
                </div>
                <span className="text-[10px] text-slate-500 block">#F8FAFC Daylight</span>
              </button>

              {/* High Contrast OLED */}
              <button
                type="button"
                onClick={() => handleThemeChange('high-contrast')}
                className={`p-3 rounded-lg border text-left transition-colors font-mono ${
                  settings.theme === 'high-contrast'
                    ? 'border-blue-500 bg-blue-500/10 text-white font-semibold'
                    : 'border-slate-800 bg-slate-800/40 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 text-xs">
                    <Shield size={13} className="text-emerald-400" />
                    <span>Pure Black</span>
                  </div>
                  {settings.theme === 'high-contrast' && <Check size={12} className="text-blue-400" />}
                </div>
                <span className="text-[10px] text-slate-500 block">OLED High-Contrast</span>
              </button>
            </div>
          </section>

          {/* 2. Custom Dashboard Logo Branding */}
          <section className="space-y-2 pt-3 border-t border-slate-800">
            <div>
              <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                Dashboard Logo &amp; Custom Branding
              </span>
              <p className="text-[11px] text-slate-400">
                Upload custom logo (PNG/SVG) to persist across sessions in local storage.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 cursor-pointer transition-colors">
                <Upload size={13} />
                <span>Upload Custom Logo</span>
                <input
                  type="file"
                  accept="image/png, image/svg+xml, image/webp"
                  onChange={handleLogoUpload}
                  className="hidden"
                />
              </label>

              <button
                type="button"
                onClick={handleResetLogo}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                <RotateCcw size={12} />
                <span>Reset to Default</span>
              </button>

              {logoUploaded && (
                <span className="text-emerald-400 font-mono text-xs flex items-center gap-1">
                  <Check size={12} /> Logo updated! Reloading...
                </span>
              )}
            </div>
          </section>

          {/* 3. FastAPI Backend Gateway Endpoint */}
          <section className="space-y-2 pt-3 border-t border-slate-800">
            <div>
              <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] font-mono">
                Backend Daemon Endpoint
              </span>
              <p className="text-[11px] text-slate-400">
                Configured REST endpoint for cryptographic scans and live probes.
              </p>
            </div>

            <form onSubmit={handleSaveApiUrl} className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700">
                  <Server size={14} className="text-slate-400" />
                  <input
                    type="text"
                    value={localApiUrl}
                    onChange={(e) => setLocalApiUrl(e.target.value)}
                    placeholder="http://localhost:8000"
                    className="flex-1 bg-transparent border-none outline-none font-mono text-xs text-slate-100"
                    spellCheck={false}
                  />
                </div>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-semibold transition-colors"
                >
                  {urlSaved ? 'Saved ✓' : 'Save'}
                </button>
              </div>

              <div className="flex items-center justify-between text-xs font-mono pt-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Daemon Status:</span>
                  <span className={`inline-flex items-center gap-1 font-semibold ${backendOnline ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {backendOnline ? (
                      <>
                        <CheckCircle2 size={12} />
                        <span>Connected (Port 8000)</span>
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
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors"
                >
                  <RefreshCw size={11} className={isPinging ? 'animate-spin' : ''} />
                  <span>{isPinging ? 'Probing...' : 'Ping Test'}</span>
                </button>
              </div>
            </form>
          </section>

          <section className="space-y-2 pt-3 border-t border-slate-800">
            <div>
              <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] font-mono">
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
                className="flex-1 min-w-0 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 outline-none font-mono text-xs text-slate-100"
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-semibold transition-colors"
              >
                {apiKeySaved ? 'Saved' : 'Set Key'}
              </button>
            </form>
          </section>

        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950/70 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-500 text-[11px]">
            Aegiscripta Enterprise SOC v2.4
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition-colors"
          >
            Done
          </button>
        </div>

      </div>
    </div>
  );
};
