/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif'
        ],
        mono: [
          'JetBrains Mono',
          'Fira Code',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace'
        ],
      },
      colors: {
        canvas: '#080D1A',
        aegis: {
          dark: '#080D1A',
          navy: '#0B132B',
          slate: '#0F172A',
          card: 'rgba(15, 23, 42, 0.72)',
          'card-hover': 'rgba(19, 30, 54, 0.85)',
          border: 'rgba(56, 189, 248, 0.16)',
          'border-bright': 'rgba(0, 242, 254, 0.35)',
          cyan: '#00F2FE',
          teal: '#38BDF8',
          blue: '#1E40AF',
          emerald: '#10B981',
          amber: '#F59E0B',
          rose: '#EF4444',
          accent: '#06B6D4',
        },
        surface: {
          primary: '#0B132B',
          secondary: '#0F172A',
          elevated: '#162038',
        },
        border: {
          primary: '#1E293B',
          subtle: '#28354E',
        },
        soc: {
          secure: '#10b981',
          warning: '#f59e0b',
          critical: '#f43f5e',
          pqc: '#00f2fe',
        },
        text: {
          primary: '#F8FAFC',
          secondary: '#94A3B8',
          muted: '#64748B',
        },
        // The slate ramp is variable-driven (see `--t-slate-*` in styles.css) so
        // the "Pure Black" OLED theme can swap the whole neutral scale for a true
        // neutral obsidian ramp. This keeps every `hover:`/`group-hover:` accent
        // working untouched — no `!important` specificity war required.
        slate: {
          50: 'rgb(var(--t-slate-50) / <alpha-value>)',
          100: 'rgb(var(--t-slate-100) / <alpha-value>)',
          200: 'rgb(var(--t-slate-200) / <alpha-value>)',
          300: 'rgb(var(--t-slate-300) / <alpha-value>)',
          400: 'rgb(var(--t-slate-400) / <alpha-value>)',
          500: 'rgb(var(--t-slate-500) / <alpha-value>)',
          600: 'rgb(var(--t-slate-600) / <alpha-value>)',
          700: 'rgb(var(--t-slate-700) / <alpha-value>)',
          800: 'rgb(var(--t-slate-800) / <alpha-value>)',
          900: 'rgb(var(--t-slate-900) / <alpha-value>)',
          950: 'rgb(var(--t-slate-950) / <alpha-value>)',
        },
      },
      boxShadow: {
        subtle: '0 1px 2px 0 rgba(0, 0, 0, 0.35)',
        'cyan-glow': '0 0 20px rgba(0, 242, 254, 0.25)',
        'cyan-glow-lg': '0 0 35px rgba(0, 242, 254, 0.4)',
        'card-glow': '0 4px 20px -2px rgba(0, 0, 0, 0.5), 0 0 15px -3px rgba(0, 242, 254, 0.08)',
        'emerald-glow': '0 0 15px rgba(16, 185, 129, 0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 12s linear infinite',
      }
    },
  },
  plugins: [],
};
