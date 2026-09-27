import React, { useState, useEffect } from 'react';

interface LogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const Logo: React.FC<LogoProps> = ({
  className = '',
  size = 30,
  showText = true
}) => {
  const [logoSrc, setLogoSrc] = useState<string>('/logo.png');
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    const custom = localStorage.getItem('aegis_custom_logo');
    if (custom) {
      setLogoSrc(custom);
    }
  }, []);

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      {/* Dynamic Logo Image with Fallback */}
      {!hasError ? (
        <img
          src={logoSrc}
          alt="Aegiscripta Logo"
          style={{ height: size, width: 'auto' }}
          className="object-contain max-w-[36px]"
          onError={() => {
            if (logoSrc !== '/logo.svg') {
              setLogoSrc('/logo.svg');
            } else {
              setHasError(true);
            }
          }}
        />
      ) : (
        /* Fallback Clean Geometric SVG Shield Crest */
        <div
          className="flex items-center justify-center rounded-lg bg-blue-600/15 border border-blue-500/30 text-blue-600 dark:text-blue-400"
          style={{ width: size, height: size }}
        >
          <svg viewBox="0 0 24 24" className="w-5 h-5 fill-none stroke-current" strokeWidth="2">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
            <path d="M12 8v8" strokeLinecap="round" />
            <path d="M8 12h8" strokeLinecap="round" />
          </svg>
        </div>
      )}

      {/* Brand Text */}
      {showText && (
        <div className="flex flex-col leading-none">
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white font-sans flex items-center gap-1.5">
            Aegiscripta
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block"></span>
          </span>
          <span className="text-[9px] tracking-[0.2em] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mt-0.5">
            CYBER POSTURE OPS
          </span>
        </div>
      )}
    </div>
  );
};
