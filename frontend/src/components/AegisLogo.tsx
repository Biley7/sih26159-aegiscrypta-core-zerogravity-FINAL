import React from 'react';

interface AegisLogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const AegisLogo: React.FC<AegisLogoProps> = ({
  className = '',
  size = 28,
  showText = true
}) => {
  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      {/* Stylized Cyan Crest Icon */}
      <div 
        className="relative flex items-center justify-center"
        style={{ width: size, height: size }}
      >
        <svg
          viewBox="0 0 100 100"
          className="w-full h-full drop-shadow-[0_0_12px_rgba(0,242,254,0.65)]"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="aegis-crest-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00F2FE" />
              <stop offset="50%" stopColor="#38BDF8" />
              <stop offset="100%" stopColor="#1E40AF" />
            </linearGradient>
            <linearGradient id="aegis-crest-edge" x1="100%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.9" />
              <stop offset="60%" stopColor="#00F2FE" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.3" />
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Outer Shield / Delta Crest Shape */}
          <path
            d="M50 8 L90 78 C90 78 72 73 50 88 C28 73 10 78 10 78 L50 8 Z"
            fill="url(#aegis-crest-grad)"
            stroke="url(#aegis-crest-edge)"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />

          {/* Inner Negative Cut forming Stylized 'A' */}
          <path
            d="M50 28 L72 68 C64 65 57 66 50 72 C43 66 36 65 28 68 L50 28 Z"
            fill="#080D1A"
          />

          {/* Central Quantum Node Core */}
          <circle cx="50" cy="52" r="5" fill="#00F2FE" filter="url(#glow)" />
          <path
            d="M38 58 H62"
            stroke="#00F2FE"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        </svg>
      </div>

      {/* Brand Text */}
      {showText && (
        <div className="flex flex-col leading-none">
          <span className="text-xl font-bold tracking-tight text-white font-sans flex items-center gap-1.5">
            Aegiscripta
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse inline-block"></span>
          </span>
          <span className="text-[10px] tracking-wider text-cyan-400/80 font-mono font-medium uppercase mt-0.5">
            CYBER POSTURE OPS
          </span>
        </div>
      )}
    </div>
  );
};
