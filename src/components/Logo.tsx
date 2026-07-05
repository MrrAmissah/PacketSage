import React from 'react';

interface LogoProps {
  className?: string;
  iconClassName?: string;
  forceLight?: boolean;
}

/**
 * High-fidelity, vector-perfect SVG representation of the PacketSage symbol:
 * A letter 'P' shape composed of precise circuit tracks, utilizing a deep navy body,
 * white internal circuit traces, a bright accent-blue lower stem, and a bright blue inner pad.
 */
export function PacketSageIcon({ className = "w-8 h-8", style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={style}
    >
      {/* Deep Navy Main Body of the 'P' (upper bowl & stem connection) */}
      <path
        d="M25 15h34c14.36 0 20 8.5 20 19.5S73.36 54 59 54H43.5c-1.5 0-3 .5-4 1.5L25 70.5V15z"
        fill="#001c43"
        className="fill-[#001c43] dark:fill-[#081e3d]"
      />

      {/* Internal Track 1: Upper circuit lane */}
      <path
        d="M25 41.5l11.5-11.5H58"
        stroke="#ffffff"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="58" cy="30" r="5" fill="#ffffff" />
      <circle cx="58" cy="30" r="2.2" fill="#001c43" className="fill-[#001c43] dark:fill-[#081e3d]" />

      {/* Internal Track 2: Middle circuit lane */}
      <path
        d="M25 54.5l13.5-13.5H65"
        stroke="#ffffff"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="65" cy="41" r="5" fill="#ffffff" />
      <circle cx="65" cy="41" r="2.2" fill="#001c43" className="fill-[#001c43] dark:fill-[#081e3d]" />

      {/* Bright Accent Blue lower stem of the 'P' */}
      <path
        d="M25 76.5L43.5 58c1-1 2.5-1.5 4-1.5H50v21.5c0 1.5-.5 3-1.5 4H25v-5.5z"
        fill="#0062f1"
      />

      {/* Inner Bright Accent Blue Pad (dot) */}
      <circle cx="51" cy="56.5" r="4.5" fill="#0062f1" />
    </svg>
  );
}

/**
 * Full PacketSage horizontal logo combination with perfect alignment and typography.
 * Adapts text colors to the current theme while preserving brand integrity.
 */
export function PacketSageLogo({ className = "", iconClassName = "w-8 h-8", forceLight = false }: LogoProps) {
  return (
    <div className={`flex flex-col select-none ${className}`}>
      <div className="flex items-center gap-2.5">
        <PacketSageIcon className={iconClassName} />
        <div className="flex items-baseline text-lg tracking-tight leading-none">
          {/* "Packet" - Premium navy blue in light mode, off-white in dark mode using CSS variable */}
          <span className={`font-extrabold transition-colors duration-150 ${forceLight ? 'text-white' : 'text-logo-packet'}`}>
            Packet
          </span>
          {/* "Sage" - Regular, bright accent blue */}
          <span className="font-normal text-[#0062f1] ml-0.5">
            Sage
          </span>
        </div>
      </div>
      <span className={`text-[8.5px] font-semibold tracking-wider uppercase mt-1.5 pl-1 block whitespace-nowrap ${forceLight ? 'text-slate-400/80' : 'text-text-muted'}`}>
        Network Forensic Workspace
      </span>
    </div>
  );
}
