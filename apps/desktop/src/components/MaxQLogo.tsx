import { useId } from "react";

interface MaxQLogoProps {
  size?: number;
  className?: string;
  interactive?: boolean;
  onClick?: () => void;
  title?: string;
}

/**
 * Official MaxQ vector brand mark:
 * Soft periwinkle blue-violet squircle housing a crisp geometric orbital `Q`
 * whose tail launches upward-right as an aerodynamic Max-Q delta arrow.
 */
export function MaxQLogo({
  size = 38,
  className = "",
  interactive = false,
  onClick,
  title,
}: MaxQLogoProps) {
  const gradId = useId();
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      disabled={!onClick}
      className={`group relative inline-flex shrink-0 items-center justify-center rounded-2xl focus:outline-none ${
        interactive ? "cursor-pointer transition-transform duration-200 hover:scale-105 active:scale-95" : "cursor-default"
      } ${className}`}
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-label="MaxQ Logo"
      >
        <defs>
          <linearGradient id={gradId} x1="8" y1="6" x2="94" y2="94" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#6A85FF" />
            <stop offset="52%" stopColor="#7A81FF" />
            <stop offset="100%" stopColor="#9478FF" />
          </linearGradient>
        </defs>
        {/* Flat rounded squircle */}
        <rect x="2" y="2" width="96" height="96" rx="24" fill={`url(#${gradId})`} />
        {/* Orbital Q ring with clean aerodynamic gap at upper-right & lower-right */}
        <path
          d="M61.5 29.8C57.6 26.8 52.8 25 47.5 25C34.5 25 24 35.5 24 48.5C24 61.5 34.5 72 47.5 72C51.6 72 55.4 71 58.8 69.2"
          stroke="#FFFFFF"
          strokeWidth="8.6"
          strokeLinecap="butt"
        />
        <path
          d="M67.2 38.2C69.6 41.3 71 44.8 71 48.5C71 54.4 68.8 59.8 65.2 63.9"
          stroke="#FFFFFF"
          strokeWidth="8.6"
          strokeLinecap="butt"
        />
        {/* Aerodynamic upward delta tail (lifts slightly on hover) */}
        <g className={interactive ? "transition-transform duration-200 group-hover:translate-x-[1.5px] group-hover:-translate-y-[1.5px]" : ""}>
          <path
            d="M36.5 55.2L67.6 28.4L62.8 23.6L79.5 20.5L75.4 36.8L70.6 32.1L56.2 49.4C54.3 51.7 54.5 55.1 56.6 57.2L74.8 75.5H63.5L49.2 61.2C45.8 57.8 41.2 55.5 36.5 55.2Z"
            fill="#FFFFFF"
          />
        </g>
      </svg>
    </button>
  );
}
