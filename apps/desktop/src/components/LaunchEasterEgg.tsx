import { useEffect, useState } from "react";

interface LaunchEasterEggProps {
  launchKey: number;
}

const STAGES = [
  "T+00:00 · IGNITION · JaxCore 引擎点火",
  "T+00:01 · PASSING MAX-Q · 突破最大动压!",
  "T+00:02 · ORBIT NOMINAL · SPKI 护盾全开",
];

/**
 * Playful non-blocking aerospace Easter egg triggered by clicking the MaxQ emblem 5 times
 * or pressing "模拟 Max-Q 升空" in the About / Lab tab.
 */
export function LaunchEasterEgg({ launchKey }: LaunchEasterEggProps) {
  const [visible, setVisible] = useState(false);
  const [stageIdx, setStageIdx] = useState(0);

  useEffect(() => {
    if (launchKey <= 0) return;
    setVisible(true);
    setStageIdx(0);
    const t1 = setTimeout(() => setStageIdx(1), 750);
    const t2 = setTimeout(() => setStageIdx(2), 1650);
    const t3 = setTimeout(() => setVisible(false), 2850);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [launchKey]);

  if (!visible) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-50 overflow-hidden">
      {/* Stage Telemetry Banner */}
      <div className="fixed left-1/2 top-5 -translate-x-1/2">
        <div
          className="mq-enter flex items-center gap-2.5 rounded-full px-4 py-2 text-xs font-semibold shadow-sm"
          style={{
            background: "linear-gradient(135deg, var(--mq-accent), var(--mq-accent-2))",
            color: "#ffffff",
          }}
        >
          <span className="h-2 w-2 rounded-full bg-white" />
          <span className="font-mono-tabular">{STAGES[stageIdx]}</span>
        </div>
      </div>

      {/* Flat Geometric Periwinkle Rocket Flying Diagonally Across Viewport */}
      <div key={launchKey} className="mq-rocket-arc fixed left-0 top-1/2">
        <svg width="88" height="44" viewBox="0 0 88 44" fill="none" xmlns="http://www.w3.org/2000/svg">
          {/* Exhaust ribbon */}
          <path d="M4 22L28 16V28L4 22Z" fill="#A5B4FC" fillOpacity="0.65" />
          <path d="M13 22L28 18.5V25.5L13 22Z" fill="#C4B5FD" />
          {/* Rocket body */}
          <path
            d="M28 13H62C71 13 80 18 84 22C80 26 71 31 62 31H28V13Z"
            fill="#6B7CFF"
          />
          {/* Fins */}
          <path d="M28 13L20 5H34L40 13H28Z" fill="#9281FF" />
          <path d="M28 31L20 39H34L40 31H28Z" fill="#9281FF" />
          {/* Window */}
          <circle cx="56" cy="22" r="5" fill="#FFFFFF" />
          <circle cx="56" cy="22" r="2.6" fill="#A5B4FC" />
        </svg>
      </div>
    </div>
  );
}
