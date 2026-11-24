import { useMemo } from "react";

interface SpkiSigilProps {
  seed: string;
  size?: number;
  className?: string;
}

/**
 * Deterministic 5x5 symmetric geometric visual crest derived from a node's real
 * SHA-256 SPKI Base64 fingerprint. Makes MITM certificate drift visually unmistakable
 * at a glance while adding tactile periwinkle personality to every pinned node.
 */
export function SpkiSigil({ seed, size = 28, className = "" }: SpkiSigilProps) {
  const { cells, primary, secondary, bg } = useMemo(() => {
    // Simple deterministic FNV-1a style hash across the SPKI fingerprint string
    let h1 = 0x811c9dc5;
    let h2 = 0x01000193;
    for (let i = 0; i < seed.length; i++) {
      const ch = seed.charCodeAt(i);
      h1 ^= ch;
      h1 = Math.imul(h1, 0x01000193);
      h2 ^= ch + ((i * 31) & 0xff);
      h2 = Math.imul(h2, 0x85ebca6b);
    }

    // Curated flat blue-violet / sky / iris palette triplets
    const palettes: Array<[string, string, string]> = [
      ["#6B7CFF", "#A28EFF", "#EEF0FF"],
      ["#5485FF", "#88A4FF", "#EBF2FF"],
      ["#7F71FF", "#B49BFF", "#F1EEFF"],
      ["#4D96E8", "#7B8CFF", "#EAF4FF"],
      ["#6366F1", "#93A0FF", "#ECEEFF"],
      ["#7A68F0", "#68B5F5", "#EEF1FF"],
    ];
    const [p, s, b] = palettes[Math.abs(h1) % palettes.length];

    // 5x5 horizontally symmetric grid (only 15 bits needed: 3 cols x 5 rows)
    const bits = (h1 >>> 0) ^ ((h2 >>> 0) << 1);
    const grid: Array<{ x: number; y: number; tone: 1 | 2 }> = [];
    for (let row = 0; row < 5; row++) {
      for (let col = 0; col < 3; col++) {
        const bitIdx = row * 3 + col;
        const active = ((bits >>> bitIdx) & 1) === 1 || (row === 2 && col === 2);
        if (active) {
          const tone: 1 | 2 = ((h2 >>> (bitIdx % 24)) & 1) === 1 ? 2 : 1;
          grid.push({ x: col, y: row, tone });
          if (col < 2) {
            grid.push({ x: 4 - col, y: row, tone });
          }
        }
      }
    }
    return { cells: grid, primary: p, secondary: s, bg: b };
  }, [seed]);

  const pad = 4;
  const cell = (36 - pad * 2) / 5;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 rounded-lg ${className}`}
      aria-label="SPKI Visual Fingerprint Sigil"
    >
      <rect width="36" height="36" rx="8" fill={bg} />
      {cells.map((c, idx) => (
        <rect
          key={idx}
          x={pad + c.x * cell + 0.5}
          y={pad + c.y * cell + 0.5}
          width={cell - 1}
          height={cell - 1}
          rx={1.5}
          fill={c.tone === 1 ? primary : secondary}
        />
      ))}
    </svg>
  );
}
