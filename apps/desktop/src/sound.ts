// Optional ultra-soft Web Audio API kinetic chimes (muted by default; zero external audio assets).

let sharedCtx: AudioContext | null = null;

function getCtx(): AudioContext | null {
  if (typeof window === "undefined") return null;
  const Ctor = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  if (!sharedCtx) {
    sharedCtx = new Ctor();
  }
  if (sharedCtx.state === "suspended") {
    void sharedCtx.resume();
  }
  return sharedCtx;
}

export function playSoftTone(kind: "connect" | "disconnect" | "launch" | "ping") {
  const ctx = getCtx();
  if (!ctx) return;
  const now = ctx.currentTime;

  const schedule = (freq: number, start: number, dur: number, peak = 0.045) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, start);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(peak, start + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + dur);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(start);
    osc.stop(start + dur + 0.02);
  };

  if (kind === "connect") {
    schedule(523.25, now, 0.14); // C5
    schedule(659.25, now + 0.07, 0.18); // E5
    schedule(783.99, now + 0.14, 0.24); // G5
  } else if (kind === "disconnect") {
    schedule(587.33, now, 0.12, 0.035);
    schedule(440.0, now + 0.08, 0.18, 0.035);
  } else if (kind === "ping") {
    schedule(740.0, now, 0.09, 0.025);
  } else if (kind === "launch") {
    // Ascending aerospace chime chord
    [440, 554.37, 659.25, 880, 1108.73].forEach((f, idx) => {
      schedule(f, now + idx * 0.065, 0.28, 0.04);
    });
  }
}
