const nf = new Intl.NumberFormat('en-US');
export const fmtInt = (n) => nf.format(Math.round(n));
export const fmtPct = (n, d = 1) => `${(n * 100).toFixed(d)}%`;

export function fmtCompact(n) {
  const a = Math.abs(n);
  if (a >= 1e9) return `${(n / 1e9).toFixed(a >= 1e10 ? 0 : 1)}B`;
  if (a >= 1e6) return `${(n / 1e6).toFixed(a >= 1e7 ? 1 : 2)}M`;
  if (a >= 1e3) return `${(n / 1e3).toFixed(a >= 1e4 ? 0 : 1)}k`;
  return `${Math.round(n)}`;
}

export function fmtBytes(b) {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

export function fmtDurationUs(us) {
  if (us < 1000) return `${Math.round(us)} µs`;
  if (us < 1e6) return `${(us / 1000).toFixed(1)} ms`;
  if (us < 6e7) return `${(us / 1e6).toFixed(2)} s`;
  return `${(us / 6e7).toFixed(1)} min`;
}

export function fmtFeature(v) {
  if (v === 0) return '0';
  const a = Math.abs(v);
  if (a >= 1e5 || a < 0.01) return v.toExponential(2);
  if (a >= 100) return fmtInt(v);
  return v.toFixed(2);
}

export const fmtScore = (v) => (v >= 0 ? '+' : '−') + Math.abs(v).toFixed(3);

// Capture timestamps are displayed exactly as recorded (UTC), so the replay matches the dataset files.
export function fmtTime(iso, opts = {}) {
  const d = new Date(iso);
  const time = d.toISOString().slice(11, opts.seconds === false ? 16 : 19);
  if (opts.date === false) return time;
  const day = d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' });
  return `${day} ${time}`;
}
