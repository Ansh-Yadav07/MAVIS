// SAMPLE DATA. Every flow and score in this file is generated for interface design.
// None of it is model output: no MAVIS model has been trained yet.
// Timestamps follow the CIC-IDS2017 capture week (3–7 July 2017) so the replay reads
// like the dataset, and each attack class appears on the day the dataset recorded it.
// IP addresses use private and documentation ranges (RFC 1918 / RFC 5737) only.

export const SAMPLE_NOTICE =
  'Sample flows and scores generated in the browser for design purposes. They are not MAVIS model output.';

// Cut-off used only for the sample autoencoder scores. The real code defines none yet.
export const SAMPLE_AE_THRESHOLD = 0.35;

function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(2017_07_03);
const between = (a, b) => a + (b - a) * rand();
const int = (a, b) => Math.floor(between(a, b + 1));
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const gauss = () => {
  let u = 0, v = 0;
  while (u === 0) u = rand();
  while (v === 0) v = rand();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
};

export const DAYS = [
  { id: 'mon', label: 'Mon 3 Jul', date: '2017-07-03' },
  { id: 'tue', label: 'Tue 4 Jul', date: '2017-07-04' },
  { id: 'wed', label: 'Wed 5 Jul', date: '2017-07-05' },
  { id: 'thu', label: 'Thu 6 Jul', date: '2017-07-06' },
  { id: 'fri', label: 'Fri 7 Jul', date: '2017-07-07' },
];

const INTERNAL = Array.from({ length: 18 }, (_, i) => `192.168.10.${[3, 5, 8, 9, 12, 14, 15, 16, 17, 19, 25, 50, 51, 2, 4, 6, 7, 1][i]}`);
const EXTERNAL = [
  '203.0.113.14', '203.0.113.77', '198.51.100.23', '198.51.100.140', '192.0.2.61',
  '192.0.2.200', '203.0.113.201', '198.51.100.9', '192.0.2.18', '203.0.113.95',
];
const ATTACKER = '203.0.113.73';

const SERVICES = {
  21: 'FTP', 22: 'SSH', 53: 'DNS', 80: 'HTTP', 123: 'NTP', 137: 'NetBIOS', 139: 'SMB',
  443: 'HTTPS', 444: 'Meterpreter', 445: 'SMB', 8080: 'HTTP-alt', 3268: 'LDAP-GC', 389: 'LDAP',
};
export const serviceFor = (port) => SERVICES[port] || (port < 1024 ? 'Well-known' : 'Ephemeral');

// Each profile: day, hour window, destination port(s), protocol, feature generator, score bias.
const PROFILES = {
  'BENIGN': { weight: 0, ports: [443, 80, 53, 443, 443, 123, 139, 445, 389], proto: null, bias: 0 },
  'FTP-Patator': { day: 'tue', hours: [9.3, 10.3], ports: [21], proto: 'TCP', bias: 0.55, cls: 'Brute force' },
  'SSH-Patator': { day: 'tue', hours: [14, 15], ports: [22], proto: 'TCP', bias: 0.5, cls: 'Brute force' },
  'DoS slowloris': { day: 'wed', hours: [9.7, 10.2], ports: [80], proto: 'TCP', bias: 0.62, cls: 'Denial of service' },
  'DoS Slowhttptest': { day: 'wed', hours: [10.2, 10.6], ports: [80], proto: 'TCP', bias: 0.6, cls: 'Denial of service' },
  'DoS Hulk': { day: 'wed', hours: [10.7, 11.4], ports: [80], proto: 'TCP', bias: 0.78, cls: 'Denial of service' },
  'DoS GoldenEye': { day: 'wed', hours: [11.2, 11.4], ports: [80], proto: 'TCP', bias: 0.72, cls: 'Denial of service' },
  'Heartbleed': { day: 'wed', hours: [15.3, 15.6], ports: [444], proto: 'TCP', bias: 0.92, cls: 'Exploit' },
  'Web Attack – Brute Force': { day: 'thu', hours: [9.3, 10], ports: [80], proto: 'TCP', bias: 0.35, cls: 'Web attack' },
  'Web Attack – XSS': { day: 'thu', hours: [10.2, 10.7], ports: [80], proto: 'TCP', bias: 0.38, cls: 'Web attack' },
  'Web Attack – Sql Injection': { day: 'thu', hours: [10.7, 10.9], ports: [80], proto: 'TCP', bias: 0.45, cls: 'Web attack' },
  'Infiltration': { day: 'thu', hours: [14.3, 15.6], ports: [444, 445, 139], proto: 'TCP', bias: 0.66, cls: 'Infiltration' },
  'Bot': { day: 'fri', hours: [10, 11], ports: [8080], proto: 'TCP', bias: 0.48, cls: 'Botnet' },
  'PortScan': { day: 'fri', hours: [13.9, 14.6], ports: null, proto: 'TCP', bias: 0.58, cls: 'Reconnaissance' },
  'DDoS': { day: 'fri', hours: [15.9, 16.4], ports: [80], proto: 'TCP', bias: 0.84, cls: 'Denial of service' },
};

export const ATTACK_CLASS = Object.fromEntries(
  Object.entries(PROFILES).map(([k, v]) => [k, v.cls || 'Benign'])
);

// How many sample attack flows to create per label (scaled loosely to the dataset's mix).
const ATTACK_COUNTS = {
  'FTP-Patator': 16, 'SSH-Patator': 14, 'DoS slowloris': 10, 'DoS Slowhttptest': 9, 'DoS Hulk': 34,
  'DoS GoldenEye': 12, 'Heartbleed': 3, 'Web Attack – Brute Force': 8, 'Web Attack – XSS': 6,
  'Web Attack – Sql Injection': 3, 'Infiltration': 5, 'Bot': 9, 'PortScan': 30, 'DDoS': 28,
};
const BENIGN_COUNT = 520;

const FEATURE_KEYS = [
  'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Bytes/s', 'Flow Packets/s',
  'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow IAT Mean', 'SYN Flag Count',
  'PSH Flag Count', 'Init_Win_bytes_forward', 'Down/Up Ratio',
];

// Illustrative benign medians, used to phrase "x times the usual value" in the sample explanation.
export const BENIGN_BASELINE = {
  'Flow Duration': 1.6e6, 'Total Fwd Packets': 6, 'Total Backward Packets': 5, 'Flow Bytes/s': 4.1e3,
  'Flow Packets/s': 38, 'Fwd Packet Length Mean': 62, 'Bwd Packet Length Mean': 118, 'Flow IAT Mean': 2.4e5,
  'SYN Flag Count': 0, 'PSH Flag Count': 0.4, 'Init_Win_bytes_forward': 8192, 'Down/Up Ratio': 1,
};

function featuresFor(label) {
  const f = {};
  const jitter = (v, s = 0.35) => Math.max(0, v * Math.exp(gauss() * s));
  for (const k of FEATURE_KEYS) f[k] = jitter(BENIGN_BASELINE[k] || 1, 0.6);
  f['SYN Flag Count'] = rand() < 0.08 ? 1 : 0;
  f['PSH Flag Count'] = rand() < 0.4 ? 1 : 0;
  switch (label) {
    case 'DoS Hulk': case 'DDoS': case 'DoS GoldenEye':
      f['Flow Packets/s'] = jitter(2400); f['Flow Bytes/s'] = jitter(1.9e5); f['Flow IAT Mean'] = jitter(900);
      f['Total Fwd Packets'] = jitter(3); f['Bwd Packet Length Mean'] = jitter(1800, 0.2); f['Down/Up Ratio'] = jitter(0.3);
      break;
    case 'DoS slowloris': case 'DoS Slowhttptest':
      f['Flow Duration'] = jitter(9.8e7, 0.2); f['Flow IAT Mean'] = jitter(1.1e7, 0.2); f['Flow Packets/s'] = jitter(0.4);
      f['Bwd Packet Length Mean'] = 0; f['Total Backward Packets'] = int(0, 1);
      break;
    case 'PortScan':
      f['Flow Duration'] = jitter(60, 0.5); f['Total Fwd Packets'] = 1; f['Total Backward Packets'] = 1;
      f['SYN Flag Count'] = 1; f['Fwd Packet Length Mean'] = 0; f['Bwd Packet Length Mean'] = 0;
      f['Init_Win_bytes_forward'] = 1024; f['Flow Packets/s'] = jitter(33000);
      break;
    case 'FTP-Patator': case 'SSH-Patator':
      f['Total Fwd Packets'] = jitter(22, 0.2); f['Total Backward Packets'] = jitter(33, 0.2); f['PSH Flag Count'] = 1;
      f['Fwd Packet Length Mean'] = jitter(14, 0.2); f['Init_Win_bytes_forward'] = 29200; f['Flow Duration'] = jitter(6e6, 0.3);
      break;
    case 'Heartbleed':
      f['Bwd Packet Length Mean'] = jitter(16000, 0.05); f['Flow Bytes/s'] = jitter(9.4e5, 0.1); f['Flow Duration'] = jitter(1.2e8, 0.05);
      f['Total Backward Packets'] = jitter(2700, 0.1); f['Down/Up Ratio'] = jitter(1.6);
      break;
    case 'Infiltration':
      f['Flow Duration'] = jitter(4.4e7); f['Bwd Packet Length Mean'] = jitter(640); f['Total Backward Packets'] = jitter(70); f['Down/Up Ratio'] = jitter(3.2);
      break;
    case 'Bot':
      f['Flow IAT Mean'] = jitter(6e6, 0.15); f['Fwd Packet Length Mean'] = jitter(205, 0.15); f['Init_Win_bytes_forward'] = 8192;
      break;
    default:
      if (label.startsWith('Web Attack')) {
        f['Fwd Packet Length Mean'] = jitter(420); f['Total Fwd Packets'] = jitter(4); f['Flow Duration'] = jitter(5.4e6); f['PSH Flag Count'] = 1;
      }
  }
  return f;
}

// Turns a 0..1 "suspicion" level into each detector's native score scale.
function scoresFor(level, label) {
  const n = () => gauss() * 0.09;
  // Some attack families are known to be hard for density methods (low-volume web attacks)
  // and some for isolation (long slow flows); vary per model so disagreement exists.
  const tweak = {
    if: label.startsWith('DoS slow') ? -0.25 : 0,
    lof: label.startsWith('Web Attack') ? -0.22 : label === 'PortScan' ? 0.12 : 0,
    ae: label === 'Bot' ? 0.18 : 0,
  };
  const l = (m) => Math.min(1, Math.max(0, level + tweak[m] + n()));
  return {
    if: +((l('if') - 0.42) * 0.38).toFixed(4),   // roughly −0.16 … +0.22, outlier above 0
    lof: +((l('lof') - 0.45) * 2.6).toFixed(4),  // roughly −1.2 … +1.4, outlier above 0
    ae: +(0.02 + Math.pow(l('ae'), 2.2) * 1.4).toFixed(4), // MSE, sample cut-off 0.35
  };
}

function protoFor(port, profile) {
  if (profile.proto) return profile.proto;
  if (port === 53 || port === 123 || port === 137) return 'UDP';
  return rand() < 0.03 ? 'ICMP' : 'TCP';
}

const STATUSES = ['New', 'Triaging', 'Escalated', 'Closed', 'False positive'];

export function severityFor(flags, scores) {
  const agree = flags.if + flags.lof + flags.ae;
  const strength = Math.max(scores.if / 0.22, scores.lof / 1.4, scores.ae / 1.42);
  if (agree === 3 && strength > 0.8) return 'critical';
  if (agree === 3 || (agree === 2 && strength > 0.7)) return 'high';
  if (agree === 2) return 'medium';
  if (agree === 1) return 'low';
  return 'none';
}

function makeFlow(i, label, profile) {
  const day = profile.day ? DAYS.find((d) => d.id === profile.day) : pick(DAYS);
  const [h0, h1] = profile.hours || [8.8, 17.2];
  const hour = between(h0, h1);
  const ts = new Date(`${day.date}T00:00:00Z`);
  ts.setUTCSeconds(Math.floor(hour * 3600));

  const isAttack = label !== 'BENIGN';
  const dstPort = profile.ports ? pick(profile.ports) : int(1, 1024);
  const proto = protoFor(dstPort, profile);
  const outbound = !isAttack && rand() < 0.62;
  const src = isAttack
    ? (label === 'Bot' || label === 'Infiltration' ? pick(INTERNAL) : ATTACKER)
    : pick(INTERNAL);
  const dst = isAttack
    ? (label === 'Bot' ? ATTACKER : label === 'Infiltration' ? pick(INTERNAL) : '192.168.10.50')
    : outbound ? pick(EXTERNAL) : pick(INTERNAL);

  // Benign flows mostly sit low; a few noisy ones create believable false positives.
  const level = isAttack
    ? Math.min(1, Math.max(0.15, profile.bias + gauss() * 0.14))
    : Math.max(0, (rand() < 0.06 ? 0.55 : 0.18) + gauss() * 0.12);

  const scores = scoresFor(level, label);
  const flags = { if: scores.if > 0, lof: scores.lof > 0, ae: scores.ae > SAMPLE_AE_THRESHOLD };
  const severity = severityFor(flags, scores);
  const features = featuresFor(label);
  const fwd = Math.round(features['Total Fwd Packets']);
  const bwd = Math.round(features['Total Backward Packets']);
  const bytes = Math.round(fwd * features['Fwd Packet Length Mean'] + bwd * features['Bwd Packet Length Mean']);

  let status = 'New';
  if (severity !== 'none') {
    const r = rand();
    status = day.id === 'fri' ? (r < 0.7 ? 'New' : 'Triaging')
      : r < 0.18 ? 'New' : r < 0.36 ? 'Triaging' : r < 0.52 ? 'Escalated' : r < 0.82 ? 'Closed' : 'False positive';
    if (!isAttack && status === 'Escalated') status = 'False positive';
  }

  return {
    id: `FL-${String(10000 + i).slice(1)}`,
    ts: ts.toISOString(),
    day: day.id,
    src: { ip: src, port: int(32768, 60999) },
    dst: { ip: dst, port: dstPort },
    proto,
    service: proto === 'ICMP' ? 'ICMP' : serviceFor(dstPort),
    durationUs: Math.round(features['Flow Duration']),
    packets: fwd + bwd,
    bytes,
    features,
    label,
    attackClass: ATTACK_CLASS[label],
    scores,
    flags,
    agree: flags.if + flags.lof + flags.ae,
    severity,
    status,
  };
}

function build() {
  const flows = [];
  let i = 1;
  for (let k = 0; k < BENIGN_COUNT; k++) flows.push(makeFlow(i++, 'BENIGN', PROFILES.BENIGN));
  for (const [label, n] of Object.entries(ATTACK_COUNTS)) {
    for (let k = 0; k < n; k++) flows.push(makeFlow(i++, label, PROFILES[label]));
  }
  flows.sort((a, b) => a.ts.localeCompare(b.ts));
  flows.forEach((f, idx) => { f.id = `FL-${String(idx + 1).padStart(4, '0')}`; });
  return flows;
}

export const SAMPLE_FLOWS = build();
export const STATUS_OPTIONS = STATUSES;
export const SAMPLE_FEATURE_KEYS = FEATURE_KEYS;

// Analysis runs shown in the activity feed. Sample, like the flows above.
export const SAMPLE_ACTIVITY = [
  { ts: '2017-07-07T16:40:00Z', kind: 'run', text: 'Sample replay finished for Fri 7 Jul', meta: 'Design data' },
  { ts: '2017-07-07T16:22:00Z', kind: 'alert', text: 'DDoS burst against 192.168.10.50 flagged by all three detectors', meta: 'Sample event' },
  { ts: '2017-07-07T14:31:00Z', kind: 'alert', text: 'Port sweep from 203.0.113.73 across 900+ ports', meta: 'Sample event' },
  { ts: '2017-07-07T10:48:00Z', kind: 'note', text: 'Bot beaconing pattern escalated for review', meta: 'Sample note' },
  { ts: '2017-07-06T15:02:00Z', kind: 'alert', text: 'Infiltration flows over SMB from an internal host', meta: 'Sample event' },
  { ts: '2017-07-05T15:21:00Z', kind: 'alert', text: 'Heartbleed response sizes far above any benign flow', meta: 'Sample event' },
];
