# MAVIS demo mode: shared spec (supersedes the snapshot console)

Goal: a clean, live-only console that starts at zero, shows the Mac's real traffic (sensor), and
reacts visibly when a **simulated** attack is injected: attack graph, red alarm + beep, automatic
response by severity, and a visible Active → Contained → Resolved lifecycle.

## Safety rule
The simulator **never sends packets**. It posts synthetic *flow records* to the local MAVIS API
(`POST /api/ingest`, localhost only). Attacker addresses are from documentation / private ranges
(198.51.100.0/24, 203.0.113.0/24, 10.66.0.0/16). Blocking stays dry-run unless the user changes it.

## 1. Simulator: `scripts/simulate.py`
- Feature values come from a small **attack library** sampled from CIC-IDS2017 so the trained
  engine detects them for real: `scripts/build_sim_library.py` reads `dataset/*.csv` with
  `data.cic.load_flow_csv`, keeps raw (unscaled) feature rows: ~1,500 benign and up to 400 per
  family (DoS, DDoS, PortScan, BruteForce, WebAttack, Bot, Infiltration), writes
  `data/sim_library.parquet` (committed; keep it < 5 MB).
- Each injected flow = one library row of the chosen family + `Src IP`, `Dst IP`, `Src Port`,
  `Dst Port` (= the row's `Destination Port` unless the scenario sets it), `Protocol` 6,
  `Timestamp` now (UTC ISO). Sensor block: `{"id": "simulator", "iface": "sim", "mode": "sim"}`.
  Batches every 1 s. The simulator must not change `sensor` state of a real sensor: the pipeline
  keeps per-sensor heartbeats (see 2) so the real sensor stays "connected".
- CLI:
  ```
  .venv/bin/python scripts/simulate.py office --minutes 5            # synthetic normal office traffic (if no sudo sensor)
  .venv/bin/python scripts/simulate.py ddos --target 192.168.1.10 --intensity high --seconds 60
  .venv/bin/python scripts/simulate.py portscan|bruteforce|webattack|dos|botnet --target <ip>
  .venv/bin/python scripts/simulate.py insider --host 192.168.1.20 --db 192.168.1.50
  .venv/bin/python scripts/simulate.py story                         # scripted 3-minute demo: calm → scan → brute force → DDoS → insider
  ```
  `--target` default: the Mac's primary IPv4 (fallback 192.168.1.10). Intensity low/medium/high
  sets flows/s (e.g. DDoS 40/200/800 flows/s from 60/300/1000 sources). Prints one line per second.

## 2. Server additions (src/live/pipeline.py, scripts/serve.py)
- Per-sensor heartbeats: `sensors: [{id, iface, mode, connected, lastSeen, flows}]`; the top-level
  `sensor` stays the most recent *non-simulator* sensor (or the simulator if it is the only one).
- `GET /api/engine` → `engine_meta(engine)` (src/engine/frontend.py) plus `evaluation`
  (`reports/engine_evaluation.json`, `reports/evaluation_anomaly.json` if present).
- Attack **episodes** (new `src/live/episodes.py`): alerts (flow alerts with verdict ≠ normal and
  insider alerts) are grouped by `(family_or_kind, target_ip)` into episodes:
  `{id, family, title, severity (max), state: active|contained|resolved, target, sources (count),
    topSources [ip...≤10], flows, flowsPerSec (last 10 s), firstSeen, lastSeen, stateSince,
    mitre, actions: [ {ts, kind, detail, backend, ip?} ] }`
  - active: an alert in the last 15 s. contained: response actions taken and alert rate fell
    below 20 % of its peak, or all sources blocked. resolved: no alert for 30 s. Resolved episodes
    are kept (last 50).
- **Auto-response by severity** when an episode opens or escalates (works in every response
  mode; in `suggest` mode actions are recorded as *recommended*, in `auto` they are executed via
  ResponseManager, always respecting its safety rules and dry-run backend):
  - low → `logged`; medium → `notified` (Slack if configured, else recorded);
  - high → `blocked` top sources (≤ 10) via ResponseManager.block (dry-run by default);
  - critical → `blocked` + for DDoS/flood with > 20 sources `upstream-protection` (simulated:
    "Cloudflare Under Attack mode would be enabled"), for insider/infiltration `isolated`
    (simulated host quarantine record).
- **Threat status**: `status: {level: calm|elevated|under-attack, since, headline, activeEpisodes,
  alertsPerSec}`. under-attack if any active episode is critical or alertsPerSec ≥ 20;
  elevated if any active high/medium; else calm.
- `GET /api/live` adds `status`, `episodes` (active first, then recent), `sensors`.
- `POST /api/live/reset` also clears episodes and status. New `POST /api/episodes/<id>/resolve`
  (analyst marks resolved).

## 3. Console (frontend/)
- **Live-only**: remove the CIC snapshot from every view. No `data/mavis.json`; engine facts come
  from `GET api/engine` (fallback: `data/engine.json`, a small file written by
  `scripts/export_frontend.py`, engine meta + evaluation only). Delete `frontend/data/mavis.json`.
- Navigation: Overview (live dashboard) · Attack Graph · Alerts (live queue) · Incidents (episodes +
  insider) · Hosts · Models (compact: detectors, fusion, evaluation numbers) · Settings (incl.
  response mode, sound). Remove: Dataset Analysis, Network Traffic (snapshot), Event Explorer
  (snapshot), Reports (snapshot), Analyze capture, Live Monitor (merged into Overview/Graph).
- Everything starts at **0** and grows with live data. Without the API (static Netlify) show one
  clear page: what MAVIS is + how to run it locally.
- **Alarm**: when `status.level` becomes `under-attack`: full-width red banner (flat
  `--sev-critical`, flashing at ~1 Hz, reduced-motion → steady), headline + target + sources +
  flows/s, buttons "View attack" / "Acknowledge"; a beep (WebAudio, two short tones, repeats every
  5 s while active and not acknowledged/muted). Sound needs one user click to enable (browser
  rule): a "Sound on" toggle in the top bar. `elevated` → amber strip, no sound.
- **Response timeline** per episode: detected → actions (blocked 12 IPs, upstream protection…)
  → contained → resolved, with timestamps; green "Resolved" state.
- **Attack graph**: live force-free layout (no physics library needed): protected hosts in the
  centre column/cluster, external/attacker nodes on an outer ring, edges = flows in the last
  30 s (width ∝ rate), attackers coloured by severity, blocked nodes greyed with a cross, particles
  along active edges. Calm traffic stays subtle; an attack visibly converges on the target.
- Theme rules unchanged (tokens.css; no gradients/glows/purple/emoji).
