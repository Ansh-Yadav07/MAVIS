# MAVIS live mode: shared spec

Live mode lets MAVIS watch real traffic instead of uploaded CSVs:

```text
packets ─▶ sensor (scripts/sensor.py, sudo) ─▶ POST /api/ingest ─▶ serve.py live pipeline
                                                                   ├─ engine.score (verdicts)
                                                                   ├─ host profiles (insider / lateral movement)
                                                                   └─ response manager (block / notify)
console (frontend) ◀─ GET /api/live (poll every 1-2 s) ◀───────────┘
```

All parts are local-first: `serve.py` binds 127.0.0.1. Blocking defaults to **dry-run**.

## 1. Sensor → server: `POST /api/ingest`
Body (JSON):
```json
{"sensor": {"id": "mac-en0", "iface": "en0", "mode": "live|pcap", "started": "ISO-8601"},
 "flows": [ { "<CIC feature name>": number, ...,
              "Src IP": "192.168.1.20", "Dst IP": "192.168.1.50", "Src Port": 51322,
              "Dst Port": 3306, "Protocol": 6, "Timestamp": "2026-10-19T22:31:05.123+00:00" } ]}
```
- Feature names are exactly `data.cic.FEATURES` (CIC-IDS2017 spelling; `Destination Port` is also set).
- Units as CICFlowMeter: durations and IATs in microseconds, lengths in bytes, rates per second.
- Response: `{"accepted": n, "alerts": n, "seq": last_seq}`. Sensor sends a batch every ~1 s (also an empty
  batch as heartbeat so the console knows the sensor is alive).

## 2. Server state: `GET /api/live?since=<seq>`
```json
{"seq": 1234,
 "sensor": {"connected": true, "id": "...", "iface": "en0", "lastSeen": "ISO", "mode": "live"},
 "learning": {"active": false, "startedAt": null, "flows": 0, "target": 3000, "calibrated": false, "calibratedAt": null},
 "stats": {"flows": 0, "alerts": 0, "bySeverity": {}, "byFamily": {}, "byVerdict": {},
           "timeline": [{"t": "ISO second", "flows": 0, "alerts": 0}]},
 "flows":  [ <console flow object + "seq": int, "insider": [ ...insider alert ids ]> ],
 "hosts":  [ {"ip": "...", "flows": 0, "alerts": 0, "maxRisk": 0, "role": null, "services": {"web": 12, "db": 1},
              "peers": 3, "firstSeen": "ISO", "lastSeen": "ISO", "blocked": false} ],
 "insider": [ <insider alert> ],
 "blocks":  [ <block> ],
 "response": <response config (secrets masked)> }
```
- `flows` returns only flows with `seq > since` (max 500 per call); the server keeps the last 5,000 flows,
  200 insider alerts and all hosts seen. Console flow objects use the same shape as `data/mavis.json`
  flows (see `src/engine/frontend.py` `flow_records`), with real `src.ip`, `dst.ip`, `ts`, `proto`, and
  `day: "live"`, `file: "<sensor id>"`.
- `POST /api/live/learn` `{"action": "start", "target": 3000}` | `{"action": "stop"}` | `{"action": "apply"}`:
  collect normal traffic, then `apply` calls `engine.recalibrate(X)` on it and rebuilds host profiles
  from it. Learning never starts on its own: the console asks the user.
- `POST /api/live/reset`: clear live flows, stats, insider alerts (keeps blocks and profiles).

## 3. Insider / lateral-movement alerts (host profiles)
Service classes by destination port:
`web` 80,443,8080,8443 · `dns` 53 · `mail` 25,465,587,110,143,993,995 · `db` 1433,1521,3306,5432,6379,9200,27017 ·
`admin` 22,23,3389,5900,5985,5986 · `file` 21,139,445,2049 · `directory` 88,389,636,3268 · other: `other`.

Insider alert:
```json
{"id": "ins-17", "ts": "ISO", "src": "192.168.1.20", "dst": "192.168.1.50", "dstPort": 3306,
 "kind": "new-service | role-violation | new-internal-peer | fan-out",
 "service": "db", "severity": "high", "risk": 78,
 "title": "192.168.1.20 used a database service for the first time",
 "detail": "Baseline for this host: web, mail, dns (412 flows).",
 "mitre": [{"tactic": "TA0008 Lateral Movement", "technique": "T1021 Remote Services"}],
 "actions": ["..."], "flowId": "live:123"}
```
- Profiles are learned from the learning window (or, if never learned, from the first 10 minutes per host
  with alerts suppressed while a host is younger than that: "warming up").
- `new-service`: a host uses a service class it never used in its baseline; severity high for `db`/`admin`/`file`/`directory`, medium otherwise.
- `role-violation`: `config/roles.json` `{"roles": {"mail-user": {"allow": ["mail","web","dns"]}}, "hosts": {"192.168.1.20": "mail-user"}}`; any other class → high.
- `new-internal-peer`: first contact to an internal (RFC 1918) host on `db`/`admin`/`file` → medium.
- `fan-out`: one host contacts ≥ 20 distinct internal hosts or ≥ 50 distinct ports within 60 s → high (scan / lateral movement).
- `flood`: one source sends ≥ max(100, 4 × its learned peak) flows to one dst:port within 10 s → high (DoS; MITRE T1499).
- `ddos`: one dst:port receives ≥ 200 flows from ≥ 20 distinct sources within 10 s → critical (MITRE T1498). Checked for
  external sources too; per-IP blocking is not suggested for it.
  The kind list above therefore also includes `flood | ddos`.

## 4. Response (blocking)
`src/response/` exposes `ResponseManager(config_path='config/response.json', audit_path='results/response/audit.jsonl')`:
- `config()` / `update_config(patch)`: `{"mode": "suggest|approve|auto", "backend": "dry-run|pf|nftables|cloudflare",
  "ttlMinutes": 60, "allowlist": ["127.0.0.1/32", "<gateway>/32", ...], "maxBlocksPerMinute": 10,
  "autoRules": {"minSeverity": "critical", "minConfidence": "high", "minVotes": 2, "families": ["BruteForce","PortScan","WebAttack","DoS","Bot","Infiltration"]},
  "notify": {"slackWebhook": null}}` (webhook / API tokens come from env vars, never returned unmasked).
- `evaluate(alert_flow) -> {"action": "none|suggest|pending|blocked", "reason": str}` (called by the live pipeline for every alert).
- `block(ip, reason, ttl_minutes=None, source="analyst", alert_id=None) -> block`; `unblock(ip, source="analyst")`;
  `blocks()` (active, expired ones pruned); `pending()`; `approve(ip)`; `reject(ip)`; `audit(limit=200)`.
- Block object: `{"ip", "reason", "createdAt", "expiresAt", "source": "auto|analyst", "alertId", "backend", "status": "active|pending|failed", "error": null}`.
- Safety: never block allowlisted CIDRs, loopback, the machine's own addresses, or broadcast; refuse
  more than `maxBlocksPerMinute` (then notify instead); auto mode only when the alert meets `autoRules`
  and is a *known* family (never `Novel`); a DDoS (many sources) is never blocked per IP: it returns
  `{"action": "suggest", "reason": "distributed attack: enable upstream protection (e.g. Cloudflare Under Attack mode)"}`.
- Backends: `dry-run` (records only, default), `pf` (macOS: `pfctl -t mavis_block -T add <ip>`; needs a pf
  anchor + root, documented, errors reported not raised), `nftables` (Linux: `nft add element inet mavis blocklist { <ip> timeout <ttl>m }`),
  `cloudflare` (IP Access Rules API, token from `CLOUDFLARE_API_TOKEN`, zone from `CLOUDFLARE_ZONE_ID`).
  Optional Slack notification on every block/pending via `MAVIS_SLACK_WEBHOOK`.

HTTP (wired in serve.py): `GET /api/blocks` → `{"blocks": [...], "pending": [...]}` · `POST /api/blocks` `{"ip","reason","ttlMinutes"?,"alertId"?}` ·
`DELETE /api/blocks/<ip>` · `POST /api/blocks/<ip>/approve` · `POST /api/blocks/<ip>/reject` ·
`GET /api/response/config` · `POST /api/response/config` (patch) · `GET /api/response/audit`.

## 5. Known limits
- Sensor features approximate CICFlowMeter (see the `src/sensor/flowmeter.py` docstring for the differences).
- The models were trained on 2017 lab traffic, so always run learning on your own network first.
- Per-flow models miss scans made of tiny flows; the fan-out rule catches those.
- Live capture needs root.
- Blocking backends other than dry-run change real firewall rules.
