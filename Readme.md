# 🛡️ MAVIS
## Multi-Attack Vector Intelligence System

> An explainable, behaviour-based network intrusion detection system: it learns what normal traffic looks like, flags known attacks and never-seen-before behaviour, explains every alert, and responds by severity.

---

## 📌 Overview

MAVIS watches **network flows** (one summary row per conversation: duration, packet counts and sizes, timing, TCP flags; no payloads) and decides for each flow whether it is normal, a known attack, or suspicious new behaviour.

It combines four anomaly detectors, an attack classifier and host-behaviour rules into one engine. Every alert comes with:
- a **0–100 risk score** and severity,
- the **reason** (which features were abnormal and which detectors agreed),
- a **MITRE ATT&CK** mapping,
- recommended **response steps**.

A live console shows your machine's real traffic, raises an alarm when the system is under attack, and records the automatic response (block, notify, isolate) from detection to resolution.

---

## 🎯 Why MAVIS

| Approach | Limitation | What MAVIS adds |
|---|---|---|
| Rate limiters / WAF | See volume per IP only; fooled by distributed or slow attacks | Judges *behaviour*, independent of IP; catches slow scans and brute force |
| Signature IDS (Snort, Suricata) | Miss anything without a rule | Anomaly detectors flag unknown behaviour |
| Commercial AI (Darktrace, Vectra) | Expensive, black box | Free and open, every alert explained, you set the false-alarm budget |

Intended for security analysts in small and medium organisations, universities, managed security providers, and for students and researchers.

---

## 🧠 How it works

```text
packets ─▶ flow meter (sensor) ─▶ 69 flow features ─▶ MAVIS engine ──────────────▶ verdict, risk, reason
                                                     │
          ┌───────────────────── novelty ────────────┤──────── recognition ─────────┐
          │ Isolation Forest · LOF · Autoencoder ·   │  gradient-boosted classifier │
          │ ECOD  (trained on normal traffic only)   │  (names the attack family)   │
          └───────────────── combined under one false-positive "alert budget" ─────┘
                                                     │
                     host-behaviour rules: fan-out scans, floods, DDoS, insider / lateral movement
                                                     │
                     incidents (active → contained → resolved) ─▶ automatic response by severity
```

- **Two detection paths share one alert budget** (default 1 % false positives): the classifier recognises known attacks, and the anomaly ensemble raises *novel* alerts for behaviour that matches nothing known.
- **Learn my network:** a short learning window recalibrates the thresholds on your own normal traffic, without retraining the models.
- **Response by severity:** low → logged, medium → notified, high → block the sources, critical → block plus upstream DDoS protection or host isolation. Blocking defaults to **dry-run**; pf (macOS), nftables (Linux) and Cloudflare backends are available.

---

## 📊 Results (CIC-IDS2017, 1 % false-positive budget)

| | ROC-AUC | Recall | F1 |
|---|---|---|---|
| **MAVIS engine** (classifier + anomaly ensemble) | 0.9995 | 0.9995 | 0.982 |
| Anomaly ensemble only (IF + LOF + AE + ECOD) | 0.958 | 0.522 | 0.670 |

- Known attack families are caught at 97–100 %. This number is optimistic: training and test flows come from the same capture week.
- **Zero-day test** (classifier never sees the family): DDoS 64 %, WebAttack 49 %, while Bot, BruteForce and PortScan stay below 1 % per flow. Scans and floods are covered by the host-behaviour rules instead.

Details, data and caveats: [docs/MODEL_CARD.md](docs/MODEL_CARD.md).

---

## 🚀 Getting started

Requirements: Python 3.9, macOS or Linux.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Train the engine (once)

Put the CIC-IDS2017 MachineLearningCSV files under `dataset/` (see [docs/DATA.md](docs/DATA.md)), then:

```bash
.venv/bin/python scripts/preprocess.py        # clean, split, scale        -> dataset/processed/
.venv/bin/python scripts/train_evaluate.py    # train IF, LOF, AE, ECOD     -> results/models/
.venv/bin/python scripts/build_engine.py      # build the MAVIS engine      -> results/engine/
.venv/bin/python scripts/export_frontend.py   # engine facts for the console -> frontend/data/engine.json
```

### Live monitoring and demo

```bash
./scripts/start.sh                              # console + API + sensor on your network (asks for your password once)
.venv/bin/python scripts/simulate.py story      # 3-minute attack story: scan, brute force, DDoS, insider
```

1. Open http://localhost:8000. The console starts at zero and fills with your machine's real traffic.
2. In the **Learning** panel, click **Start learning** and use the machine normally until it says *Calibrated on your network*.
3. Run the simulator. Watch the **Network flow** map and **Attack Graph**, the red *UNDER ATTACK* alarm (turn on **Sound** in the top bar for the beep), and the incident timeline in **Incidents**.

The simulator **never sends packets**: it posts synthetic flow records, built from real CIC-IDS2017 attack flows, to the local API only. Single scenarios: `ddos`, `dos`, `portscan`, `bruteforce`, `webattack`, `botnet`, `insider`, `office`.

Other tools:
- `.venv/bin/python scripts/analyze.py flows.csv`: analyse a CICFlowMeter CSV from the terminal.
- Role rules for insider detection: copy `config/roles.example.json` to `config/roles.json`.
- Response settings: in the console (Settings), or `config/response.json` (from `config/response.example.json`).

### Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests -q
```

---

## 🗂️ Project layout

```text
src/data/       loading and preprocessing of CICFlowMeter flows
src/models/     Isolation Forest, LOF, Autoencoder, ECOD
src/engine/     MAVIS engine: fusion, calibration, explanations, MITRE knowledge
src/live/       live pipeline, host profiles (insider / scan / flood rules), incidents
src/response/   blocking and notification (dry-run, pf, nftables, Cloudflare, Slack)
src/sensor/     packet-to-flow meter used by scripts/sensor.py
scripts/        training, engine build, server, sensor, simulator, start.sh
frontend/       analyst console (plain HTML, CSS and ES modules)
docs/           DATA, MODEL_CARD, LIVE_SPEC, DEMO_SPEC
```

---

## ⚠️ Limits and responsible use

- The models were trained on 2017 lab traffic; always run the learning step on your own network.
- MAVIS detects and recommends; it is not an inline blocker. Large floods must be absorbed upstream (ISP, CDN).
- Only monitor networks you own or are authorised to monitor.
