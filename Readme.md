# 🛡️ MAVIS
## Multi-Attack Vector Intelligence System

> An ML-based network security system for detecting abnormal network behavior and identifying potential cyber threats.

---

## 📌 Overview

**MAVIS (Multi-Attack Vector Intelligence System)** is a Machine Learning-based network security project designed to analyze network traffic and detect suspicious or anomalous behavior.

Traditional security systems often rely heavily on predefined rules and signatures. MAVIS explores a machine-learning-based approach where network traffic is analyzed based on its behavioral characteristics.

The system will process network traffic features, apply multiple Machine Learning techniques, generate anomaly/threat scores, and present the results through an interactive dashboard.

---

## 🎯 Problem Statement

Modern networks generate a huge volume of traffic, making manual monitoring and rule-based detection difficult.

Attackers can also modify their behavior to avoid traditional signatures.

MAVIS aims to address this problem by using Machine Learning to:

- Analyze network traffic behavior
- Detect unusual patterns
- Identify potentially malicious traffic
- Assign a threat/risk score
- Provide useful information to a security analyst
- Visualize detected threats through a dashboard

---

## 💡 Core Idea

MAVIS will analyze network traffic using multiple Machine Learning approaches rather than depending on a single model.

Each model provides a different perspective on whether network behavior is normal or suspicious.

The outputs will then be combined into a MAVIS threat-analysis layer.

### High-Level Pipeline

```text
                 Network Traffic
                        │
                        ▼
              Feature Extraction
                        │
                        ▼
                Data Preprocessing
                        │
                        ▼
              Feature Engineering
                        │
                        ▼
              ┌─────────────────┐
              │  ML Detection   │
              │     Layer       │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    Isolation       Local         Autoencoder
     Forest       Outlier Factor
          │            │            │
          └────────────┼────────────┘
                       ▼
                MAVIS Risk Engine
                       │
                       ▼
             Threat / Risk Score
                       │
              ┌────────┴────────┐
              ▼                 ▼
           Normal            Suspicious
                                │
                                ▼
                         Threat Analysis
                                │
                                ▼
                         MAVIS Dashboard
---

## 🚀 Getting Started

```bash
pip install -r requirements.txt
# put the CIC-IDS2017 CSVs under dataset/ (see docs/DATA.md)
python scripts/preprocess.py         # clean, split and scale      -> dataset/processed/
python scripts/train_evaluate.py     # train IF, LOF, Autoencoder   -> results/models/, reports/evaluation_anomaly.json
python scripts/build_engine.py       # build the MAVIS risk engine  -> results/engine/, reports/engine_evaluation.json
python scripts/export_frontend.py    # engine output for the console -> frontend/data/mavis.json
python scripts/serve.py              # open the console with live analysis at http://localhost:8000
python -m pytest tests
```

- **Analyse any capture from the terminal:** `python scripts/analyze.py flows.csv`
- **Analyse in the browser:** run `python scripts/serve.py`, open *Analyze capture* and drop a CICFlowMeter CSV.
- **Static site:** `frontend/` deploys to Netlify as is and shows the committed engine snapshot; live upload needs `serve.py`.

### Live monitoring

One command (server + sensor on your Mac's network, asks for your password once):

```bash
./scripts/start.sh
```

Or step by step:

```bash
.venv/bin/python scripts/serve.py                         # console + API on http://localhost:8000
sudo .venv/bin/python scripts/sensor.py --iface en0       # watch your network (lo0 = localhost demo)
.venv/bin/python scripts/simulate.py story                 # simulated attacks: posts flow records to the local API only
```

- Open **Live Monitor** in the console.
- Click **Start learning** while normal traffic flows, then **Apply** (learn my network) before judging alerts.
- Insider and lateral-movement alerts compare each host with its own baseline: a new service, role rules in `config/roles.json` (copy from `config/roles.example.json`), and fan-out scans.
- Blocking is dry-run by default. Set the mode and backend in `config/response.json` (copy from `config/response.example.json`). The pf, nftables and Cloudflare backends need admin rights.

Details and the API are in [docs/LIVE_SPEC.md](docs/LIVE_SPEC.md).

See [docs/DATA.md](docs/DATA.md) for the data sources, how to add your own captures, and every preprocessing step.
