# MAVIS console

A live-only console written as plain ES modules and CSS: no framework, no build step, no npm.
It starts at zero and fills with live data from the local API (`scripts/serve.py`).

## Run

```bash
.venv/bin/python scripts/serve.py                                   # API + this console on http://localhost:8000
sudo .venv/bin/python scripts/sensor.py --iface en0                 # real traffic of this machine
.venv/bin/python scripts/simulate.py story                          # simulated attacks (posts flow records, sends no packets)
```

On a static host without the API the console shows one landing page (what MAVIS is and how to run it)
and the Models page. Engine facts come from `GET api/engine`, falling back to `data/engine.json`.

## Views

Overview, Attack Graph, Alerts, Incidents, Hosts, Models, Settings. The alarm banner (flashing red on
`under-attack`, amber on `elevated`, optional beep, tab-title prefix) is shown on every page.

## Layout

```
index.html
styles/    tokens.css (the only colours), base, shell, components, charts, views, console
src/
  main.js              boot, routing, preferences
  core/                dom helpers, hash router, preference store, formatting
  data/                index.js (engine facts), live.js (polling + actions), model-registry.js
  components/          shell, alarm, attackgraph, flow-detail, overlays, security, block, icons, charts
  views/               one file per page, plus landing.js and common.js
data/engine.json       engine meta and evaluation (written by scripts/export_frontend.py)
```

Rules: colours only from `tokens.css`; no gradients, glows, blur or emoji; every view works at 360 px.
