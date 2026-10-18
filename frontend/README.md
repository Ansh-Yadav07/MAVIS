# MAVIS frontend

The analyst console for MAVIS. Plain HTML, CSS and ES modules: no framework, no build step, no backend.

```bash
# from the repo root
python3 -m http.server 8000 --directory frontend
# open http://localhost:8000
```

ES modules do not load from `file://`, so open it through any static server.

### Deploying to Netlify

`netlify.toml` at the repo root tells Netlify to publish `frontend/` with no build command. Connect the repo and leave the site's build settings empty (or set publish directory to `frontend`, build command blank). For a manual deploy, drag the `frontend` folder itself onto Netlify Drop, not the whole repo.

## Where the data comes from

Everything the console shows is real:

| Tag | Source |
|---|---|
| **Engine output** | `data/mavis.json`, written by `scripts/export_frontend.py`: the trained MAVIS engine run over every CIC-IDS2017 file. Full-file totals per capture, plus an exported subset of flows (alerts of every family, misses, false positives and normal traffic) with scores, verdicts and explanations. |
| **Evaluated** | `reports/engine_evaluation.json`, `reports/evaluation_anomaly.json`: metrics on held-out flows, embedded in the same file. |
| **Measured** | `reports/raw_data_profile.json` via `src/data/dataset-profile.js` (row counts, labels, missing values). |
| **Your upload** | A CSV analysed live through `scripts/serve.py` (`POST /api/analyze`). Kept for the browser session only. |

The public CIC-IDS2017 ML CSVs have no IP addresses or timestamps, so the console shows destination port/service and capture order instead and never invents either.

Regenerate after retraining:

```bash
python scripts/build_engine.py && python scripts/export_frontend.py
node frontend/tools/build-profile.mjs     # only if the raw profile changed
```

Run with live analysis (upload a capture in the browser):

```bash
python scripts/serve.py      # serves frontend/ + /api on http://localhost:8000
```

The alert budget in the top bar re-applies thresholds the engine calibrated for 0.1 % … 5 % false positives, so verdicts change instantly without re-running models. Analyst edits (status, notes) and preferences stay in this browser's localStorage.

## Structure

```
index.html              shell markup, fonts, stylesheets
styles/
  tokens.css            colours, type scale, spacing, motion (dark default, light variant)
  base.css              reset, focus ring, reduced motion
  shell.css             rail, top bar, provenance strip, responsive navigation
  components.css        buttons, inputs, tabs, tags, severity, tables, drawer, dialog, toast, tooltip
  charts.css            one look for every SVG chart
  views.css             per-section layout only
src/
  main.js               preferences, routing, view mounting
  core/                 dom helpers, formatting, store (localStorage, guarded), hash router
  components/           shell, icons, logo, charts, table, overlays, security vocabulary, flow detail
  data/                 measured profile, model registry, pipeline status, engine-data access layer (reads data/mavis.json)
  views/                overview, network, threats, explorer, models, dataset, reports, settings
tools/build-profile.mjs regenerates src/data/dataset-profile.js
```

Views compose components and never define new looks. Charts are hand-drawn SVG at the container's real width, redrawn on resize, sharing one tooltip.

## Design

"Field instrument": warm paper surfaces, a bottle-green structure colour, one amber signal colour for what needs attention, earthy severity and detector colours (`styles/tokens.css`). Light is the default and a dark variant exists. No gradients, glows or glass.

## Accessibility and motion

Keyboard: `/` focuses search, arrows move through menus and tabs, `Enter` opens a row, `Esc` closes overlays and focus returns to where it was. Severity uses shape and label as well as colour. Motion is short CSS transitions and entrance animations; `prefers-reduced-motion` and the Settings motion toggle turn it off.
