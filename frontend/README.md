# MAVIS frontend

The analyst console for MAVIS. Plain HTML, CSS and ES modules: no framework, no build step, no backend.

```bash
# from the repo root
python3 -m http.server 8000 --directory frontend
# open http://localhost:8000
```

ES modules do not load from `file://`, so open it through any static server.

## What is real and what is sample

Every number in the UI carries a tag that says where it came from.

| Tag | Source | Files |
|---|---|---|
| **Measured** | `reports/raw_data_profile.json` (row counts, labels, missing and infinite values, duplicates, constant columns) | `src/data/dataset-profile.js` (generated) |
| **From code** | Model classes and parameters in `src/models/*.py` | `src/data/model-registry.js` |
| **Not built** | Stages described in the root Readme that have no code yet (preprocessing, training run, fusion / risk engine) | `src/data/pipeline-status.js` |
| **Sample** | Flows, detector scores, severities, statuses and activity generated in the browser for design | `src/data/sample/events.js` |

No model has been trained in this repository, so there are no real detections, scores or evaluation metrics. The UI never presents sample data as model output, and it never claims live capture: the Network Traffic replay is labelled as simulated.

Regenerate the measured profile after re-running the profiler:

```bash
node frontend/tools/build-profile.mjs
```

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
  data/                 measured profile, model registry, pipeline status, sample data, access layer
  views/                overview, network, threats, explorer, models, dataset, reports, settings
tools/build-profile.mjs regenerates src/data/dataset-profile.js
```

Views compose components and never define new looks. Charts are hand-drawn SVG at the container's real width, redrawn on resize, sharing one tooltip.

## Connecting real results later

When the pipeline produces per-flow scores, replace `src/data/sample/events.js` with a module (or a `fetch`) that returns the same shape:

```js
{ id, ts, day, src: { ip, port }, dst: { ip, port }, proto, service, durationUs, packets, bytes,
  features: { 'Flow Duration': …, … }, label, attackClass,
  scores: { if, lof, ae },          // native units: −decision_function for IF/LOF, MSE for AE
  flags: { if, lof, ae },           // score above each detector's cut-off
  agree, severity, status }
```

Then drop the sample tags on the panels that read it, set the autoencoder cut-off in `components/security.js`, and replace the sample severity rule once the fusion engine exists.

## Accessibility and motion

Keyboard: `/` focuses search, arrows move through menus and tabs, `Enter` opens a row, `Esc` closes overlays and focus returns to where it was. Severity uses shape and label as well as colour. Motion is short CSS transitions and entrance animations; `prefers-reduced-motion` and the Settings motion toggle turn it off.
