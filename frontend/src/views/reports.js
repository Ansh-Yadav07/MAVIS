// Reports: a readable analysis report that mixes measured facts and sample results, each labelled,
// and copies out as Markdown.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtInt, fmtPct, fmtTime } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, hBars } from '../components/charts.js';
import { toast } from '../components/overlays.js';
import { sevBadge, modelStrip, ipText, tagSample, tagReal, tagPlanned, SEV_LABEL } from '../components/security.js';
import { flows, cicSummary, DAYS } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { pageHead, severityRows, severityCounts } from './common.js';

export default {
  title: 'Reports',
  render(root) {
    let scope = 'week';

    const build = () => {
      const all = flows();
      const list = scope === 'week' ? all : all.filter((f) => f.day === scope);
      const flagged = list.filter((f) => f.agree > 0);
      const sev = severityCounts(list);
      const cic = cicSummary();
      const tp = flagged.filter((f) => f.label !== 'BENIGN').length;
      const important = flagged.filter((f) => f.severity === 'critical' || f.severity === 'high').sort((a, b) => b.agree - a.agree || b.ts.localeCompare(a.ts)).slice(0, 6);
      const srcCounts = {};
      flagged.forEach((f) => { srcCounts[f.src.ip] = (srcCounts[f.src.ip] || 0) + 1; });
      const topSrc = Object.entries(srcCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);
      const perModel = MODELS.map((m) => ({ m, n: list.filter((f) => f.flags[m.id]).length, only: list.filter((f) => f.flags[m.id] && f.agree === 1).length }));
      const scopeLabel = scope === 'week' ? '3–7 July 2017' : DAYS.find((d) => d.id === scope).label + ' 2017';
      return { list, flagged, sev, cic, tp, important, topSrc, perModel, scopeLabel };
    };

    const paint = () => {
      const r = build();
      mount($('#report', root), html`
        <article class="report" aria-label="Analysis report">
          <header class="report-head">
            <div class="report-kicker">MAVIS analysis report</div>
            <h2 class="report-title">CIC-IDS2017 · ${r.scopeLabel}</h2>
            <div class="report-meta"><span>${tagReal()} dataset facts</span><span>${tagSample()} detection results</span><span>${tagPlanned()} fusion engine</span></div>
          </header>

          <section class="report-sec">
            <h3>1. Summary</h3>
            <p>The CIC-IDS2017 export contains <b>${fmtInt(r.cic.rows)}</b> labelled flows across 8 capture files, of which <b>${fmtPct(r.cic.attack / r.cic.rows)}</b> are labelled as attacks. No detector has been trained yet. In the sample run, <b>${fmtInt(r.flagged.length)}</b> of ${fmtInt(r.list.length)} flows were flagged by at least one detector and <b>${fmtInt(r.sev.critical + r.sev.high)}</b> reached high or critical severity.</p>
          </section>

          <section class="report-sec report-two">
            <div>
              <h3>2. Anomaly statistics ${tagSample()}</h3>
              <dl class="kv">
                <dt>Flows analysed</dt><dd class="mono">${fmtInt(r.list.length)}</dd>
                <dt>Flagged</dt><dd class="mono">${fmtInt(r.flagged.length)} (${fmtPct(r.flagged.length / r.list.length)})</dd>
                <dt>Flagged and attack-labelled</dt><dd class="mono">${fmtInt(r.tp)}</dd>
                <dt>Flagged but benign</dt><dd class="mono">${fmtInt(r.flagged.length - r.tp)}</dd>
                <dt>All three agree</dt><dd class="mono">${fmtInt(r.flagged.filter((f) => f.agree === 3).length)}</dd>
              </dl>
            </div>
            <div>
              <h3>3. Severity distribution ${tagSample()}</h3>
              <div class="chart" id="rp-sev"></div>
            </div>
          </section>

          <section class="report-sec">
            <h3>4. Model comparison ${tagSample()}</h3>
            <div class="table-wrap"><table class="table">
              <thead><tr><th scope="col">Detector</th><th class="r" scope="col">Flagged</th><th class="r" scope="col">Flagged alone</th><th scope="col">Score</th></tr></thead>
              <tbody>${r.perModel.map(({ m, n, only }) => html`<tr><td><span style="display:inline-flex;gap:8px;align-items:center"><span class="mdot" data-m="${m.id}"></span>${m.name}</span></td><td class="r mono">${fmtInt(n)}</td><td class="r mono">${fmtInt(only)}</td><td class="muted">${m.scoreName}</td></tr>`)}</tbody>
            </table></div>
          </section>

          <section class="report-sec">
            <h3>5. Important events ${tagSample()}</h3>
            ${r.important.length ? html`<ul class="report-events">${r.important.map((f) => html`<li><a href="#event-${f.id}">${sevBadge(f.severity)}<span class="mono">${f.id}</span>${ipText(f.src.ip)}<span class="muted">→</span>${ipText(f.dst.ip, f.dst.port)}${modelStrip(f.flags)}<span class="mono muted">${fmtTime(f.ts, { seconds: false })}</span></a></li>`)}</ul>`
              : html`<p class="muted">No high or critical events in this scope.</p>`}
          </section>

          <section class="report-sec">
            <h3>6. Evaluation metrics</h3>
            <p>Precision, recall, F1 and ROC-AUC will be reported here once the detectors are trained and scored on held-out CIC-IDS2017 data. Metrics computed on sample flows are on the <a href="#models">ML Models</a> page and are not a measure of real performance.</p>
          </section>

          <section class="report-sec">
            <h3>7. Dataset information ${tagReal()}</h3>
            <dl class="kv">
              <dt>Source</dt><dd>CIC-IDS2017, 8 CSV files (Monday to Friday captures)</dd>
              <dt>Rows</dt><dd class="mono">${fmtInt(r.cic.rows)} · ${fmtInt(r.cic.benign)} benign · ${fmtInt(r.cic.attack)} attack-labelled</dd>
              <dt>Columns</dt><dd class="mono">${r.cic.columns} (78 features and the Label)</dd>
              <dt>Quality</dt><dd class="mono">${fmtInt(r.cic.missing)} missing · ${fmtInt(r.cic.infinite)} infinite · ${fmtInt(r.cic.dups)} duplicates</dd>
            </dl>
          </section>

          <section class="report-sec">
            <h3>8. Recommendations</h3>
            <ol class="recs">
              <li><b>Clean before training.</b> Remove or impute the ${fmtInt(r.cic.missing)} missing and ${fmtInt(r.cic.infinite)} infinite values, and deduplicate ${fmtInt(r.cic.dups)} repeated rows. ${tagReal('From profile')}</li>
              <li><b>Drop constant columns.</b> Several bulk and flag columns are constant in every file and add nothing for the detectors. ${tagReal('From profile')}</li>
              <li><b>Define the autoencoder cut-off.</b> For example a high percentile of reconstruction error on benign validation data. ${tagPlanned('Open')}</li>
              <li><b>Build the fusion engine.</b> Normalise the three scores to one scale before combining them. ${tagPlanned('Open')}</li>
              ${r.topSrc.length ? html`<li><b>Investigate ${r.topSrc.map(([ip]) => ip).join(', ')}.</b> These sources produced the most flagged flows in the sample run (${r.topSrc.map(([, n]) => fmtInt(n)).join(', ')}). ${tagSample()}</li>` : ''}
            </ol>
          </section>
        </article>`);
      bindChart($('#rp-sev', root), (w) => hBars(w, 0, { rows: severityRows(r.list), label: 'Severity distribution', labelWidth: 78, showShare: true }));
      return r;
    };

    mount(root, html`
      ${pageHead({
        title: 'Reports',
        sub: 'A shareable summary of the dataset, the sample detection run and what to do next.',
        actions: html`
          <label class="visually-hidden" for="rp-scope">Report scope</label>
          <select class="select" id="rp-scope" style="width:auto">
            <option value="week">Full capture week</option>
            ${DAYS.map((d) => html`<option value="${d.id}">${d.label}</option>`)}
          </select>
          <button class="btn btn-primary" data-action="copy-md">${icon('copy')}Copy as Markdown</button>`,
      })}
      <div id="report"></div>`);

    let current = paint();

    on(root, 'change', '#rp-scope', (_e, s) => { scope = s.value; current = paint(); });
    on(root, 'click', '[data-action="copy-md"]', async () => {
      const r = current;
      const md = [
        `# MAVIS analysis report: CIC-IDS2017, ${r.scopeLabel}`, '',
        '> Dataset facts are measured. Detection results are SAMPLE data; no model has been trained yet.', '',
        '## Summary', `- Labelled flows: ${fmtInt(r.cic.rows)} (${fmtPct(r.cic.attack / r.cic.rows)} attack-labelled)`,
        `- Sample flows analysed: ${fmtInt(r.list.length)}; flagged: ${fmtInt(r.flagged.length)}; high or critical: ${fmtInt(r.sev.critical + r.sev.high)}`, '',
        '## Severity (sample)', ...['critical', 'high', 'medium', 'low'].map((s) => `- ${SEV_LABEL[s]}: ${fmtInt(r.sev[s])}`), '',
        '## Model comparison (sample)', '| Detector | Flagged | Flagged alone |', '|---|---:|---:|', ...r.perModel.map(({ m, n, only }) => `| ${m.name} | ${n} | ${only} |`), '',
        '## Important events (sample)', ...r.important.map((f) => `- ${f.id} ${f.severity} ${f.src.ip} -> ${f.dst.ip}:${f.dst.port} (${f.agree}/3 detectors)`), '',
        '## Recommendations', '- Clean missing, infinite and duplicate rows', '- Drop constant columns', '- Define the autoencoder cut-off', '- Build the fusion engine',
      ].join('\n');
      try { await navigator.clipboard.writeText(md); toast('Report copied as Markdown'); }
      catch { toast('Copy is blocked in this view. Select the report text instead.', { tone: 'warn' }); }
    });
  },
};
