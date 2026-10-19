// Shown instead of the live views when the local API is not reachable (static site):
// what MAVIS is and how to run it.
import { html, mount } from '../core/dom.js';
import { go } from '../core/router.js';
import { on } from '../core/dom.js';
import { pageHead, panel } from './common.js';

export default {
  title: 'MAVIS',
  render(root) {
    mount(root, html`
      ${pageHead({ title: 'MAVIS', sub: 'Multi-Attack Vector Intelligence System: live network anomaly detection with an automatic response.' })}
      <div class="landing">
        ${panel({ title: 'What it is', body: html`<div class="prose">
          <p>MAVIS watches network flows and scores each one with four anomaly detectors trained on benign traffic plus an attack classifier. Alerts are grouped into incidents, and the response follows the severity: log, notify, block the sources, or ask for upstream protection.</p>
          <p>The console shows a live attack graph, a flashing alarm with sound when an attack is under way, and a timeline from detection to containment. Everything runs locally and starts at zero.</p>
          <p><b>This page is the static site.</b> The live console needs the local server, which this host does not have.</p></div>` })}
        ${panel({ title: 'Run it locally', body: html`<ol class="lv-howto-steps">
          <li>Start the server (binds 127.0.0.1 only), then open <span class="mono">http://localhost:8000</span>:<pre>.venv/bin/python scripts/serve.py</pre></li>
          <li>Watch the real traffic of this machine. The sensor needs root to read packets; use your Wi-Fi or Ethernet interface:<pre>sudo .venv/bin/python scripts/sensor.py --iface en0</pre></li>
          <li>Inject a simulated attack. The simulator never sends packets: it posts synthetic flow records to the local API.<pre>.venv/bin/python scripts/simulate.py story</pre></li></ol>
          <p class="panel-meta">Blocking is dry-run by default: nothing touches your firewall until you change the backend in Settings.</p>` })}
        <div><button class="btn btn-primary" data-go="models">See the models</button></div>
      </div>`);
    on(root, 'click', '[data-go]', (_e, b) => go(b.dataset.go));
  },
};
