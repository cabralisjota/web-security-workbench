/* Real server-side training demo: only predefined, fictional fixture comparisons. */
(() => {
  'use strict';
  const section = document.getElementById('security');
  if (!section) return;

  const style = document.createElement('style');
  style.textContent = `
    .modules button.live-module {width:100%;text-align:left;padding:10px 11px;
      background:#153148;border:1px solid #315b79;border-radius:9px;
      color:#edf6ff;font-size:12px;line-height:1.45;cursor:pointer}
    .modules button.live-module:hover,.modules button.live-module:focus-visible {border-color:#65d7df;background:#20415c}
    .modules button.live-module:disabled,.live-runall:disabled {opacity:.65;cursor:wait}
    .live-controls {margin:0 0 16px}
    .live-output {white-space:normal;overflow-wrap:anywhere;margin-top:12px}
    .live-output h3 {margin:0 0 6px;font-size:17px}
    .live-output p {margin:7px 0}
    .live-output pre {white-space:pre-wrap;overflow-wrap:anywhere;max-height:260px;
      overflow:auto;background:#071421;border:1px solid #2b4963;padding:12px;border-radius:9px}
    .live-output details {margin-top:9px}
    .live-output .live-good {color:#7ae3bb}
    .live-output .live-bad {color:#ff8c9c}
    .live-output button {margin-top:9px;padding:9px 12px;background:#1b3853;
      color:#edf6ff;border:1px solid #315b79;border-radius:9px}
  `;
  document.head.appendChild(style);

  const description = section.querySelector('.sectionhead p');
  if (description) description.textContent = 'Run any of the 17 server-side synthetic security training modules. No external website is scanned.';

  const controls = document.createElement('div');
  controls.className = 'card pad live-controls';
  const heading = document.createElement('h2');
  heading.textContent = 'Live training engine on Render';
  const hint = document.createElement('p');
  hint.className = 'sub';
  hint.textContent = 'These are real Python vulnerable-versus-fixed fixture comparisons, not live vulnerability scans. No account or API key required.';
  const runAll = document.createElement('button');
  runAll.className = 'action live-runall';
  runAll.type = 'button';
  runAll.textContent = 'Run all 17 training modules';
  const output = document.createElement('div');
  output.className = 'result live-output';
  output.setAttribute('role', 'status');
  output.setAttribute('aria-live', 'polite');
  output.textContent = 'Choose a module below or run the entire training suite.';
  controls.append(heading, hint, runAll, output);
  const cards = section.querySelector('.two');
  if (cards) cards.before(controls); else section.append(controls);

  function textEl(tag, value, cls) {
    const el = document.createElement(tag);
    el.textContent = value;
    if (cls) el.className = cls;
    return el;
  }
  function download(data, filename) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'}));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function showResult(payload) {
    output.replaceChildren();
    if (payload.result) {
      const r = payload.result;
      output.append(
        textEl('h3', r.title),
        textEl('p', r.passed ? 'PASS — expected vulnerable and fixed behavior reproduced' : 'REVIEW — training comparison did not meet expectations', r.passed ? 'live-good' : 'live-bad'),
        textEl('p', `${r.cwe} · Vulnerable response: HTTP ${r.vulnerable_http} · Fixed response: HTTP ${r.fixed_http} · Control: HTTP ${r.normal_http}`),
        textEl('p', `Risk: ${r.impact}`),
        textEl('p', `Remediation: ${r.remediation}`),
      );
      const details = document.createElement('details');
      details.append(textEl('summary', 'Inspect synthetic evidence'), textEl('pre', JSON.stringify(r.evidence, null, 2)));
      output.append(details);
      const button = textEl('button', 'Download JSON evidence');
      button.type = 'button';
      button.addEventListener('click', () => download(payload, `workbench-${r.key}-synthetic.json`));
      output.append(button);
    } else {
      output.append(
        textEl('h3', `Training complete: ${payload.passed}/${payload.total} comparisons passed`),
        textEl('p', 'All checks executed server-side using predefined fictional inputs. No external targets were contacted.'),
      );
      const details = document.createElement('details');
      details.append(textEl('summary', 'View individual module results'));
      const list = document.createElement('ul');
      payload.results.forEach(r => list.append(textEl('li', `${r.passed ? 'PASS' : 'REVIEW'} — ${r.title} (${r.cwe})`)));
      details.append(list);
      output.append(details);
      const button = textEl('button', 'Download full JSON report');
      button.type = 'button';
      button.addEventListener('click', () => download(payload, 'workbench-17-module-synthetic-report.json'));
      output.append(button);
    }
    output.scrollIntoView({behavior:'smooth',block:'nearest'});
  }
  async function run(path, trigger) {
    trigger.disabled = true;
    output.textContent = 'Executing training comparisons on the Render server…';
    try {
      const response = await fetch(path, {method:'POST', headers:{'Accept':'application/json'}});
      if (!response.ok) throw new Error(`Server returned HTTP ${response.status}`);
      showResult(await response.json());
    } catch (error) {
      output.textContent = `Training request failed: ${error.message}. Please try again.`;
    } finally {
      trigger.disabled = false;
    }
  }
  runAll.addEventListener('click', () => run('/api/training/run-all', runAll));

  fetch('/api/training/modules', {headers:{'Accept':'application/json'}})
    .then(response => {if (!response.ok) throw new Error(`HTTP ${response.status}`); return response.json();})
    .then(data => {
      for (const [group, id] of [['API','api-mod'],['Web','web-mod']]) {
        const container = document.querySelector(`#${id} .modules`);
        if (!container) continue;
        container.replaceChildren();
        data.modules.filter(m => m.group === group).forEach(module => {
          const button = textEl('button', `${module.title} · ${module.cwe}`, 'live-module');
          button.type = 'button';
          button.addEventListener('click', () => run(`/api/training/run/${encodeURIComponent(module.key)}`, button));
          container.append(button);
        });
      }
    })
    .catch(error => {output.textContent = `Could not load training modules: ${error.message}`;});
})();
