'use strict';
// hostlint report: renders the JSON in #report-data. Everything from the
// results is untrusted text and only ever reaches the page as textContent or
// attribute values set through the DOM; links are built from indexes.
(() => {
  const data = JSON.parse(document.getElementById('report-data').textContent);
  const ORDER = ['FAIL', 'ERROR', 'MANUAL', 'WAIVED', 'PASS', 'NOT_APPLICABLE'];
  const NAME = {FAIL: 'FAIL', ERROR: 'ERROR', MANUAL: 'MANUAL', WAIVED: 'WAIVED', PASS: 'PASS', NOT_APPLICABLE: 'N/A'};
  const MARK = {FAIL: '✗', ERROR: '!', MANUAL: '?', WAIVED: '~', PASS: '✓', NOT_APPLICABLE: '–'};
  const PROBLEMS = ['FAIL', 'ERROR', 'MANUAL'];
  const state = {
    shown: new Set(ORDER),
    query: '',
    lang: (navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en',
  };
  const str = (i) => (i ? data.strings[i] : '');
  const title = (o) => (state.lang === 'ko' && o.titleKo) || o.title;

  // cell[p][h]: control index → the host's control result.
  const cell = data.profiles.map(() => data.hosts.map(() => new Map()));
  data.hosts.forEach((h, hi) => h.controls.forEach((hc) => cell[hc.p][hi].set(hc.c, hc)));

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'onclick') e.addEventListener('click', v);
      else if (k === 'oninput') e.addEventListener('input', v);
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === undefined || c === null || c === false) continue;
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
  }

  const badge = (s) => el('span', {class: 'badge s-' + s}, MARK[s] + ' ' + NAME[s]);
  const sev = (s) => (s ? el('span', {class: 'sev sev-' + s}, s) : null);
  const hostLink = (hi) => el('a', {href: '#/host/' + hi}, data.hosts[hi].name);
  const controlLink = (p, c) => el('a', {href: '#/control/' + p + '/' + c}, data.profiles[p].controls[c].id);
  const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');

  function counts(list) {
    const n = Object.fromEntries(ORDER.map((s) => [s, 0]));
    for (const s of list) n[s]++;
    return n;
  }

  // A stacked bar of status counts, with the numbers next to it.
  function bar(n) {
    const total = ORDER.reduce((t, s) => t + n[s], 0);
    const b = el('div', {class: 'bar', role: 'img', 'aria-label': ORDER.filter((s) => n[s]).map((s) => n[s] + ' ' + NAME[s]).join(', ')});
    for (const s of ORDER) {
      if (!n[s]) continue;
      const seg = el('span', {class: 's-' + s, title: n[s] + ' ' + NAME[s]});
      seg.style.width = (100 * n[s] / total) + '%';
      b.append(seg);
    }
    const legend = el('div', {class: 'legend'}, ORDER.filter((s) => n[s]).map((s) => el('span', {class: 'count c-' + s}, n[s] + ' ' + NAME[s])));
    return el('div', {class: 'bars'}, b, legend);
  }

  function hostMatches(h) {
    if (!state.query) return true;
    const q = state.query.toLowerCase();
    const labels = Object.entries(h.labels || {}).map(([k, v]) => k + '=' + v);
    return [h.name, h.os, h.file, ...labels].some((t) => t.toLowerCase().includes(q));
  }

  // ---- toolbar -------------------------------------------------------------

  function toolbar() {
    const chips = ORDER.map((s) => {
      const b = el('button', {type: 'button', class: 'chip s-' + s, 'aria-pressed': String(state.shown.has(s)), onclick: () => {
        if (state.shown.has(s)) state.shown.delete(s); else state.shown.add(s);
        if (state.shown.size === 0) ORDER.forEach((x) => state.shown.add(x));
        refreshToolbar();
        render();
      }}, MARK[s] + ' ' + NAME[s]);
      return b;
    });
    const problems = el('button', {type: 'button', class: 'chip', onclick: () => {
      state.shown = new Set(PROBLEMS);
      refreshToolbar();
      render();
    }}, 'Problems only');
    const all = el('button', {type: 'button', class: 'chip', onclick: () => {
      state.shown = new Set(ORDER);
      refreshToolbar();
      render();
    }}, 'All');
    let timer;
    const search = el('input', {type: 'search', placeholder: 'Filter hosts: name, OS, label', 'aria-label': 'Filter hosts', value: state.query, oninput: (e) => {
      clearTimeout(timer);
      const q = e.target.value.trim();
      timer = setTimeout(() => {
        state.query = q;
        render();
      }, 150);
    }});
    const lang = el('button', {type: 'button', class: 'chip', title: 'Language of control and check titles', onclick: () => {
      state.lang = state.lang === 'ko' ? 'en' : 'ko';
      refreshToolbar();
      render();
    }}, state.lang === 'ko' ? 'EN' : '한국어');
    return el('div', {class: 'tools'}, el('div', {class: 'chips'}, chips, problems, all), search, lang);
  }

  function refreshToolbar() {
    const t = document.getElementById('toolbar');
    const focused = document.activeElement && document.activeElement.type === 'search';
    t.replaceChildren(toolbar());
    if (focused) t.querySelector('input').focus();
  }

  // ---- overview ------------------------------------------------------------

  function overview() {
    const out = [];
    const hosts = data.hosts.map((h, hi) => hi).filter((hi) => hostMatches(data.hosts[hi]));
    out.push(summary(hosts));
    if (data.notes && data.notes.length) {
      out.push(el('section', {class: 'notes'}, el('h2', {}, 'Notes'), el('ul', {}, data.notes.map((n) => el('li', {}, n)))));
    }
    data.profiles.forEach((p, pi) => out.push(profileSection(p, pi, hosts)));
    out.push(hostTable(hosts));
    return out;
  }

  function summary(hosts) {
    const all = [];
    let failing = 0;
    let notRoot = 0;
    for (const hi of hosts) {
      const st = data.hosts[hi].controls.map((c) => c.s);
      all.push(...st);
      if (st.includes('FAIL')) failing++;
      if (!data.hosts[hi].root) notRoot++;
    }
    return el('section', {class: 'summary'},
      el('div', {class: 'tiles'},
        tile(hosts.length, hosts.length === data.hosts.length ? 'hosts' : 'hosts match the filter'),
        tile(failing, 'hosts with a failed control'),
        tile(data.profiles.length === 1 ? data.profiles[0].controls.length : data.profiles.length, data.profiles.length === 1 ? 'controls in ' + data.profiles[0].id : 'profiles'),
        notRoot ? tile(notRoot, 'hosts scanned without root', 'warn') : null),
      el('h2', {}, 'Control results across hosts'),
      bar(counts(all)));
  }

  const tile = (n, label, cls) => el('div', {class: 'tile ' + (cls || '')}, el('strong', {}, String(n)), el('span', {}, label));

  function profileSection(p, pi, hosts) {
    const controls = p.controls.map((c, ci) => ci);
    const statusOf = (hi, ci) => {
      const hc = cell[pi][hi].get(ci);
      return hc ? hc.s : null;
    };
    const rows = hosts.filter((hi) => controls.some((ci) => state.shown.has(statusOf(hi, ci))));
    const cols = controls.filter((ci) => rows.some((hi) => state.shown.has(statusOf(hi, ci))));

    // Controls that fail on most hosts.
    const worst = controls.map((ci) => ({ci, n: hosts.filter((hi) => statusOf(hi, ci) === 'FAIL').length}))
      .filter((x) => x.n > 0).sort((a, b) => b.n - a.n || a.ci - b.ci).slice(0, 10);
    const worstList = worst.length ? el('ol', {class: 'worst'}, worst.map(({ci, n}) => el('li', {},
      controlLink(pi, ci), ' ', title(p.controls[ci]), ' ', sev(p.controls[ci].severity),
      el('span', {class: 'muted'}, ' — fails on ' + n + ' of ' + plural(hosts.length, 'host'))))) : el('p', {class: 'muted'}, 'No control failed.');

    const head = el('tr', {}, el('th', {class: 'corner'}, 'Host'), cols.map((ci) => el('th', {class: 'col', title: title(p.controls[ci])}, controlLink(pi, ci))));
    const body = rows.map((hi) => el('tr', {}, el('th', {class: 'row'}, hostLink(hi)), cols.map((ci) => {
      const s = statusOf(hi, ci);
      if (!s) return el('td', {class: 'none', title: 'not in this host\'s result'}, '');
      const label = data.hosts[hi].name + ' · ' + p.controls[ci].id + ' · ' + NAME[s];
      return el('td', {class: 's-' + s + (state.shown.has(s) ? '' : ' dim')},
        el('a', {href: '#/host/' + hi + '/' + pi + '/' + ci, title: label, 'aria-label': label}, MARK[s]));
    })));
    const matrix = rows.length && cols.length
      ? el('div', {class: 'matrix-wrap'}, el('table', {class: 'matrix'}, el('thead', {}, head), el('tbody', {}, body)))
      : el('p', {class: 'muted'}, 'No host has a control with the selected statuses.');

    return el('section', {class: 'profile'},
      el('h2', {}, p.id, p.title ? ' — ' + p.title : '', el('span', {class: 'muted small'}, ' revision ' + p.revisions.join(', '))),
      el('h3', {}, 'Most failed controls'), worstList,
      el('h3', {}, 'Hosts × controls'), matrix);
  }

  function hostTable(hosts) {
    const rows = hosts.map((hi) => {
      const h = data.hosts[hi];
      const n = counts(h.controls.map((c) => c.s));
      return el('tr', {},
        el('td', {}, hostLink(hi), h.root ? null : el('span', {class: 'tag warn', title: 'Scanned without root: checks that need protected files report ERROR'}, 'not root')),
        el('td', {}, h.os, h.supported ? null : el('span', {class: 'tag', title: 'Not in the tested distribution matrix'}, 'best effort')),
        el('td', {}, Object.entries(h.labels || {}).map(([k, v]) => el('span', {class: 'tag'}, k + '=' + v))),
        ORDER.map((s) => el('td', {class: 'num' + (n[s] && PROBLEMS.includes(s) ? ' c-' + s : '')}, String(n[s]))),
        el('td', {class: 'muted'}, h.scanned));
    });
    return el('section', {},
      el('h2', {}, 'Hosts'),
      el('div', {class: 'table-wrap'}, el('table', {class: 'hosts'},
        el('thead', {}, el('tr', {}, el('th', {}, 'Host'), el('th', {}, 'OS'), el('th', {}, 'Labels'), ORDER.map((s) => el('th', {class: 'num'}, NAME[s])), el('th', {}, 'Scanned'))),
        el('tbody', {}, rows))));
  }

  // ---- one host ------------------------------------------------------------

  function hostPage(hi, focusP, focusC) {
    const h = data.hosts[hi];
    if (!h) return notFound();
    const facts = [
      ['OS', h.os + (h.supported ? '' : ' (best effort: not in the tested matrix)')],
      ['Kernel', h.kernel],
      ['Architecture', h.arch],
      ['Target', h.target],
      ['Scanned', h.scanned + (h.tool ? ' with hostlint ' + h.tool : '')],
      ['Privileges', h.root ? 'root' : 'not root: checks that need protected files report ERROR'],
      ['Labels', Object.entries(h.labels || {}).map(([k, v]) => k + '=' + v).join(', ')],
      ['Result file', h.file],
    ].filter(([, v]) => v);
    const out = [
      el('p', {}, el('a', {href: '#/'}, '← All hosts')),
      el('h2', {}, h.name),
      el('dl', {class: 'facts'}, facts.map(([k, v]) => [el('dt', {}, k), el('dd', {}, v)])),
    ];
    if (h.waivers && h.waivers.length) {
      out.push(el('div', {class: 'callout warn'}, el('strong', {}, 'Waivers that did not apply'),
        el('ul', {}, h.waivers.map((w) => el('li', {}, w.scope + ' ' + w.id + ' (until ' + w.expires + '): ' + w.problem + ' — ' + w.reason)))));
    }
    if (h.collectors && h.collectors.length) {
      out.push(el('div', {class: 'callout'}, el('strong', {}, 'Collectors that saw only part of the host'),
        el('ul', {}, h.collectors.map((c) => el('li', {}, el('code', {}, c.name), ' ' + c.status,
          c.error ? ': ' + c.error : '', c.skipped && c.skipped.length ? ' (skipped: ' + c.skipped.join(', ') + ')' : '')))));
    }
    data.profiles.forEach((p, pi) => {
      const list = h.controls.filter((hc) => hc.p === pi);
      if (!list.length) return;
      out.push(el('h3', {}, p.id), bar(counts(list.map((hc) => hc.s))));
      const shown = list.filter((hc) => state.shown.has(hc.s) || (pi === focusP && hc.c === focusC));
      if (!shown.length) out.push(el('p', {class: 'muted'}, 'No control with the selected statuses.'));
      for (const hc of shown) {
        const c = p.controls[hc.c];
        const focus = pi === focusP && hc.c === focusC;
        const d = el('details', {class: 'control', id: 'c-' + pi + '-' + hc.c, open: focus || undefined},
          el('summary', {}, badge(hc.s), ' ', el('strong', {}, c.id), ' ', title(c), ' ', sev(c.severity)),
          el('p', {class: 'small'}, el('a', {href: '#/control/' + pi + '/' + hc.c}, 'Compare ' + c.id + ' across hosts →')),
          controlBody(h, hc));
        out.push(d);
      }
    });
    return out;
  }

  function controlBody(h, hc) {
    return el('div', {class: 'body'},
      hc.r ? el('p', {class: 'reason'}, str(hc.r)) : null,
      hc.w ? waiver(hc.w) : null,
      hc.x ? el('p', {class: 'muted small'}, 'Evaluated with parameters stricter than the profile\'s (customized).') : null,
      hc.k.map((k) => check(h.checks[k])));
  }

  const waiver = (w) => el('p', {class: 'waiver'}, 'Waived (' + w.scope + (w.errors ? ', including errors' : '') + ') until ' + w.expires + ': ' + w.reason);

  function check(hk) {
    const c = data.checks[hk.c];
    const ev = hk.e || [];
    return el('div', {class: 'check'},
      el('div', {class: 'check-head'}, badge(hk.s), ' ', el('code', {}, c.id), ' ', title(c),
        hk.o ? el('span', {class: 'muted'}, ' (was ' + NAME[hk.o] + ')') : null),
      hk.r ? el('p', {class: 'reason'}, str(hk.r)) : null,
      hk.w ? waiver(hk.w) : null,
      c.params ? el('p', {class: 'muted small'}, 'Parameters: ' + JSON.stringify(c.params)) : null,
      hk.v ? el('p', {class: 'muted small'}, 'Looked at ' + plural(hk.v.count, 'item') + ' (' + hk.v.population + ')') : null,
      ev.length ? el('ul', {class: 'evidence'}, ev.map(([t, s]) => el('li', {}, el('span', {class: 'text'}, str(t)), s ? el('span', {class: 'source'}, str(s)) : null))) : null,
      hk.m ? el('p', {class: 'muted small'}, '…and ' + hk.m + ' more not shown') : null);
  }

  // ---- one control across hosts --------------------------------------------

  function controlPage(pi, ci) {
    const p = data.profiles[pi];
    const c = p && p.controls[ci];
    if (!c) return notFound();
    const hosts = data.hosts.map((h, hi) => hi).filter((hi) => hostMatches(data.hosts[hi]) && cell[pi][hi].has(ci));
    const out = [
      el('p', {}, el('a', {href: '#/'}, '← All hosts')),
      el('h2', {}, c.id, ' ', title(c), ' ', sev(c.severity)),
      c.titleKo ? el('p', {class: 'muted'}, state.lang === 'ko' ? c.title : c.titleKo) : null,
      el('p', {class: 'muted'}, p.id + ' · ' + plural(hosts.length, 'host') + ' scanned for this control'),
      bar(counts(hosts.map((hi) => cell[pi][hi].get(ci).s))),
    ];
    for (const s of ORDER) {
      if (!state.shown.has(s)) continue;
      const these = hosts.filter((hi) => cell[pi][hi].get(ci).s === s);
      if (!these.length) continue;
      // Hosts with the same findings are shown once.
      const groups = new Map();
      for (const hi of these) {
        const h = data.hosts[hi];
        const hc = cell[pi][hi].get(ci);
        const key = JSON.stringify([hc.s, hc.r, hc.w, hc.x, hc.k.map((k) => h.checks[k])]);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(hi);
      }
      out.push(el('h3', {}, badge(s), ' on ' + plural(these.length, 'host')));
      for (const group of groups.values()) {
        const first = data.hosts[group[0]];
        out.push(el('div', {class: 'group'},
          el('p', {class: 'hosts-line'}, group.length > 1 ? 'Same result on ' + group.length + ' hosts: ' : 'Host: ', hostChips(group, pi, ci)),
          controlBody(first, cell[pi][group[0]].get(ci))));
      }
    }
    return out;
  }

  function hostChips(group, pi, ci) {
    const limit = 30;
    const chip = (hi) => el('a', {class: 'host-chip', href: '#/host/' + hi + '/' + pi + '/' + ci}, data.hosts[hi].name);
    const span = el('span', {}, group.slice(0, limit).map(chip));
    if (group.length > limit) {
      const more = el('button', {type: 'button', class: 'chip', onclick: () => {
        more.replaceWith(...group.slice(limit).map(chip));
      }}, 'show ' + (group.length - limit) + ' more');
      span.append(more);
    }
    return span;
  }

  const notFound = () => [el('p', {}, 'Not found. ', el('a', {href: '#/'}, 'Back to all hosts'))];

  // ---- routing -------------------------------------------------------------

  function render() {
    const parts = location.hash.replace(/^#\/?/, '').split('/').map((x) => parseInt(x, 10));
    const kind = location.hash.replace(/^#\/?/, '').split('/')[0];
    let view;
    if (kind === 'host') view = hostPage(parts[1], parts[2], parts[3]);
    else if (kind === 'control') view = controlPage(parts[1], parts[2]);
    else view = overview();
    document.getElementById('app').replaceChildren(...view);
    if (kind === 'host' && !Number.isNaN(parts[3])) {
      const target = document.getElementById('c-' + parts[2] + '-' + parts[3]);
      if (target) target.scrollIntoView({block: 'start'});
    }
  }

  document.getElementById('footer').replaceChildren(el('p', {class: 'muted small'},
    'Generated ' + data.generated + (data.tool ? ' by hostlint ' + data.tool : '') + ' from ' + plural(data.files, 'result file') +
    '. Each host\'s results are as of its scan time. hostlint only observes; it changed nothing on these hosts.'));
  refreshToolbar();
  window.addEventListener('hashchange', () => {
    render();
    if (!/^#\/host\/\d+\/\d+\/\d+/.test(location.hash)) window.scrollTo(0, 0);
  });
  render();
})();
