// logStar UI – vanilla JS + ECharts. All views are driven by one filter state that is mirrored in the URL hash.

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const LEVELS = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'];
const FRAMEWORK = ['java.', 'javax.', 'jakarta.', 'jdk.', 'sun.', 'com.sun.', 'org.jboss.', 'org.wildfly.', 'io.undertow.',
  'org.hibernate.', 'org.apache.', 'org.springframework.', 'com.arjuna.', 'org.infinispan.', 'org.eclipse.', 'io.netty.',
  'org.glassfish.', 'com.fasterxml.', 'org.slf4j.', 'org.postgresql.', 'oracle.', 'com.mysql.', 'org.h2.', 'net.bytebuddy.',
  'io.smallrye.', 'org.xnio.', 'org.jgroups.', 'jdk.proxy'];
const TYPE_LABEL = {
  spike: 'Häufung', 'error-rate': 'Fehlerrate', new: 'Neue Fehlerart', silence: 'Log-Stille', silenced: 'Verstummt',
  crash: 'Absturz', 'start-errors': 'Startfehler', known: 'Bekanntes Muster'
};
const FLAG_LABEL = { NEW: 'NEU', SPIKE: 'SPIKE', CRIT: 'KRITISCH', SILENT: 'VERSTUMMT' };

const state = { q: '', minLevel: '', from: null, to: null, groups: [], exclude: [], tab: 'overview' };
let info = null, ov = null, charts = {}, fmt = {}, eventCursor = null, eventsDirty = true;
const groupSort = { key: 'count', dir: -1 };
const groupFlags = new Set();
const anomalyTypes = new Set();

// ------------------------------------------------------------------------------------------------ utils

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = n => (n ?? 0).toLocaleString('de-DE');
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const lvColor = l => css('--lv-' + l.toLowerCase());

function setupFormats() {
  const tz = info.zone;
  fmt.full = new Intl.DateTimeFormat('de-DE', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
  fmt.dt = new Intl.DateTimeFormat('de-DE', { timeZone: tz, day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  fmt.dts = new Intl.DateTimeFormat('de-DE', { timeZone: tz, day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  fmt.time = new Intl.DateTimeFormat('de-DE', { timeZone: tz, hour: '2-digit', minute: '2-digit' });
  fmt.day = new Intl.DateTimeFormat('de-DE', { timeZone: tz, weekday: 'short', day: '2-digit', month: '2-digit' });
}
const tFull = ts => fmt.full.format(ts).replace(',', '');
const tDt = ts => fmt.dt.format(ts).replace(',', '');
const tDts = ts => fmt.dts.format(ts).replace(',', '');

function dur(ms) {
  if (ms < 60000) return Math.round(ms / 1000) + ' s';
  if (ms < 3600000) return Math.round(ms / 60000) + ' min';
  if (ms < 86400000) return (ms / 3600000).toFixed(1).replace('.', ',') + ' h';
  return (ms / 86400000).toFixed(1).replace('.', ',') + ' Tage';
}

function tplHtml(t) {
  return esc(t).replace(/&lt;\*&gt;/g, '<span class="w">‹*›</span>');
}

const lvBadge = l => `<span class="lv lv-${l}">${l}</span>`;
const flagBadges = flags => (flags || []).map(f => `<span class="badge b-${f}">${FLAG_LABEL[f] || f}</span>`).join('');
const simple = c => c ? c.substring(c.lastIndexOf('.') + 1) : '';

function sevClass(score) {
  return score >= 85 ? 's-critical' : score >= 65 ? 's-serious' : score >= 45 ? 's-warning' : 's-low';
}

function spark(series, w = 140, h = 26, color = css('--critical')) {
  if (!series || !series.length) return '';
  const n = series.length, max = Math.max(1, ...series);
  const bw = w / n;
  let bars = '';
  for (let i = 0; i < n; i++) {
    if (!series[i]) continue;
    const bh = Math.max(1.5, (series[i] / max) * (h - 2));
    bars += `<rect x="${(i * bw).toFixed(1)}" y="${(h - bh).toFixed(1)}" width="${Math.max(1, bw - 0.6).toFixed(1)}" height="${bh.toFixed(1)}"/>`;
  }
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><line x1="0" y1="${h - 0.5}" x2="${w}" y2="${h - 0.5}" stroke="${css('--axis')}" stroke-width="1"/><g fill="${color}">${bars}</g></svg>`;
}

// ------------------------------------------------------------------------------------------------ state / URL

function params(extra = {}) {
  const p = new URLSearchParams();
  if (state.q) p.set('q', state.q);
  if (state.minLevel) p.set('minLevel', state.minLevel);
  if (state.from != null) p.set('from', state.from);
  if (state.to != null) p.set('to', state.to);
  if (state.groups.length) p.set('groups', state.groups.join(','));
  if (state.exclude.length) p.set('exclude', state.exclude.join(','));
  for (const [k, v] of Object.entries(extra)) if (v != null && v !== '') p.set(k, v);
  return p;
}

function writeHash() {
  const p = params();
  if (state.tab !== 'overview') p.set('tab', state.tab);
  const h = p.toString();
  if (location.hash.substring(1) !== h) history.replaceState(null, '', h ? '#' + h : location.pathname);
}

function readHash() {
  const p = new URLSearchParams(location.hash.substring(1));
  state.q = p.get('q') || '';
  state.minLevel = p.get('minLevel') || '';
  state.from = p.has('from') ? +p.get('from') : null;
  state.to = p.has('to') ? +p.get('to') : null;
  state.groups = (p.get('groups') || '').split(',').filter(Boolean).map(Number);
  state.exclude = (p.get('exclude') || '').split(',').filter(Boolean).map(Number);
  state.tab = p.get('tab') || 'overview';
}

async function api(path, p = params()) {
  const t0 = performance.now();
  const r = await fetch(`/api/${path}?${p}`);
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  j._ms = Math.round(performance.now() - t0);
  return j;
}

function setStatus(s, err = false) {
  const el = $('#status');
  el.textContent = s;
  el.classList.toggle('err', err);
}

// ------------------------------------------------------------------------------------------------ filters

function renderFilterBar() {
  const pills = [];
  if (state.from != null || state.to != null) {
    pills.push(`<span class="pill">Zeitraum: ${tDts(state.from ?? info.minTs)} – ${tDts(state.to ?? info.maxTs)} <button data-clear="time" title="Zeitfilter entfernen">✕</button></span>`);
  }
  for (const g of state.groups) pills.push(`<span class="pill">nur Gruppe #${g} <button data-clear="group" data-id="${g}">✕</button></span>`);
  for (const g of state.exclude) pills.push(`<span class="pill">ohne Gruppe #${g} <button data-clear="exclude" data-id="${g}">✕</button></span>`);
  if (pills.length > 1) pills.push(`<span class="pill">alle Filter <button data-clear="all">✕</button></span>`);
  $('#filterBar').innerHTML = pills.join('');
}

$('#filterBar').addEventListener('click', e => {
  const b = e.target.closest('button[data-clear]');
  if (!b) return;
  const k = b.dataset.clear, id = +b.dataset.id;
  if (k === 'time') { state.from = state.to = null; }
  if (k === 'group') state.groups = state.groups.filter(x => x !== id);
  if (k === 'exclude') state.exclude = state.exclude.filter(x => x !== id);
  if (k === 'all') { state.from = state.to = null; state.groups = []; state.exclude = []; state.q = ''; state.minLevel = ''; }
  refresh();
});

function setTime(from, to) {
  state.from = Math.floor(from);
  state.to = Math.ceil(to);
  refresh();
}

// ------------------------------------------------------------------------------------------------ main refresh

async function refresh() {
  writeHash();
  $('#q').value = state.q;
  $('#minLevel').value = state.minLevel;
  renderFilterBar();
  eventsDirty = true;
  setStatus('lädt …');
  try {
    ov = await api('overview');
    setStatus(`${num(ov.total)} Ereignisse · ${ov.tookMs} ms`);
    renderKpis();
    renderTimeline();
    renderHeat();
    renderTree();
    renderTopAnomalies();
    renderTopGroups();
    renderGroupTable();
    renderAnomalies();
    if (state.tab === 'events') loadEvents(true);
  } catch (e) {
    setStatus(e.message, true);
  }
}

function showTab(tab) {
  state.tab = tab;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + tab));
  writeHash();
  if (tab === 'events' && eventsDirty) loadEvents(true);
  Object.values(charts).forEach(c => c.resize());
}

// ------------------------------------------------------------------------------------------------ overview

function renderKpis() {
  const lt = ov.levelTotals;
  const errors = lt[4] + lt[5], warns = lt[3];
  const k = (label, value, sub, dot, goto) =>
    `<div class="kpi" ${goto ? `data-goto="${goto}"` : ''}><div class="label">${dot ? `<span class="dot" style="background:${dot}"></span>` : ''}${label}</div><div class="value">${value}</div><div class="sub">${sub || '&nbsp;'}</div></div>`;
  const pct = x => ov.total ? (100 * x / ov.total).toLocaleString('de-DE', { maximumFractionDigits: 2 }) + ' %' : '';
  const incidents = ov.incidents.length;
  $('#kpis').innerHTML =
    k('Ereignisse', num(ov.total), `${dur(ov.end - ov.start)} Zeitraum`, null, 'events') +
    k('Fehler', num(errors), pct(errors) + ' aller Ereignisse', css('--critical'), null) +
    k('Warnungen', num(warns), pct(warns), css('--warning'), null) +
    k('Fehlergruppen', num(ov.errorGroupCount), `aus ${num(ov.groupCount)} Gruppen`, null, 'groups') +
    k('Neue Fehlerarten', num(ov.newGroupCount), 'erst spät aufgetreten', null, 'groups') +
    k('Vorfälle', num(incidents), `${num(ov.anomalyCount)} Auffälligkeiten`, incidents ? css('--critical') : null, 'anomalies');
  $('#anomalyBadge').textContent = incidents || '';
}

function axisLabels() {
  const n = ov.hist[0].length, labels = [];
  const multiDay = ov.end - ov.start > 86400000;
  for (let i = 0; i < n; i++) {
    const t = ov.start + i * ov.bucketMs;
    labels.push(multiDay && ov.bucketMs >= 3600000 ? fmt.day.format(t) + ' ' + fmt.time.format(t) : (multiDay ? tDt(t) : fmt.time.format(t)));
  }
  return labels;
}

const bucketOf = ts => Math.max(0, Math.min(ov.hist[0].length - 1, Math.floor((ts - ov.start) / ov.bucketMs)));

function baseAxis(labels, show) {
  return {
    type: 'category', data: labels, axisTick: { show: false },
    axisLine: { lineStyle: { color: css('--axis') } },
    axisLabel: { show, color: css('--muted'), fontSize: 11, hideOverlap: true }
  };
}

function valueAxis(name) {
  return {
    type: 'value', name, nameTextStyle: { color: css('--muted'), fontSize: 11, align: 'left' },
    splitNumber: 3, axisLabel: { color: css('--muted'), fontSize: 11, formatter: v => v >= 1000 ? (v / 1000) + 'k' : v },
    splitLine: { lineStyle: { color: css('--grid') } }
  };
}

function chart(id) {
  if (!charts[id]) {
    charts[id] = echarts.init(document.getElementById(id), null, { renderer: 'canvas' });
  }
  return charts[id];
}

function tooltipBase() {
  return {
    backgroundColor: css('--surface'), borderColor: css('--border'), textStyle: { color: css('--ink'), fontSize: 12 },
    extraCssText: 'box-shadow:0 4px 16px rgba(0,0,0,.15);border-radius:8px;'
  };
}

function renderTimeline() {
  const labels = axisLabels();
  const n = labels.length;
  const bar = (lv, idx, stack) => ({
    name: lv, type: 'bar', stack, data: ov.hist[idx], barCategoryGap: '15%',
    itemStyle: { color: lvColor(lv) }, emphasis: { focus: 'series' }, large: n > 400
  });
  const tip = {
    ...tooltipBase(), trigger: 'axis', axisPointer: { type: 'shadow' },
    formatter: ps => {
      const i = ps[0].dataIndex, t = ov.start + i * ov.bucketMs;
      let s = `<b>${tDts(t)}</b> – ${fmt.time.format(t + ov.bucketMs)}<br>`;
      let tot = 0;
      for (const p of ps.slice().reverse()) {
        if (!p.value || p.seriesName === 'Vorfall') continue;
        tot += p.value;
        s += `<span class="dot" style="background:${p.color}"></span> ${p.seriesName}: <b>${num(p.value)}</b><br>`;
      }
      const inc = ov.incidents.find(x => bucketOf(x.from) <= i && i <= bucketOf(x.to));
      if (inc) s += `<span style="color:${css('--critical')}">■ Vorfall: ${esc(inc.title.substring(0, 70))}</span><br>`;
      const mk = ov.markers.filter(m => bucketOf(m.ts) === i);
      for (const m of mk.slice(0, 4)) s += `<span style="color:${css('--accent')}">▍ ${esc(m.text.substring(0, 80))}</span><br>`;
      return s + `<span style="color:${css('--muted')}">Σ ${num(tot)} · Klick/Ziehen = Zeitfilter</span>`;
    }
  };
  const brush = { xAxisIndex: 'all', brushLink: 'all', throttleType: 'debounce', throttleDelay: 300, brushStyle: { color: 'rgba(42,120,214,0.15)', borderColor: css('--accent') }, toolbox: [] };

  // restarts / deployments as vertical marker lines
  const markLine = {
    symbol: 'none', silent: false, animation: false,
    data: ov.markers.filter(m => m.type !== 'started').map(m => ({
      xAxis: bucketOf(m.ts),
      lineStyle: { color: m.type === 'start' || m.type === 'stop' ? css('--ink-2') : css('--accent'), type: m.type === 'stop' ? 'dashed' : 'solid', width: 1.5 },
      label: { show: false }, name: m.text
    })),
    tooltip: { ...tooltipBase(), formatter: p => esc(p.name) }
  };

  const vol = chart('chartVolume');
  vol.setOption({
    animation: false, legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 10, textStyle: { color: css('--ink-2'), fontSize: 12 }, data: LEVELS },
    grid: { left: 48, right: 12, top: 26, bottom: 4 }, tooltip: tip, brush, toolbox: { show: false },
    xAxis: baseAxis(labels, false), yAxis: valueAxis('Ereignisse'),
    series: LEVELS.map((lv, i) => ({ ...bar(lv, i, 'all'), markLine: i === 0 ? markLine : undefined }))
  }, true);

  // incidents as shaded background bands on the error chart
  const errTotals = ov.hist[3].map((v, i) => v + ov.hist[4][i] + ov.hist[5][i]);
  const yMax = Math.max(1, ...errTotals);
  const band = new Array(n).fill(null), bandInc = new Array(n).fill(null);
  for (const inc of ov.incidents) {
    for (let i = bucketOf(inc.from); i <= bucketOf(inc.to); i++) { band[i] = yMax; bandInc[i] ??= inc; }
  }
  const er = chart('chartErrors');
  er.setOption({
    animation: false, legend: { show: false },
    grid: { left: 48, right: 12, top: 18, bottom: 24 }, tooltip: tip, brush, toolbox: { show: false },
    xAxis: baseAxis(labels, true), yAxis: valueAxis('Fehler & Warnungen'),
    series: [{
      name: 'Vorfall', type: 'bar', data: band, barGap: '-100%', barCategoryGap: '0%', z: 1, cursor: 'pointer',
      itemStyle: { color: 'rgba(208,59,59,0.13)' }, emphasis: { itemStyle: { color: 'rgba(208,59,59,0.25)' } }, tooltip: { show: false }
    }, ...['WARN', 'ERROR', 'FATAL'].map((lv, j) => ({
      ...bar(lv, 3 + j, 'err'), z: 2,
      markLine: j === 0 ? markLine : undefined
    }))]
  }, true);
  echarts.connect([vol, er]);

  for (const c of [vol, er]) {
    c.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX', brushMode: 'single' } });
    c.off('brushEnd');
    c.on('brushEnd', e => {
      const a = e.areas && e.areas[0];
      if (!a) return;
      const [i0, i1] = a.coordRange;
      if (i1 - i0 < 1) return;
      setTime(ov.start + i0 * ov.bucketMs, ov.start + (i1 + 1) * ov.bucketMs);
    });
    c.off('click');
    c.on('click', p => {
      if (p.seriesName === 'Vorfall' && bandInc[p.dataIndex]) openIncident(bandInc[p.dataIndex]);
      else if (p.componentType === 'series' && p.dataIndex != null) setTime(ov.start + p.dataIndex * ov.bucketMs, ov.start + (p.dataIndex + 1) * ov.bucketMs);
    });
  }
}

function warnGroups() {
  return ov.groups.filter(g => g.level === 'WARN' || g.level === 'ERROR' || g.level === 'FATAL');
}

function rebin(series, cols) {
  if (series.length <= cols) return series.slice();
  const f = Math.ceil(series.length / cols), out = [];
  for (let i = 0; i < series.length; i += f) out.push(series.slice(i, i + f).reduce((a, b) => a + b, 0));
  return out;
}

function groupLabel(g, max = 60) {
  const ex = g.exRoot ? simple(g.exRoot) + ': ' : '';
  const s = (ex + g.template).replace(/<\*>/g, '‹*›');
  return s.length > max ? s.substring(0, max - 1) + '…' : s;
}

function renderHeat() {
  const el = chart('chartHeat');
  // rows: conspicuous groups first (new, spike, critical), then by volume; colour is normalised per row so the
  // temporal shape of every group is visible regardless of its absolute volume
  const interest = g => (g.flags || []).reduce((s, f) => s + ({ NEW: 3, SPIKE: 3, CRIT: 2, SILENT: 2 }[f] || 0), 0) * 10 + (g.level !== 'WARN' ? 5 : 0) + Math.log10(1 + g.count);
  const gs = warnGroups().slice().sort((a, b) => interest(b) - interest(a)).slice(0, 25);
  if (!gs.length) {
    el.clear();
    el.setOption({ title: { text: 'Keine Fehler oder Warnungen im Zeitraum', left: 'center', top: 'middle', textStyle: { color: css('--muted'), fontSize: 13, fontWeight: 400 } } });
    return;
  }
  const cols = Math.min(90, ov.hist[0].length);
  const factor = Math.ceil(ov.hist[0].length / cols);
  const data = [];
  let max = 1;
  gs.forEach((g, y) => {
    const row = rebin(g.series, cols), rmax = Math.max(1, ...row);
    row.forEach((v, x) => { if (v > 0) data.push([x, y, Math.max(0.08, v / rmax), v]); });
  });
  max = 1;
  const nCols = rebin(gs[0].series, cols).length;
  const labels = [];
  for (let i = 0; i < nCols; i++) {
    const t = ov.start + i * factor * ov.bucketMs;
    labels.push(ov.end - ov.start > 86400000 ? tDt(t) : fmt.time.format(t));
  }
  el.setOption({
    animation: false,
    grid: { left: 290, right: 14, top: 8, bottom: 60 },
    tooltip: {
      ...tooltipBase(), formatter: p => {
        const g = gs[p.value[1]], t = ov.start + p.value[0] * factor * ov.bucketMs;
        return `<b>${num(p.value[3])}×</b> ${tDt(t)} – ${fmt.time.format(t + factor * ov.bucketMs)}<br>${lvBadge(g.level)} ${esc(groupLabel(g, 90))}`;
      }
    },
    xAxis: { type: 'category', data: labels, axisLabel: { color: css('--muted'), fontSize: 10, hideOverlap: true }, axisTick: { show: false }, axisLine: { lineStyle: { color: css('--axis') } }, splitArea: { show: false } },
    yAxis: {
      type: 'category', inverse: true, data: gs.map(g => g.id), axisTick: { show: false }, axisLine: { show: false },
      axisLabel: { color: css('--ink-2'), fontSize: 11, width: 280, overflow: 'truncate', formatter: id => { const g = gs.find(x => x.id == id); return (g.level === 'WARN' ? '▲ ' : '● ') + groupLabel(g, 48); } }
    },
    visualMap: {
      min: 0, max, dimension: 2, calculable: false, orient: 'horizontal', left: 'center', bottom: 0, itemWidth: 10, itemHeight: 160,
      text: ['Zeilen-Maximum', 'wenige'], textStyle: { color: css('--muted'), fontSize: 11 },
      inRange: { color: [css('--seq-1'), css('--seq-2'), css('--seq-3'), css('--seq-4'), css('--seq-5')] }
    },
    series: [{ type: 'heatmap', data, itemStyle: { borderColor: css('--surface'), borderWidth: 1 }, progressive: 0 }]
  }, true);
  el.off('click');
  el.on('click', p => openGroup(gs[p.value[1]].id));
}

function renderTree() {
  const el = chart('chartTree');
  const cats = ov.categories.slice().sort((a, b) => b.value - a.value);
  if (!cats.length) { el.clear(); return; }
  const colors = [1, 2, 3, 4, 5, 6, 7, 8].map(i => css('--cat-' + i));
  const top = cats.slice(0, 8);
  const rest = cats.slice(8);
  if (rest.length) top.push({ name: 'Weitere', value: rest.reduce((s, c) => s + c.value, 0), children: rest.map(c => ({ name: c.name, value: c.value })), other: true });
  const data = top.map((c, i) => {
    const color = c.other ? css('--cat-other') : colors[i];
    return {
      name: c.name, value: c.value, itemStyle: { color, borderColor: color },
      children: c.children.map(ch => ({ name: ch.name, value: ch.value, itemStyle: { color } }))
    };
  });
  el.setOption({
    animation: false,
    tooltip: { ...tooltipBase(), formatter: p => `${esc(p.treePathInfo.slice(1).map(x => x.name).join(' → '))}<br><b>${num(p.value)}</b> Ereignisse` },
    series: [{
      type: 'treemap', data, roam: false, nodeClick: false, breadcrumb: { show: false }, width: '100%', height: '100%', top: 0, left: 0,
      label: { show: true, formatter: p => `${p.name}\n${num(p.value)}`, fontSize: 11, color: '#fff', overflow: 'truncate', textShadowColor: 'rgba(0,0,0,0.35)', textShadowBlur: 2 },
      upperLabel: { show: true, height: 22, color: '#fff', fontWeight: 600, fontSize: 12, formatter: p => `${p.name}  ${num(p.value)}` },
      levels: [
        { itemStyle: { borderWidth: 0, gapWidth: 3, borderColor: css('--surface') }, upperLabel: { show: false } },
        { itemStyle: { borderWidth: 3, gapWidth: 2 }, upperLabel: { show: true } },
        { itemStyle: { borderWidth: 0, gapWidth: 0, borderColor: css('--surface') }, colorAlpha: [0.55, 0.9], upperLabel: { show: false } }
      ]
    }]
  }, true);
  el.off('click');
  el.on('click', p => {
    let path = p.treePathInfo.slice(1).map(x => x.name);
    if (path[0] === 'Weitere') path = path.slice(1);
    if (!path.length) return;
    const ids = warnGroups().filter(g => g.subsystem === path[0] && (path.length < 2 || g.category === path[1])).map(g => g.id);
    if (ids.length) { state.groups = ids; refresh(); }
  });
}

function anomalyRow(a, compact = false) {
  return `<div class="anomaly" data-anomaly='${esc(JSON.stringify({ from: a.from, to: a.to, clusters: a.clusters, type: a.type }))}'>
    <div class="score ${sevClass(a.score)}">${a.score}<small>Score</small></div>
    <div><div class="type">${TYPE_LABEL[a.type] || a.type} · ${tDt(a.from)}${a.to > a.from + 60000 ? ' – ' + tDt(a.to) : ''}</div>
      <div class="title">${tplHtml(a.title)}</div>
      ${compact ? '' : `<div class="detail">${esc(a.detail)}</div>`}
      ${!compact && a.metrics && a.metrics.advice ? `<div class="detail"><b>Tipp:</b> ${esc(a.metrics.advice)}</div>` : ''}
    </div>
    <div class="actions">
      <button class="ghost small" data-act="zoom">Zeitraum</button>
      ${a.clusters && a.clusters.length ? '<button class="ghost small" data-act="groups">Gruppen</button>' : ''}
      ${a.type !== 'known' ? '<button class="ghost small" data-act="cause">Ursachen</button>' : ''}
    </div></div>`;
}

function incidentCard(inc, compact) {
  const types = inc.types.map(t => TYPE_LABEL[t] || t).join(' · ');
  return `<div class="anomaly" data-incident="${inc.id}">
    <div class="score ${sevClass(inc.score)}">${inc.score}<small>Vorfall</small></div>
    <div><div class="type">${tDt(inc.from)} – ${fmt.time.format(inc.to)} (${dur(inc.to - inc.from)}) · ${inc.anomalies.length} Signale · ${types}</div>
      <div class="title">${tplHtml(inc.title)}</div>
      <div class="detail">Erstes Signal ${fmt.time.format(inc.firstSignalTs)}: ${tplHtml(inc.firstSignal)}</div>
    </div>
    <div class="actions">
      <button class="ghost small" data-act="incident">Details</button>
      <button class="ghost small" data-act="zoom">Zeitraum</button>
      <button class="ghost small" data-act="cause">Ursachen</button>
    </div></div>`;
}

function renderTopAnomalies() {
  const incs = ov.incidents.slice(0, 5);
  const inIncident = new Set(ov.incidents.flatMap(i => i.anomalies.map(a => a.title + a.from)));
  const rest = ov.anomalies.filter(a => !inIncident.has(a.title + a.from) && a.type !== 'known').slice(0, Math.max(2, 7 - incs.length));
  const known = ov.anomalies.filter(a => a.type === 'known').slice(0, 3);
  const html = incs.map(i => incidentCard(i, true)).join('') + rest.map(a => anomalyRow(a, true)).join('') + known.map(a => anomalyRow(a, true)).join('');
  $('#topAnomalies').innerHTML = html || '<div class="empty">Keine Auffälligkeiten im Zeitraum.</div>';
}

function renderTopGroups() {
  const gs = warnGroups().slice().sort((a, b) => b.count - a.count).slice(0, 10);
  $('#topGroups').innerHTML = gs.length ? `<table class="tbl">${gs.map(g => `
    <tr class="click" data-group="${g.id}"><td>${lvBadge(g.level)}</td>
    <td><div class="tpl">${flagBadges(g.flags)}${tplHtml(groupLabel(g, 110))}</div><div class="sub2">${esc(g.subsystem)}</div></td>
    <td class="num">${num(g.count)}</td><td>${spark(rebin(g.series, 60), 110, 22, lvColor(g.level))}</td></tr>`).join('')}</table>`
    : '<div class="empty">Keine Fehler im Zeitraum.</div>';
}

// ------------------------------------------------------------------------------------------------ groups tab

function renderGroupChips() {
  $('#groupFlagChips').innerHTML = Object.entries(FLAG_LABEL).map(([k, v]) =>
    `<button class="chip ${groupFlags.has(k) ? 'on' : ''}" data-flag="${k}">${v}</button>`).join('');
}

function renderGroupTable() {
  renderGroupChips();
  const f = $('#groupFilter').value.trim().toLowerCase();
  const warnOnly = $('#groupWarnOnly').checked;
  let gs = ov.groups.filter(g => !warnOnly || ['WARN', 'ERROR', 'FATAL'].includes(g.level));
  if (groupFlags.size) gs = gs.filter(g => [...groupFlags].every(fl => (g.flags || []).includes(fl)));
  if (f) gs = gs.filter(g => [g.template, g.exRoot, g.exOuter, g.code, g.subsystem, g.logger, '#' + g.id].join(' ').toLowerCase().includes(f));
  const key = groupSort.key, dir = groupSort.dir;
  const lvIdx = l => LEVELS.indexOf(l);
  gs.sort((a, b) => {
    let x = a[key], y = b[key];
    if (key === 'level') { x = lvIdx(a.level) * 1e12 + a.count; y = lvIdx(b.level) * 1e12 + b.count; }
    if (typeof x === 'string' || typeof y === 'string') return dir * String(x ?? '').localeCompare(String(y ?? ''));
    return dir * ((x ?? 0) - (y ?? 0));
  });
  $('#groupCount').textContent = `${num(gs.length)} Gruppen`;
  const th = (k, label, cls = '') => `<th class="${cls}" data-sort="${k}">${label}${groupSort.key === k ? (groupSort.dir < 0 ? ' ↓' : ' ↑') : ''}</th>`;
  const rows = gs.slice(0, 500).map(g => `<tr class="click" data-group="${g.id}">
      <td>${lvBadge(g.level)}</td>
      <td><div class="tpl">${flagBadges(g.flags)}${tplHtml(g.template)}</div>
        <div class="sub2">#${g.id} · ${esc(g.exRoot ? g.exRoot + (g.exOuter && g.exOuter !== g.exRoot ? ' (in ' + simple(g.exOuter) + ')' : '') : 'ohne Exception')} · ${esc(g.logger || '')}</div></td>
      <td>${esc(g.subsystem)}${g.code ? `<div class="sub2 mono">${esc(g.code)}</div>` : ''}</td>
      <td class="num">${num(g.count)}${g.totalCount !== g.count ? `<div class="sub2">von ${num(g.totalCount)}</div>` : ''}</td>
      <td>${spark(rebin(g.series, 70), 150, 26, lvColor(g.level))}</td>
      <td class="time">${tDt(g.first)}</td><td class="time">${tDt(g.last)}</td></tr>`).join('');
  $('#groupTable').innerHTML = `<thead><tr>${th('level', 'Level')}${th('template', 'Gruppe')}${th('subsystem', 'Subsystem')}${th('count', 'Anzahl', 'num')}<th>Verlauf</th>${th('first', 'Erstes')}${th('last', 'Letztes')}</tr></thead><tbody>${rows || '<tr><td colspan="7" class="empty">Keine Gruppen</td></tr>'}</tbody>`;
}

$('#groupTable').addEventListener('click', e => {
  const th = e.target.closest('th[data-sort]');
  if (th) {
    const k = th.dataset.sort;
    groupSort.dir = groupSort.key === k ? -groupSort.dir : -1;
    groupSort.key = k;
    renderGroupTable();
  }
});
$('#groupFilter').addEventListener('input', () => renderGroupTable());
$('#groupWarnOnly').addEventListener('change', () => renderGroupTable());
$('#groupFlagChips').addEventListener('click', e => {
  const b = e.target.closest('[data-flag]');
  if (!b) return;
  groupFlags.has(b.dataset.flag) ? groupFlags.delete(b.dataset.flag) : groupFlags.add(b.dataset.flag);
  renderGroupTable();
});

// ------------------------------------------------------------------------------------------------ anomalies tab

function renderAnomalies() {
  const types = [...new Set(ov.anomalies.map(a => a.type))];
  $('#anomalyChips').innerHTML = `<button class="chip ${anomalyTypes.size ? '' : 'on'}" data-type="">alle</button>` +
    types.map(t => `<button class="chip ${anomalyTypes.has(t) ? 'on' : ''}" data-type="${t}">${TYPE_LABEL[t] || t} (${ov.anomalies.filter(a => a.type === t).length})</button>`).join('');
  const list = ov.anomalies.filter(a => !anomalyTypes.size || anomalyTypes.has(a.type));
  let html = '';
  if (!anomalyTypes.size && ov.incidents.length) {
    html += `<div class="card-head" style="padding:12px 12px 0"><h2>Vorfälle</h2><span class="muted hint">zeitlich zusammenhängende Signale, nach Schwere</span></div>`;
    html += ov.incidents.map(i => incidentCard(i, false)).join('');
    html += `<div class="card-head" style="padding:12px 12px 0"><h2>Alle Auffälligkeiten</h2></div>`;
  }
  html += list.map(a => anomalyRow(a)).join('');
  $('#anomalyList').innerHTML = html || '<div class="empty">Keine Auffälligkeiten.</div>';
}

$('#anomalyChips').addEventListener('click', e => {
  const b = e.target.closest('[data-type]');
  if (!b) return;
  const t = b.dataset.type;
  if (!t) anomalyTypes.clear();
  else anomalyTypes.has(t) ? anomalyTypes.delete(t) : anomalyTypes.add(t);
  renderAnomalies();
});

function padRange(from, to) {
  const span = Math.max(to - from, 10 * 60000);
  return [from - span * 0.5, to + span * 0.5];
}

document.addEventListener('click', e => {
  const act = e.target.closest('[data-act]');
  const row = e.target.closest('[data-anomaly],[data-incident]');
  if (row) {
    const inc = row.dataset.incident != null ? ov.incidents.find(i => i.id == row.dataset.incident) : null;
    const a = inc || JSON.parse(row.dataset.anomaly);
    const what = act ? act.dataset.act : (inc ? 'incident' : 'zoom');
    if (what === 'zoom') { const [f, t] = padRange(a.from, a.to); state.tab = 'overview'; showTab('overview'); setTime(f, t); }
    if (what === 'groups') { state.groups = a.clusters.slice(0, 40); refresh(); showTab('groups'); }
    if (what === 'cause') openCorrelation(a.from, a.type === 'new' || a.type === 'silenced' ? a.from + 5 * 60000 : a.to);
    if (what === 'incident' && inc) openIncident(inc);
    return;
  }
  const g = e.target.closest('[data-group]');
  if (g && !e.target.closest('button')) { openGroup(+g.dataset.group); return; }
  const go = e.target.closest('[data-goto]');
  if (go) { e.preventDefault(); showTab(go.dataset.goto); }
});

// ------------------------------------------------------------------------------------------------ events tab

function highlightTerms() {
  const terms = [];
  const q = state.q || '';
  for (const m of q.matchAll(/"([^"]+)"/g)) terms.push(m[1]);
  for (const w of q.replace(/"[^"]*"/g, ' ').split(/\s+/)) {
    if (!w || /^(AND|OR|NOT)$/.test(w) || w.startsWith('-')) continue;
    const v = w.includes(':') ? w.substring(w.indexOf(':') + 1) : w;
    if (w.startsWith('level:') || w.startsWith('group:')) continue;
    const t = v.replace(/[()*?"]/g, '');
    if (t.length >= 2) terms.push(t);
  }
  if (!terms.length) return null;
  return new RegExp('(' + terms.map(t => esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\W+')).join('|') + ')', 'gi');
}

function formatRaw(text, hl) {
  return text.split('\n').map((line, i) => {
    let h = esc(line);
    if (hl) h = h.replace(hl, '<mark>$1</mark>');
    if (i === 0) return h;
    const m = line.match(/^\s+at\s+(?:[\w.$]+\/\/|[\w.]+@[\w.]+\/)?([\w.$<>]+)/);
    if (m) return `<span class="${FRAMEWORK.some(p => m[1].startsWith(p)) ? 'fw' : 'app'}">${h}</span>`;
    if (/^(Caused by: |Suppressed: )?[a-z][\w$]*(\.[\w$]+)+(Exception|Error|Throwable)\b/.test(line.trim())) return `<span class="exl">${h}</span>`;
    if (/^\s+\.\.\. \d+ more/.test(line)) return `<span class="fw">${h}</span>`;
    return h;
  }).join('\n');
}

/** Strips timestamp, level, logger and thread from a header line so that only the message remains. */
function messageOf(line, ev) {
  let s = line.replace(/^\[?\d{4}[-\/.]\d{2}[-\/.]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?\s*/, '')
    .replace(/^\[?\d{2}:\d{2}:\d{2}[.,]\d+\]?\s*/, '').replace(/^\d{2}[ .-]\w{2,3}[ .-]\d{4} \d{2}:\d{2}:\d{2}[.,]\d+\s*/, '');
  const prefixes = [ev.level, 'WARNING', 'SEVERE', `[${ev.logger}]`, `(${ev.thread})`, `[${ev.thread}]`, ev.logger, '-', ':', '---'].filter(Boolean);
  for (let guard = 0; guard < 8; guard++) {
    s = s.replace(/^\s+/, '');
    const p = prefixes.find(x => s.startsWith(x) && (s.length === x.length || /[\s:]/.test(s[x.length])));
    if (!p) break;
    s = s.substring(p.length);
  }
  return s.replace(/^\s*[-:]\s+/, '') || line;
}

function eventHtml(ev, hl, open = false) {
  const nl = ev.text.indexOf('\n');
  const first = nl > 0 ? ev.text.substring(0, nl) : ev.text;
  const lines = ev.text.split('\n').length;
  const msg = messageOf(first, ev);
  let m = esc(msg);
  if (hl) m = m.replace(hl, '<mark>$1</mark>');
  return `<div class="ev ${ev.focus ? 'focus' : ''}" data-doc="${ev.doc}">
    <div class="ev-head"><span class="t">${tFull(ev.ts)}</span>${lvBadge(ev.level)}<span class="lg" title="${esc(ev.logger)}">${esc(ev.logger)}</span>
      <span class="m">${m}${lines > 1 ? `<span class="st">+${lines - 1} Zeilen</span>` : ''}</span></div>
    <div class="ev-body" ${open ? '' : 'hidden'}>
      <div class="ev-meta"><span>Thread: <b>${esc(ev.thread)}</b></span><span>Datei: ${esc(info.files[ev.file]?.path.split('/').pop())} @ ${num(ev.off)}</span>
        <a href="#" data-open-group="${ev.group}">Gruppe #${ev.group}</a>
        <button class="ghost small" data-context="${ev.doc}">Kontext ±25</button>
        <button class="ghost small" data-thread="${esc(ev.thread)}" data-ts="${ev.ts}">gleicher Thread ±2 min</button></div>
      <pre class="raw">${formatRaw(ev.text, hl)}</pre>
    </div></div>`;
}

let eventSeq = 0;

async function loadEvents(reset) {
  const seq = ++eventSeq;
  if (reset) { eventCursor = null; $('#eventList').innerHTML = '<div class="empty">lädt …</div>'; }
  eventsDirty = false;
  try {
    const r = await api('events', params({ order: $('#eventOrder').value, cursor: reset ? null : eventCursor, limit: 150 }));
    if (seq !== eventSeq) return; // a newer request superseded this one
    if (reset) $('#eventList').innerHTML = '';
    const hl = highlightTerms();
    $('#eventList').insertAdjacentHTML('beforeend', r.events.map(e => eventHtml(e, hl)).join(''));
    if (reset && !r.events.length) $('#eventList').innerHTML = '<div class="empty">Keine Ereignisse für diese Suche.</div>';
    $('#eventTotal').textContent = `${num(r.total)}${r.totalExact ? '' : '+'} Treffer · ${r.tookMs} ms`;
    eventCursor = r.cursor;
    $('#eventMore').hidden = !eventCursor;
  } catch (e) {
    if (seq === eventSeq) $('#eventList').innerHTML = `<div class="empty err">${esc(e.message)}</div>`;
  }
}

function eventListClick(e) {
  const ctx = e.target.closest('[data-context]');
  if (ctx) { openContext(+ctx.dataset.context); return; }
  const th = e.target.closest('[data-thread]');
  if (th) {
    const ts = +th.dataset.ts;
    closeDrawer();
    state.q = `thread:"${th.dataset.thread.replace(/"/g, '\\"')}"`;
    state.groups = []; state.minLevel = '';
    state.from = ts - 120000; state.to = ts + 120000;
    $('#eventOrder').value = 'asc';
    showTab('events');
    refresh();
    return;
  }
  const og = e.target.closest('[data-open-group]');
  if (og) { e.preventDefault(); openGroup(+og.dataset.openGroup); return; }
  const head = e.target.closest('.ev-head');
  if (head) { const b = head.nextElementSibling; b.hidden = !b.hidden; }
}

$('#eventList').addEventListener('click', eventListClick);
$('#drawerBody').addEventListener('click', e => { if (e.target.closest('.ev')) eventListClick(e); });
$('#eventMore').addEventListener('click', () => loadEvents(false));
$('#eventOrder').addEventListener('change', () => loadEvents(true));
$('#eventWrap').addEventListener('change', e => $('#eventList').classList.toggle('wrap', e.target.checked));

// ------------------------------------------------------------------------------------------------ drawer views

function openDrawer(title, html) {
  $('#drawerTitle').innerHTML = title;
  $('#drawerBody').innerHTML = html;
  $('#drawer').hidden = false;
  $('#drawerBody').scrollTop = 0;
}

function closeDrawer() {
  $('#drawer').hidden = true;
  if (charts.groupChart) { charts.groupChart.dispose(); delete charts.groupChart; }
}

$('#drawerClose').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeDrawer(); $('#help').hidden = true; } });

function bars(obj, total) {
  const entries = Object.entries(obj || {});
  if (!entries.length) return '<div class="muted">–</div>';
  const max = Math.max(...entries.map(e => e[1]));
  return `<div class="bars">${entries.map(([k, v]) => `<div class="row"><div class="bar"><span style="width:${(100 * v / max).toFixed(1)}%"></span><em>${esc(k || '(leer)')}</em></div><div class="num">${num(v)}${total ? ` <span class="muted">${Math.round(100 * v / total)}%</span>` : ''}</div></div>`).join('')}</div>`;
}

async function openGroup(id) {
  openDrawer(`Gruppe #${id}`, '<div class="empty">lädt …</div>');
  let g;
  try {
    g = await api('group', params({ id }));
  } catch (e) {
    $('#drawerBody').innerHTML = `<div class="empty err">${esc(e.message)}</div>`;
    return;
  }
  const hl = highlightTerms();
  $('#drawerTitle').innerHTML = `${lvBadge(g.level)} Gruppe #${g.id} ${flagBadges(g.flags)}`;
  $('#drawerBody').innerHTML = `
    <div class="tpl" style="font-size:13.5px">${tplHtml(g.template)}</div>
    <div class="btnrow">
      <button data-g-act="events">Ereignisse anzeigen</button>
      <button class="ghost" data-g-act="filter">Nur diese Gruppe</button>
      <button class="ghost" data-g-act="exclude">Gruppe ausblenden</button>
      <button class="ghost" data-g-act="cause">Was passierte vor dem ersten Auftreten?</button>
    </div>
    ${(g.ruleDetails || []).map(r => `<div class="rule"><b>${esc(r.title)}</b>${esc(r.explanation)}<br><span class="muted">Tipp: ${esc(r.advice)}</span></div>`).join('')}
    <div class="kv" style="margin-top:12px">
      <div>Vorkommen</div><div><b>${num(g.count)}</b> im Zeitraum · ${num(g.totalCount)} gesamt</div>
      <div>Erstes / letztes</div><div>${tDts(g.totalFirst)} / ${tDts(g.totalLast)}</div>
      <div>Logger</div><div class="mono">${esc(g.logger)}</div>
      <div>Message-Code</div><div class="mono">${esc(g.code || '–')}</div>
      <div>Exception</div><div class="mono">${esc(g.exOuter || '–')}${g.exRoot && g.exRoot !== g.exOuter ? '<br>↳ Ursache: ' + esc(g.exRoot) : ''}</div>
      ${g.rootMessage ? `<div>Ursache-Text</div><div class="mono">${esc(g.rootMessage)}</div>` : ''}
      <div>Subsystem / Art</div><div>${esc(g.subsystem)} / ${esc(g.category)}</div>
    </div>
    <h3>Verlauf</h3><div id="groupChart" style="height:150px"></div>
    <div class="grid2" style="gap:20px">
      <div><h3>Threads</h3>${bars(g.threads, g.count)}</div>
      <div><h3>Dateien</h3>${bars(Object.fromEntries(Object.entries(g.files).map(([k, v]) => [k.split('/').pop(), v])), g.count)}</div>
    </div>
    ${g.variants.length > 1 ? `<h3>Varianten (${g.variants.length})</h3><table class="tbl small">${g.variants.map(v => `<tr><td class="num">${num(v.count)}</td><td class="tpl">${esc(v.sample)}</td></tr>`).join('')}</table>` : ''}
    ${(g.anomalies || []).length ? `<h3>Auffälligkeiten</h3>${g.anomalies.map(a => anomalyRow(a, true)).join('')}` : ''}
    <h3>Erstes Auftreten</h3>${g.firstEvent ? eventHtml(g.firstEvent, hl, true) : ''}
    ${g.lastEvent && g.lastEvent.doc !== g.firstEvent?.doc ? `<h3>Letztes Auftreten</h3>${eventHtml(g.lastEvent, hl, true)}` : ''}`;
  const c = echarts.init($('#groupChart'));
  charts.groupChart = c;
  const n = g.series.length;
  c.setOption({
    animation: false, grid: { left: 40, right: 8, top: 8, bottom: 22 },
    tooltip: { ...tooltipBase(), trigger: 'axis', formatter: ps => `${tDts(g.start + ps[0].dataIndex * g.bucketMs)}<br><b>${num(ps[0].value)}</b>×` },
    xAxis: { type: 'category', data: Array.from({ length: n }, (_, i) => tDt(g.start + i * g.bucketMs)), axisLabel: { color: css('--muted'), fontSize: 10, hideOverlap: true }, axisTick: { show: false }, axisLine: { lineStyle: { color: css('--axis') } } },
    yAxis: { type: 'value', splitNumber: 2, axisLabel: { color: css('--muted'), fontSize: 10 }, splitLine: { lineStyle: { color: css('--grid') } } },
    series: [{ type: 'bar', data: g.series, itemStyle: { color: lvColor(g.level) }, barCategoryGap: '10%' }]
  });
  $('#drawerBody').onclick = e => {
    const b = e.target.closest('[data-g-act]');
    if (!b) return;
    const a = b.dataset.gAct;
    if (a === 'events') { closeDrawer(); state.groups = [g.id]; showTab('events'); refresh(); }
    if (a === 'filter') { closeDrawer(); state.groups = [g.id]; refresh(); }
    if (a === 'exclude') { closeDrawer(); state.exclude = [...new Set([...state.exclude, g.id])]; state.groups = state.groups.filter(x => x !== g.id); refresh(); }
    if (a === 'cause') openCorrelation(g.totalFirst, g.totalFirst + 5 * 60000);
  };
}

function openIncident(inc) {
  const sig = inc.anomalies.map(a => anomalyRow(a, false)).join('');
  openDrawer(`Vorfall ${tDt(inc.from)} – ${fmt.time.format(inc.to)}`, `
    <div class="kv"><div>Dauer</div><div>${dur(inc.to - inc.from)}</div><div>Score</div><div>${inc.score}</div>
    <div>Erstes Signal</div><div>${tDts(inc.firstSignalTs)} – ${tplHtml(inc.firstSignal)}</div></div>
    <div class="btnrow"><button data-i-act="cause">Ursachen-Analyse</button><button class="ghost" data-i-act="zoom">Zeitraum ansehen</button><button class="ghost" data-i-act="events">Fehler im Zeitraum</button></div>
    <h3>Signale (chronologisch)</h3><div class="card flush">${sig}</div>`);
  $('#drawerBody').onclick = e => {
    const b = e.target.closest('[data-i-act]');
    if (!b) return;
    const a = b.dataset.iAct;
    if (a === 'cause') openCorrelation(inc.from, inc.to);
    if (a === 'zoom') { closeDrawer(); const [f, t] = padRange(inc.from, inc.to); showTab('overview'); setTime(f, t); }
    if (a === 'events') { closeDrawer(); state.minLevel = '3'; state.groups = []; const [f, t] = padRange(inc.from, inc.to); state.from = f; state.to = t; $('#eventOrder').value = 'asc'; showTab('events'); refresh(); }
  };
}

async function openCorrelation(from, to) {
  const lead = Math.max(30 * 60000, (to - from));
  openDrawer(`Ursachen-Analyse ${tDt(from)} – ${fmt.time.format(to)}`, '<div class="empty">analysiert …</div>');
  let r;
  try {
    r = await api('correlate', new URLSearchParams({ from, to, lead }));
  } catch (e) {
    $('#drawerBody').innerHTML = `<div class="empty err">${esc(e.message)}</div>`;
    return;
  }
  const rows = r.candidates.map(c => `<tr class="click" data-group="${c.id}">
    <td class="time">${tDts(c.firstInWindow)}${c.before ? '<div class="sub2">davor</div>' : ''}</td>
    <td>${lvBadge(c.level)}</td>
    <td><div class="tpl">${flagBadges(c.flags)}${tplHtml(groupLabel(c, 160))}</div><div class="sub2">${esc(c.subsystem)} · #${c.id}</div></td>
    <td class="num">${num(c.count)}</td><td class="num">${c.expected.toLocaleString('de-DE')}</td><td class="num"><b>×${c.lift.toLocaleString('de-DE')}</b></td></tr>`).join('');
  $('#drawerBody').innerHTML = `
    <p class="muted">Gruppen, die im Fenster ${tDt(r.windowFrom)} – ${fmt.time.format(to)} (inkl. ${dur(from - r.windowFrom)} Vorlauf)
    deutlich häufiger auftreten als im Durchschnitt – chronologisch nach erstem Auftreten. Die frühesten Einträge sind die besten Ursachen-Kandidaten;
    „davor“ = vor Beginn der Auffälligkeit.</p>
    <div class="card flush"><table class="tbl"><thead><tr><th>Erstes</th><th>Level</th><th>Gruppe</th><th class="num">Anzahl</th><th class="num">erwartet</th><th class="num">Faktor</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6" class="empty">Keine auffälligen Gruppen.</td></tr>'}</tbody></table></div>`;
  $('#drawerBody').onclick = null;
}

async function openContext(doc) {
  openDrawer('Kontext in der Logdatei', '<div class="empty">lädt …</div>');
  try {
    const r = await api('context', new URLSearchParams({ doc, n: 25 }));
    const hl = highlightTerms();
    $('#drawerTitle').textContent = 'Kontext: ' + r.file.split('/').pop();
    $('#drawerBody').innerHTML = `<div class="events">${r.events.map(e => eventHtml(e, hl, e.focus)).join('')}</div>`;
    $('#drawerBody').onclick = null;
    $('#drawerBody .ev.focus')?.scrollIntoView({ block: 'center' });
  } catch (e) {
    $('#drawerBody').innerHTML = `<div class="empty err">${esc(e.message)}</div>`;
  }
}

// ------------------------------------------------------------------------------------------------ files

function renderFiles() {
  $('#fileTable').innerHTML = `<thead><tr><th>#</th><th>Datei</th><th>Format</th><th class="num">Größe</th><th class="num">Ereignisse</th><th>von</th><th>bis</th><th></th></tr></thead><tbody>` +
    info.files.map(f => `<tr><td>${f.id}</td><td class="mono">${esc(f.path)}</td><td>${esc(f.layout || '')}${f.skipped ? `<span class="err"> übersprungen: ${esc(f.skipped)}</span>` : ''}</td>
      <td class="num">${(f.size / 1e6).toLocaleString('de-DE', { maximumFractionDigits: 1 })} MB</td><td class="num">${num(f.events)}</td>
      <td class="time">${f.minTs ? tDts(f.minTs) : ''}</td><td class="time">${f.maxTs ? tDts(f.maxTs) : ''}</td>
      <td>${f.events ? `<button class="ghost small" data-file-q="${f.id}">Ereignisse</button>` : ''}</td></tr>`).join('') + '</tbody>';
}

$('#fileTable').addEventListener('click', e => {
  const b = e.target.closest('[data-file-q]');
  if (b) { state.q = `file:${b.dataset.fileQ}`; showTab('events'); refresh(); }
});

// ------------------------------------------------------------------------------------------------ wiring

$('#searchForm').addEventListener('submit', e => {
  e.preventDefault();
  state.q = $('#q').value.trim();
  state.minLevel = $('#minLevel').value;
  refresh();
});
$('#minLevel').addEventListener('change', () => { state.minLevel = $('#minLevel').value; refresh(); });
$('#tabs').addEventListener('click', e => { const b = e.target.closest('[data-tab]'); if (b) showTab(b.dataset.tab); });
$('#helpBtn').addEventListener('click', () => $('#help').hidden = false);
$('#themeBtn').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.dataset.theme = dark ? 'light' : 'dark';
  localStorage.setItem('logstar-theme', document.documentElement.dataset.theme);
  if (ov) { renderTimeline(); renderHeat(); renderTree(); renderTopGroups(); renderGroupTable(); }
});
window.addEventListener('resize', () => Object.values(charts).forEach(c => c.resize()));
window.addEventListener('hashchange', () => { readHash(); showTab(state.tab); refresh(); });

(async function init() {
  const theme = localStorage.getItem('logstar-theme');
  if (theme) document.documentElement.dataset.theme = theme;
  info = await api('info', new URLSearchParams());
  setupFormats();
  $('#datasetInfo').textContent = `${num(info.events)} Ereignisse · ${info.files.filter(f => !f.skipped).length} Dateien · ${tDt(info.minTs)} – ${tDt(info.maxTs)}`;
  renderFiles();
  readHash();
  showTab(state.tab);
  refresh();
})();
