window.CHARTJS_AVAILABLE = typeof window.Chart !== 'undefined';
if (!window.CHARTJS_AVAILABLE) {
  console.warn('Chart.js unavailable; charts disabled');
}

// ── Analysis tab ──────────────────────────────────────────────────────────────
analyzeForm.addEventListener('submit', async e => {
  e.preventDefault();
  const d = domainInput.value.trim();
  if (!d) return;
  await analyzeDomain(d);
});
domainInput.addEventListener('keydown', async e => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  const d = domainInput.value.trim();
  if (!d) return;
  await analyzeDomain(d);
});
quickActions.addEventListener('click', async e => {
  const btn = e.target.closest('button[data-domain]');
  if (!btn) return;
  domainInput.value = btn.dataset.domain;
  await analyzeDomain(btn.dataset.domain);
});

osintBtn.addEventListener('click', async () => {
  const d = domainInput.value.trim() || (state.latest && state.latest.domain);
  if (!d) return;
  await analyzeDomain(d, true);
});

async function analyzeDomain(domain, forceEvidence) {
  analyzeBtn.disabled = true;
  osintBtn.disabled = true;
  setTextWithMotion(resultState, forceEvidence ? 'checking public evidence...' : 'analyzing...', resultState);
  // Signal sweep on the result panel while analyzing
  pulseNode(document.querySelector('.result-panel'), 'signal-sweep');
  try {
    const suffix = '?include_evidence=1' + (forceEvidence ? '&force_osint=1' : '');
    const r = await fetch('/v1/analyze' + suffix, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const payload = await r.json();
    state.latest = payload;
    renderResult(payload);
    await loadRecent();
    setTextWithMotion(resultState, 'fresh result', resultState);
  } catch {
    resultEl.innerHTML = '<div class="empty">Request failed.</div>';
    setTextWithMotion(resultState, 'request failed', resultState);
  } finally {
    analyzeBtn.disabled = false;
    osintBtn.disabled = false;
  }
}

async function loadRecent() {
  try {
    const r = await fetch('/v1/analysis/recent');
    const payload = await r.json();
    const items = payload.items || [];
    state.recent = items;
    setTextWithMotion(recentCount, items.length, recentCount.closest('.panel-head'));
    recentEl.innerHTML = items.length
      ? items.map(renderRecentItem).join('')
      : '<div class="empty">No cached history.</div>';
    markInsertedRows(recentEl, '.recent-item');
    if (!state.latest && items.length) renderResult(items[0]);
  } catch {
    recentEl.innerHTML = '<div class="empty">Recent unavailable.</div>';
  }
}

function renderResult(item) {
  const blocked = item.verdict === 'MALICIOUS';
  const policyLabel = blocked ? 'Block' : 'Allow';
  const policyClass = blocked ? 'badge-block' : 'badge-allow';
  const verdict = esc(item.verdict || 'UNKNOWN');
  const risk = riskClass(item.verdict);
  const score = clampScore(item.score);
  const confidence = Math.round((Number(item.confidence) || 0) * 100);
  const reasons = (item.reasons && item.reasons.length)
    ? '<div class="signals-list">' + item.reasons.map(r => '<div class="signal-row"><span></span><strong>' + esc(r) + '</strong></div>').join('') + '</div>'
    : '<div class="signals-list"><div class="signal-row muted"><span></span><strong>No risk signals reported.</strong></div></div>';
  const evidence = renderEvidence(item.evidence || []);
  const reviewPanel = renderFalsePositiveReviewPanel(item);
  resultEl.innerHTML =
    '<article class="result-body dossier ' + risk + '">' +
      '<div class="dossier-hero">' +
        '<div class="dossier-title">' +
          '<span class="verdict ' + verdict + '">' + verdict + '</span>' +
          '<h3>' + esc(item.domain) + '</h3>' +
          '<p>Policy default: <span class="' + policyClass + '">' + policyLabel + '</span></p>' +
        '</div>' +
        '<div class="score-orbit" style="--score:' + score + '">' +
          '<strong>' + score + '</strong>' +
          '<span>/100</span>' +
        '</div>' +
      '</div>' +
      '<div class="risk-meter" aria-label="Risk score">' +
        '<div class="risk-meter-track"><span style="width:' + score + '%"></span></div>' +
        '<div class="risk-meter-labels"><span>Low</span><span>Review</span><span>Block</span></div>' +
      '</div>' +
      '<div class="facts-grid">' +
        '<div><span>Verdict</span><strong class="' + verdict + '">' + verdict + '</strong></div>' +
        '<div><span>Confidence</span><strong>' + confidence + '%</strong></div>' +
        '<div><span>Category</span><strong>' + esc(item.category || 'uncategorized') + '</strong></div>' +
        '<div><span>Cache state</span><strong>' + (item.cache_hit ? 'hit' : 'fresh') + '</strong></div>' +
        '<div><span>Analyzed</span><strong>' + fmtTime(item.analyzed_at) + '</strong></div>' +
        '<div><span>Policy</span><strong><span class="' + policyClass + '">' + policyLabel + '</span></strong></div>' +
      '</div>' +
      '<section class="dossier-section"><div class="section-kicker">Signals</div>' + reasons + '</section>' +
      evidence +
      reviewPanel +
    '</article>';
  // Comet-in entrance for all child sections
  if (motionOK()) {
    requestAnimationFrame(() => {
      resultEl.querySelectorAll('.dossier-section, .review-panel, .facts-grid').forEach((el, i) => {
        el.classList.add('comet-in');
        el.style.setProperty('--comet-delay', Math.min(i * 40, 200) + 'ms');
      });
    });
  }
}

function renderFalsePositiveReviewPanel(item) {
  if (!item || !item.domain || item.verdict === 'SAFE') {
    return '';
  }
  const actions = state.session.readOnly
    ? '<div class="review-actions"><span class="report-completed">' + esc(sessionGuestMessage()) + '</span></div>'
    : '<div class="review-actions">' +
        '<button type="button" class="btn-allow" data-action="submit-false-positive-review">Allow / whitelist domain</button>' +
        '<button type="button" class="ghost btn-sm" data-action="open-override-editor" data-domain="' + escAttr(item.domain) + '" data-override-action="allow">Open override form</button>' +
      '</div>';
  return '<section class="review-panel">' +
    '<div class="review-head">' +
      '<div><span class="section-kicker">Operator Action</span><strong>False-positive review</strong></div>' +
      '<span class="chip warn">operator action</span>' +
    '</div>' +
    '<p class="review-note">Use this when the domain was blocked or escalated incorrectly and should be pinned as allowed while follow-up review continues.</p>' +
    '<label for="fp-review-reason">Review note</label>' +
    '<textarea id="fp-review-reason" placeholder="Example: verified legitimate partner portal, matched owner DNS/TLS, approved by ops review."></textarea>' +
    actions +
  '</section>';
}

function renderEvidence(items) {
  if (!items.length) {
    return '<section class="dossier-section"><div class="section-kicker">Evidence</div><div class="empty evidence-empty">No public warning evidence cached for this domain.</div></section>';
  }
  return '<section class="dossier-section"><div class="section-kicker">Evidence</div><div class="evidence-list">' + items.map(ev => {
    const confidence = Math.round((ev.confidence || 0) * 100);
    const terms = (ev.matched_terms || []).slice(0, 4).map(t => '<span>' + esc(t) + '</span>').join('');
    const title = ev.source_title || ev.source_url || 'public source';
    return '<article class="evidence-item">' +
      '<div class="evidence-top">' +
        '<strong>' + esc(title) + '</strong>' +
        '<span class="chip warn">' + confidence + '%</span>' +
      '</div>' +
      '<div class="recent-meta"><span>' + esc(ev.source_type || 'source') + '</span><span>' + fmtTime(ev.retrieved_at) + '</span></div>' +
      '<a href="' + esc(ev.source_url) + '" target="_blank" rel="noopener noreferrer">' + esc(ev.source_url) + '</a>' +
      '<div class="recent-tags">' + (terms || '<span>domain matched</span>') + '</div>' +
    '</article>';
  }).join('') + '</div></section>';
}

function renderRecentItem(item) {
  const verdict = esc(item.verdict || 'UNKNOWN');
  const confidence = Math.round((Number(item.confidence) || 0) * 100);
  return '<article class="recent-item event-item ' + riskClass(item.verdict) + '">' +
    '<div class="recent-top">' +
      '<div class="recent-domain">' + esc(item.domain) + '</div>' +
      '<span class="verdict ' + verdict + '">' + verdict + '</span>' +
    '</div>' +
    '<div class="recent-meta">' +
      '<span>score ' + clampScore(item.score) + '</span>' +
      '<span>' + confidence + '% confidence</span>' +
      '<span>' + fmtTime(item.analyzed_at) + '</span>' +
    '</div>' +
    '<div class="risk-intensity" style="--risk-level:' + clampScore(item.score) + '%"><span></span></div>' +
    '<button class="ghost btn-sm" type="button" data-action="open-dossier" data-domain="' + escAttr(item.domain) + '">Open dossier</button>' +
    '</article>';
}

// ── Telemetry tab ─────────────────────────────────────────────────────────────
document.querySelectorAll('.period-btn').forEach(btn => {
  btn.setAttribute('aria-pressed', btn.classList.contains('active') ? 'true' : 'false');
  btn.addEventListener('click', () => {
    document.querySelectorAll('.period-btn').forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-pressed', 'false');
    });
    btn.classList.add('active');
    btn.setAttribute('aria-pressed', 'true');
    state.telemetry.period = btn.dataset.period;
    state.telemetry.page = 0;
    pulseNode(btn.closest('.period-switcher'), 'stellar-pulse');
    loadTelemetry();
  });
});

const telemetryFilterInputs = [
  ['telem-domain-filter', 'domain'],
  ['telem-verdict-filter', 'verdict'],
  ['telem-source-filter', 'source'],
];
let telemetryFilterTimer;
telemetryFilterInputs.forEach(([id, key]) => {
  const el = $(id);
  if (!el) return;
  el.addEventListener('input', () => {
    state.telemetry.filters[key] = el.value.trim();
    state.telemetry.page = 0;
    clearTimeout(telemetryFilterTimer);
    telemetryFilterTimer = setTimeout(loadTelemetryItems, 180);
  });
});
if ($('telem-clear-filters')) {
  $('telem-clear-filters').addEventListener('click', () => {
    state.telemetry.filters = { domain: '', verdict: '', source: '' };
    telemetryFilterInputs.forEach(([id]) => {
      const el = $(id);
      if (el) el.value = '';
    });
    state.telemetry.page = 0;
    loadTelemetryItems();
  });
}
$('telem-prev').addEventListener('click', () => {
  if (state.telemetry.page > 0) { state.telemetry.page--; loadTelemetryItems(); }
});
$('telem-next').addEventListener('click', () => {
  state.telemetry.page++;
  loadTelemetryItems();
});

async function loadTelemetry() {
  await Promise.all([loadTelemetryStats(), loadTelemetryItems(), loadReports()]);
}

async function loadTelemetryStats() {
  try {
    const r = await fetch('/v1/telemetry/stats?period=' + state.telemetry.period);
    const s = await r.json();
    state.telemetry.stats = s;
    const statsGrid = document.querySelector('.stats-grid');
    setTextWithMotion($('st-total'), (s.total || 0).toLocaleString(), statsGrid);
    setTextWithMotion($('st-safe'), (s.safe || 0).toLocaleString());
    setTextWithMotion($('st-suspicious'), (s.suspicious || 0).toLocaleString());
    setTextWithMotion($('st-malicious'), (s.malicious || 0).toLocaleString());
    setTextWithMotion($('st-cache'), (s.cache_hits || 0).toLocaleString());
    // Update header metrics too
    setTextWithMotion(metricTotal, (s.total || 0).toLocaleString(), metricTotal.closest('.metric'));
    setTextWithMotion(metricSafe, (s.safe || 0).toLocaleString(), metricSafe.closest('.metric'));
    setTextWithMotion(metricSusp, (s.suspicious || 0).toLocaleString(), metricSusp.closest('.metric'));
    setTextWithMotion(metricMal, (s.malicious || 0).toLocaleString(), metricMal.closest('.metric'));
    setTextWithMotion(metricCache, (s.cache_hits || 0).toLocaleString(), metricCache.closest('.metric'));
    renderChart(s);
    renderCacheHitMeter(s);
  } catch {
    // fail silently
  }
}

function renderCacheHitMeter(s) {
  const el = $('cache-hit-meter');
  if (!el) return;
  const total = s.total || 0;
  const hits = s.cache_hits || 0;
  const pctVal = total > 0 ? Math.min(100, Math.round(hits / total * 100)) : 0;
  el.innerHTML =
    '<div class="cache-meter-label"><span>Cache efficiency</span><span class="cache-meter-pct">' + pctVal + '%</span></div>' +
    '<div class="cache-meter-track"><div class="cache-meter-fill" style="width:' + pctVal + '%"></div></div>';
}

async function loadTelemetryItems() {
  const offset = state.telemetry.page * state.telemetry.pageSize;
  try {
    const params = new URLSearchParams({
      limit: String(state.telemetry.pageSize),
      offset: String(offset),
      period: state.telemetry.period,
    });
    const filters = state.telemetry.filters || {};
    if (filters.domain) params.set('domain', filters.domain);
    if (filters.verdict) params.set('verdict', filters.verdict);
    if (filters.source) params.set('source', filters.source);
    const r = await fetch('/v1/telemetry/recent?' + params.toString());
    const payload = await r.json();
    const items = payload.items || [];
    state.telemetry.items = items;
    const filterCount = Object.values(filters).filter(Boolean).length;
    setTextWithMotion($('telem-info'), 'Page ' + (state.telemetry.page + 1) + (filterCount ? ' · ' + filterCount + ' filters' : ''));
    setTextWithMotion($('telem-page'), 'Page ' + (state.telemetry.page + 1));
    $('telem-prev').disabled = state.telemetry.page === 0;
    $('telem-next').disabled = items.length < state.telemetry.pageSize;
    $('telem-body').innerHTML = items.length
      ? items.map(renderTelemRow).join('')
      : '<div class="empty">No telemetry data for this period.</div>';
    renderSourceMix(items);
    markInsertedRows($('telem-body'), '.telemetry-row');
  } catch {
    $('telem-body').innerHTML = '<div class="empty">Telemetry unavailable.</div>';
    renderSourceMix([]);
  }
}

function renderTelemRow(item) {
  const actionCell = item.verdict === 'SAFE'
    ? '<button class="ghost btn-sm" data-action="open-dossier" data-domain="' + escAttr(item.domain) + '">Open</button>'
    : '<button class="ghost btn-sm" data-action="open-false-positive-review" data-domain="' + escAttr(item.domain) + '">Review</button>';
  return '<div class="telemetry-row">' +
    '<div class="cell-domain-emph">' + esc(item.domain) + '</div>' +
    '<div><span class="verdict ' + item.verdict + '">' + esc(item.verdict) + '</span></div>' +
    '<div><span class="score-spark" style="--risk-level:' + clampScore(item.score) + '%">' + item.score + '</span></div>' +
    '<div class="cell-muted">' + esc(item.source || '--') + '</div>' +
    '<div class="cell-muted">' + fmtTime(item.analyzed_at) + '</div>' +
    '<div>' + actionCell + '</div>' +
    '</div>';
}

function renderSourceMix(items) {
  const el = $('source-mix');
  if (!el) return;
  if (!items.length) {
    el.innerHTML = '<span class="source-chip muted">No page data</span>';
    setTextWithMotion($('source-mix-label'), 'current page');
    return;
  }
  const counts = items.reduce((acc, item) => {
    const source = item.source || 'unknown';
    acc[source] = (acc[source] || 0) + 1;
    return acc;
  }, {});
  const total = items.length;
  el.innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([source, count]) => '<span class="source-chip"><strong>' + esc(source) + '</strong>' + pct(count, total) + '</span>')
    .join('');
  setTextWithMotion($('source-mix-label'), total + ' rows');
}

function renderChart(s) {
  const safe    = s.safe || 0;
  const susp    = s.suspicious || 0;
  const mal     = s.malicious || 0;
  const meaningfulTotal = safe + susp + mal;
  renderRiskMix(safe, susp, mal);
  const chartWrap = document.querySelector('.chart-wrap');
  if (chartWrap) {
    chartWrap.classList.toggle('telemetry-empty', meaningfulTotal === 0);
    if (meaningfulTotal > 0) pulseNode(chartWrap, 'orbit-wake');
  }
  if (!window.CHARTJS_AVAILABLE || typeof Chart === 'undefined') {
    $('chart-legend').textContent = 'Charting asset unavailable.';
    return;
  }
  const styles = getComputedStyle(document.documentElement);
  const safeColor = styles.getPropertyValue('--safe').trim() || '#33d399';
  const warnColor = styles.getPropertyValue('--warn').trim() || '#f6b94b';
  const badColor = styles.getPropertyValue('--bad').trim() || '#ff5f86';
  const gridColor = styles.getPropertyValue('--line').trim() || 'rgba(255,255,255,0.1)';
  const total   = safe + susp + mal || 1;
  $('chart-legend').innerHTML =
    '<span class="legend-safe">Safe ' + pct(safe,total) + '</span> / ' +
    '<span class="legend-warn">Suspicious ' + pct(susp,total) + '</span> / ' +
    '<span class="legend-bad">Malicious ' + pct(mal,total) + '</span>';
  const canvas = $('verdict-chart');
  if (state.chart) { state.chart.destroy(); state.chart = null; }
  state.chart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Malicious'],
      datasets: [{
        data: [safe, susp, mal],
        backgroundColor: [safeColor, warnColor, badColor],
        borderColor: gridColor,
        borderWidth: 2,
        hoverOffset: 8
      }],
    },
    options: {
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ctx.label + ': ' + ctx.parsed.toLocaleString() } }
      },
      animation: { duration: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 400 },
    },
  });
}

function renderRiskMix(safe, susp, mal) {
  const total = safe + susp + mal;
  const el = $('risk-mix-meter');
  if (!el) return;
  const safePct = total ? Math.round(safe / total * 100) : 0;
  const suspPct = total ? Math.round(susp / total * 100) : 0;
  const malPct = total ? Math.max(0, 100 - safePct - suspPct) : 0;
  el.innerHTML =
    '<span class="mix-safe" style="width:' + safePct + '%"></span>' +
    '<span class="mix-suspicious" style="width:' + suspPct + '%"></span>' +
    '<span class="mix-malicious" style="width:' + malPct + '%"></span>';
  setTextWithMotion($('risk-mix-label'), total ? (suspPct + malPct) + '% risk' : '0%');
}

// ── Overrides tab ─────────────────────────────────────────────────────────────
document.querySelectorAll('.ov-filter').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.ov-filter').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.overrides.filter = btn.dataset.filter;
    renderOverrides();
  });
});

const ovAction = $('ov-action');
ovAction.addEventListener('change', () => {
  $('ov-submit').className = 'btn-sm ' + (ovAction.value === 'block' ? 'btn-block' : 'btn-allow');
  $('ov-submit').textContent = ovAction.value === 'block' ? '+ Block' : '+ Allow';
});

$('override-form').addEventListener('submit', async e => {
  e.preventDefault();
  const domain = $('ov-domain').value.trim();
  const action = $('ov-action').value;
  const reason = $('ov-reason').value.trim();
  if (!domain) return;
  try {
    const r = await fetch('/v1/overrides', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, action, reason }),
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Override saved: ' + domain + ' -> ' + action, 'ok');
    $('ov-domain').value = '';
    $('ov-reason').value = '';
    await loadOverrides();
  } catch(err) {
    showToast('Error: ' + err.message, 'err');
  }
});

async function loadOverrides() {
  try {
    const r = await fetch('/v1/overrides');
    const payload = await r.json();
    state.overrides.items = payload.items || [];
    renderOverrides();
  } catch {
    $('ov-tbody').innerHTML = '<tr><td colspan="5" class="empty">Overrides unavailable.</td></tr>';
  }
}

function renderOverrides() {
  const filter = state.overrides.filter;
  const items  = filter ? state.overrides.items.filter(i => i.action === filter) : state.overrides.items;
  $('ov-count').textContent = items.length + ' override' + (items.length === 1 ? '' : 's');
  $('ov-tbody').innerHTML = items.length
    ? items.map(renderOverrideRow).join('')
    : '<tr><td colspan="5" class="empty">No overrides match this filter.</td></tr>';
}

function renderOverrideRow(item) {
  const badgeClass = item.action === 'block' ? 'badge-block' : 'badge-allow';
  const actionCell = state.session.readOnly
    ? '<span class="report-completed">Read only</span>'
    : '<button class="ghost btn-sm btn-danger" data-action="delete-override" data-domain="' + escAttr(item.domain) + '">Delete</button>';
  return '<tr>' +
    '<td class="cell-strong">' + esc(item.domain) + '</td>' +
    '<td><span class="' + badgeClass + '">' + esc(item.action) + '</span></td>' +
    '<td class="cell-muted">' + esc(item.reason || '--') + '</td>' +
    '<td class="cell-muted">' + fmtTime(item.updated_at) + '</td>' +
    '<td>' + actionCell + '</td>' +
    '</tr>';
}

async function deleteOverride(domain) {
  if (!confirm('Delete override for ' + domain + '?')) return;
  try {
    const r = await fetch('/v1/overrides?domain=' + encodeURIComponent(domain), { method: 'DELETE' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Override deleted: ' + domain, 'ok');
    await loadOverrides();
  } catch(err) {
    showToast('Error: ' + err.message, 'err');
  }
}

// ── Brand Spoofing Rules CRUD ──────────────────────────────────────────────────
async function loadBrands() {
  try {
    const r = await fetch('/v1/brands');
    const payload = await r.json();
    state.brands.items = payload.items || [];
    renderBrands();
  } catch {
    $('brand-tbody').innerHTML = '<tr><td colspan="6" class="empty">Brands unavailable.</td></tr>';
  }
}

function renderBrands() {
  const items = state.brands.items;
  $('brand-count').textContent = items.length + ' protected brand' + (items.length === 1 ? '' : 's');
  $('brand-tbody').innerHTML = items.length
    ? items.map(renderBrandRow).join('')
    : '<tr><td colspan="6" class="empty">No protected brands.</td></tr>';
}

function renderBrandRow(item) {
  const alts = (item.alt_domains || []).map(alt => `<span class="badge-allow tag-inline-badge">${esc(alt)}</span>`).join('');
  const actionCell = state.session.readOnly
    ? '<span class="report-completed">Read only</span>'
    : '<button class="ghost btn-sm brand-edit-btn" data-action="edit-brand" data-brand-id="' + item.id + '">Edit</button>' +
      '<button class="ghost btn-sm btn-danger" data-action="delete-brand" data-brand-id="' + item.id + '">Delete</button>';
  return '<tr>' +
    '<td class="cell-muted">' + esc(item.id) + '</td>' +
    '<td class="cell-strong">' + esc(item.name) + '</td>' +
    '<td><a href="http://' + esc(item.official_domain) + '" target="_blank" class="brand-domain-link">' + esc(item.official_domain) + '</a></td>' +
    '<td>' + (alts || '<span class="cell-muted">--</span>') + '</td>' +
    '<td class="cell-muted">' + fmtTime(item.updated_at || item.created_at) + '</td>' +
    '<td>' + actionCell + '</td>' +
    '</tr>';
}

async function handleBrandSubmit(e) {
  e.preventDefault();
  const id = $('brand-id').value;
  const name = $('brand-name').value.trim();
  const official_domain = $('brand-official-domain').value.trim();
  const altsInput = $('brand-alt-domains').value;
  const alt_domains = altsInput ? altsInput.split(',').map(s => s.trim()).filter(s => s.length > 0) : [];

  if (!name || !official_domain) {
    showToast('Name and Official Domain are required', 'err');
    return;
  }

  const payload = { name, official_domain, alt_domains };
  const method = id ? 'PUT' : 'POST';
  const url = id ? `/v1/brands?id=${id}` : '/v1/brands';

  try {
    const r = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast(id ? 'Brand updated successfully' : 'Brand added successfully', 'ok');
    resetBrandForm();
    await loadBrands();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

function editBrand(id) {
  const item = state.brands.items.find(b => b.id === id);
  if (!item) {
    showToast('Brand not found', 'err');
    return;
  }
  $('brand-id').value = item.id;
  $('brand-name').value = item.name;
  $('brand-official-domain').value = item.official_domain;
  $('brand-alt-domains').value = (item.alt_domains || []).join(', ');
  $('brand-form-title').textContent = 'Edit Protected Brand';
  $('brand-submit').textContent = 'Update Brand';
  $('brand-name').focus();
}

function resetBrandForm() {
  $('brand-id').value = '';
  $('brand-name').value = '';
  $('brand-official-domain').value = '';
  $('brand-alt-domains').value = '';
  $('brand-form-title').textContent = 'Add Protected Brand';
  $('brand-submit').textContent = 'Add Brand';
}

async function deleteBrand(id) {
  if (!confirm('Delete protected brand rule (ID: ' + id + ')?')) return;
  try {
    const r = await fetch(`/v1/brands?id=${id}`, { method: 'DELETE' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Protected brand rule deleted', 'ok');
    if ($('brand-id').value == id) {
      resetBrandForm();
    }
    await loadBrands();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

function openOverrideEditor(domain, action) {
  switchTab('overrides');
  $('ov-domain').value = domain || '';
  $('ov-action').value = action || 'allow';
  $('ov-reason').value = 'manual operator review';
  ovAction.dispatchEvent(new Event('change'));
  $('ov-reason').focus();
}

function openDossier(domain) {
  switchTab('analysis');
  const input = document.getElementById('domain-input');
  if (input) input.value = domain || '';
  analyzeDomain(domain);
}

async function openFalsePositiveReview(domain) {
  switchTab('analysis');
  domainInput.value = domain || '';
  await analyzeDomain(domain);
  const reasonInput = $('fp-review-reason');
  if (reasonInput) {
    reasonInput.focus();
  }
}

async function submitFalsePositiveReview() {
  const latest = state.latest;
  if (!latest || !latest.domain) {
    showToast('Analyze a domain first', 'err');
    return;
  }

  const reasonInput = $('fp-review-reason');
  const reason = (reasonInput && reasonInput.value || '').trim();
  if (!reason) {
    showToast('Review note is required', 'err');
    if (reasonInput) reasonInput.focus();
    return;
  }

  try {
    const r = await fetch('/v1/overrides/review-false-positive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: latest.domain,
        reason,
        source: 'dashboard_analysis',
        previous_action: latest.verdict === 'MALICIOUS' ? 'block' : 'review'
      }),
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Domain moved to allow override: ' + latest.domain, 'ok');
    if (reasonInput) reasonInput.value = '';
    await Promise.all([loadOverrides(), analyzeDomain(latest.domain)]);
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

// ── System tab ────────────────────────────────────────────────────────────────
async function loadSystem() {
  await Promise.all([checkHealth(), loadMetrics(), loadAgentStatus()]);
}

async function checkHealth() {
  try {
    const status = await (await fetch('/v1/status')).json();
    const ok = status.status === 'ok';
    apiStatus.className = ok ? 'chip ok' : 'chip warn';
    setHTMLWithMotion(apiStatus, '<strong>core-api</strong> ' + (ok ? 'healthy' : 'limited'), apiStatus);
    pulseNode(apiStatus, 'stellar-pulse');
    setTextWithMotion($('sys-api-status'), ok ? 'Online' : 'Limited');
    $('sys-api-status').style.color = ok ? 'var(--safe)' : 'var(--warn)';
    setTextWithMotion($('sys-api-detail'), 'mode: ' + (status.mode || 'api'));
    // Redis
    const redis = status.redis || {};
    const redisOk = redis.status === 'ok';
    setTextWithMotion($('sys-redis-status'), redis.configured ? (redisOk ? 'Connected' : 'Unavailable') : 'Disabled');
    $('sys-redis-status').style.color = redis.configured ? (redisOk ? 'var(--safe)' : 'var(--warn)') : 'var(--muted)';
    setTextWithMotion($('sys-redis-detail'), redis.configured ? (redis.error || 'operational') : 'no Redis configured');
    setHTMLWithMotion(cacheEngineState, redis.configured && redisOk ? '<strong>cache engine</strong> ok' : '<strong>cache engine</strong> offline', cacheEngineState);
    pulseNode(cacheEngineState, 'stellar-pulse');
    // Enrichment assumed enabled by default
    setTextWithMotion($('sys-enrich-status'), 'Enabled');
    $('sys-enrich-status').style.color = 'var(--safe)';
    // Rate Limiting
    const rl = status.rate_limiting || {};
    if (rl.enabled) {
      rlStatus.className = 'chip ok';
      setHTMLWithMotion(rlStatus, '<strong>rate limit</strong> active', rlStatus);
    } else {
      rlStatus.className = 'chip';
      setHTMLWithMotion(rlStatus, '<strong>rate limit</strong> disabled', rlStatus);
    }
  } catch {
    apiStatus.className = 'chip bad';
    setHTMLWithMotion(apiStatus, '<strong>core-api</strong> offline', apiStatus);
    pulseNode(apiStatus, 'stellar-pulse');
    setTextWithMotion($('sys-api-status'), 'Offline');
    $('sys-api-status').style.color = 'var(--bad)';
  }
}

async function loadMetrics() {
  try {
    const r = await fetch('/metrics');
    const data = await r.json();
    const snap = data.metrics || {};
    const uptime = snap.uptime_seconds || 0;
    setTextWithMotion($('sys-uptime'), 'Uptime: ' + fmtUptime(uptime));
    const summary = snap.request_summary || {};
    const rows = Object.entries(summary).map(([key, val]) => {
      const avg = val.count ? Math.round(val.total_duration_ms / val.count) : 0;
      const max = val.max_duration_ms || 0;
      const latencyPct = max ? Math.min(100, Math.max(4, Math.round(avg / max * 100))) : 0;
      return '<tr>' +
        '<td class="cell-strong">' + esc(key) + '</td>' +
        '<td>' + (val.count || 0).toLocaleString() + '</td>' +
        '<td><span class="latency-readout">' + avg + 'ms</span><span class="latency-bars" style="--latency-level:' + latencyPct + '%"><i></i></span></td>' +
        '<td>' + max + 'ms</td>' +
        '<td>' + (val.last_status || '--') + '</td>' +
        '</tr>';
    });
    const totalReqs = Object.values(summary).reduce((s, v) => s + (v.count || 0), 0);
    setTextWithMotion($('sys-total-reqs'), totalReqs.toLocaleString() + ' total requests');
    $('metrics-tbody').innerHTML = rows.length ? rows.join('') : '<tr><td colspan="5" class="empty">No metrics yet.</td></tr>';
    markInsertedRows($('metrics-tbody'), 'tr');
  } catch {
    $('metrics-tbody').innerHTML = '<tr><td colspan="5" class="empty">Metrics unavailable.</td></tr>';
  }
}

async function loadAgentStatus() {
  try {
    const r = await fetch('/v1/agent/status');
    const data = await r.json();
    const s = data.status || data;
    const overall = $('agent-overall-status');
    if (!s.enabled) {
      setTextWithMotion(overall, 'Disabled');
      overall.style.color = 'var(--muted)';
      $('agent-panel-body').innerHTML = '<div class="empty">Agent Engine is disabled (SAFE_ZONE_AGENT_ENABLED=false).</div>';
    } else {
      setTextWithMotion(overall, 'Active');
      overall.style.color = 'var(--safe)';
      
      const tasks = s.tasks || [];
      if (!tasks.length) {
        $('agent-panel-body').innerHTML = '<div class="empty">No tasks registered in Agent Engine.</div>';
      } else {
        const rows = tasks.map(t => {
          const stateClass = t.state === 'running' ? 'badge-allow' : (t.state === 'failed' ? 'badge-block' : '');
          const stateLabel = t.state === 'running' ? 'Running' : (t.state === 'failed' ? 'Failed' : 'Idle');
          const statusPulse = t.state === 'running' ? ' agent-status-pulse' : '';
          const lastErr = t.last_error ? `<span class="latency-error-text">${esc(t.last_error)}</span>` : '--';
          
          return '<tr>' +
            '<td class="cell-strong">' + esc(t.name) + '</td>' +
            '<td><span class="' + stateClass + statusPulse + '">' + stateLabel + '</span></td>' +
            '<td>' + esc(t.interval) + '</td>' +
            '<td>' + fmtTime(t.last_run) + '</td>' +
            '<td>' + fmtTime(t.next_run) + '</td>' +
            '<td>' + t.run_count + ' / ' + t.error_count + '</td>' +
            '<td class="cell-truncate-200" title="' + esc(t.last_error) + '">' + lastErr + '</td>' +
            '<td><button class="ghost btn-sm" data-action="trigger-agent-task" data-task-name="' + escAttr(t.name) + '">Trigger</button></td>' +
            '</tr>';
        });
        
        $('agent-panel-body').innerHTML = 
          '<div class="table-wrap"><table class="override-table">' +
            '<thead><tr><th>Task Name</th><th>Status</th><th>Interval</th><th>Last Run</th><th>Next Run</th><th>Runs / Errors</th><th>Last Error</th><th>Action</th></tr></thead>' +
            '<tbody>' + rows.join('') + '</tbody>' +
          '</table></div>';
        markInsertedRows($('agent-panel-body'), 'tbody tr');
      }
    }

    // --- Render Whitelist and Storage Stats ---
    if (data.whitelist_stats) {
      const wl = data.whitelist_stats;
      setTextWithMotion($('wl-loaded'), (wl.loaded_domains || 0).toLocaleString());
      setTextWithMotion($('wl-size'), (wl.bloom_size_ram_kb || 0).toFixed(2) + ' KB');
      setTextWithMotion($('wl-hashes'), (wl.bloom_hashes || 0).toLocaleString());
      setTextWithMotion($('wl-bits'), (wl.bloom_bits || 0).toLocaleString());
      setTextWithMotion($('wl-fpr'), ((wl.fpr || 0) * 100) + '%');
    }

    if (data.database_stats) {
      const db = data.database_stats;
      setTextWithMotion($('db-file-size'), (db.file_size_mb || 0).toFixed(2) + ' MB');
      setTextWithMotion($('db-disk-free'), (db.disk_free_gb || 0).toFixed(2) + ' GB');
    }

    if (typeof data.telemetry_retention_days === 'number') {
      const days = data.telemetry_retention_days;
      updateRetentionSliderVal(days);
    }
  } catch (err) {
    $('agent-panel-body').innerHTML = '<div class="empty">Error loading Agent status: ' + esc(err.message) + '</div>';
  }
}

async function triggerAgentTask(name) {
  if (!confirm('Manually trigger agent task "' + name + '"?')) return;
  try {
    const r = await fetch('/v1/agent/trigger?task=' + encodeURIComponent(name), {
      method: 'POST'
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Task "' + name + '" triggered successfully', 'ok');
    await loadAgentStatus();
  } catch(err) {
    showToast('Error: ' + err.message, 'err');
  }
}

// ── Clients & Policies tab ───────────────────────────────────────────────────
async function loadClientsTab() {
  await Promise.all([loadGroups(), loadMappings()]);
  await loadGroupOverrides();
}

async function loadGroups() {
  try {
    const r = await fetch('/v1/groups');
    const payload = await r.json();
    const groups = payload.items || [];
    state.clients.groups = groups;

    // Populate select elements
    const mapGroupSelect = $('map-group-input');
    const ovGroupSelect = $('override-group-select');
    const prevSelectedGroup = ovGroupSelect.value;

    mapGroupSelect.innerHTML = groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('');
    ovGroupSelect.innerHTML = groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('');

    if (prevSelectedGroup && groups.some(g => String(g.id) === prevSelectedGroup)) {
      ovGroupSelect.value = prevSelectedGroup;
    } else if (groups.length > 0) {
      ovGroupSelect.value = groups[0].id;
    }

    $('groups-grid').innerHTML = groups.length
      ? groups.map(renderGroupCard).join('')
      : '<div class="empty">No policy groups configured.</div>';
  } catch (err) {
    $('groups-grid').innerHTML = '<div class="empty">Error loading groups: ' + esc(err.message) + '</div>';
  }
}

function renderGroupCard(g) {
  const blockCategories = g.block_categories || [];
  const badges = blockCategories.map(c => `<span class="grp-badge">${esc(c)}</span>`).join('');
  const strictPhish = g.strict_phishing ? '<span class="active">Strict Phishing on</span>' : '<span>Strict Phishing off</span>';
  const strictMal = g.strict_malware ? '<span class="active">Strict Malware on</span>' : '<span>Strict Malware off</span>';

  const deleteBtn = (g.id === 1 || g.name.toLowerCase() === 'default')
    ? ''
    : `<button class="ghost btn-sm btn-danger" data-action="delete-group" data-group-id="${g.id}" data-group-name="${escAttr(g.name)}">Delete</button>`;

  return `<div class="group-card">
    <div class="grp-header">
      <strong class="grp-name">${esc(g.name)}</strong>
      <span class="group-meta-note">ID: ${g.id}</span>
    </div>
    <p class="grp-desc">${esc(g.description || 'No description')}</p>
    <div class="grp-badges">
      ${badges || '<span class="grp-badge grp-badge-muted">no blocked categories</span>'}
    </div>
    <div class="grp-features grp-features-gap">
      ${strictPhish} &middot; ${strictMal}
    </div>
    <div class="grp-actions">
      <button class="ghost btn-sm" data-action="open-edit-group-modal" data-group-id="${g.id}">Edit</button>
      ${deleteBtn}
    </div>
  </div>`;
}

async function loadMappings() {
  try {
    const r = await fetch('/v1/mappings');
    const payload = await r.json();
    const mappings = payload.items || [];
    state.clients.mappings = mappings;
    $('mappings-tbody').innerHTML = mappings.length
      ? mappings.map(renderMappingRow).join('')
      : '<tr><td colspan="5" class="empty">No client mappings configured.</td></tr>';
  } catch (err) {
    $('mappings-tbody').innerHTML = '<tr><td colspan="5" class="empty">Error: ' + esc(err.message) + '</td></tr>';
  }
}

function renderMappingRow(item) {
  const typeLabels = {
    'ip': 'IP Address',
    'cidr': 'CIDR Range',
    'client_id': 'DoH Client ID'
  };
  const typeLabel = typeLabels[item.mapping_type] || item.mapping_type;
  return '<tr>' +
    '<td>' + esc(typeLabel) + '</td>' +
    '<td class="cell-strong">' + esc(item.value) + '</td>' +
    '<td><span class="chip chip-accent">' + esc(item.group_name || ('Group ID ' + item.group_id)) + '</span></td>' +
    '<td class="cell-muted">' + fmtTime(item.created_at) + '</td>' +
    '<td><button class="ghost btn-sm btn-danger" data-action="delete-mapping" data-mapping-id="' + item.id + '">Delete</button></td>' +
    '</tr>';
}

async function deleteMapping(id) {
  if (!confirm('Delete this client mapping?')) return;
  try {
    const r = await fetch('/v1/mappings?id=' + id, { method: 'DELETE' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Mapping deleted successfully', 'ok');
    await loadMappings();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function handleMappingSubmit(e) {
  e.preventDefault();
  const mapping_type = $('map-type-input').value;
  const value = $('map-value-input').value.trim();
  const group_id = parseInt($('map-group-input').value, 10);

  if (!value) {
    showToast('Mapping value is required', 'err');
    return;
  }
  if (isNaN(group_id) || group_id <= 0) {
    showToast('Valid group selection is required', 'err');
    return;
  }

  try {
    const r = await fetch('/v1/mappings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mapping_type, value, group_id })
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Mapping added successfully', 'ok');
    $('map-value-input').value = '';
    await loadMappings();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function loadGroupOverrides() {
  const group_id = parseInt($('override-group-select').value, 10);
  if (!group_id || isNaN(group_id)) {
    $('group-overrides-tbody').innerHTML = '<tr><td colspan="5" class="empty">Select a group to load overrides.</td></tr>';
    return;
  }
  try {
    const r = await fetch('/v1/group-overrides?group_id=' + group_id);
    const payload = await r.json();
    const overrides = payload.items || [];
    state.clients.overrides = overrides;
    $('group-overrides-tbody').innerHTML = overrides.length
      ? overrides.map(o => renderGroupOverrideRow(o, group_id)).join('')
      : '<tr><td colspan="5" class="empty">No overrides configured for this group.</td></tr>';
  } catch (err) {
    $('group-overrides-tbody').innerHTML = '<tr><td colspan="5" class="empty">Error: ' + esc(err.message) + '</td></tr>';
  }
}

function renderGroupOverrideRow(item, group_id) {
  const badgeClass = item.action === 'block' ? 'badge-block' : 'badge-allow';
  return '<tr>' +
    '<td class="cell-strong">' + esc(item.domain) + '</td>' +
    '<td><span class="' + badgeClass + '">' + esc(item.action) + '</span></td>' +
    '<td class="cell-muted">' + esc(item.reason || '--') + '</td>' +
    '<td class="cell-muted">' + fmtTime(item.updated_at) + '</td>' +
    '<td><button class="ghost btn-sm btn-danger" data-action="delete-group-override" data-group-id="' + group_id + '" data-domain="' + escAttr(item.domain) + '">Delete</button></td>' +
    '</tr>';
}

async function deleteGroupOverride(group_id, domain) {
  if (!confirm('Delete override for ' + domain + '?')) return;
  try {
    const r = await fetch('/v1/group-overrides?group_id=' + group_id + '&domain=' + encodeURIComponent(domain), { method: 'DELETE' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Group override deleted: ' + domain, 'ok');
    await loadGroupOverrides();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function handleGroupOverrideSubmit(e) {
  e.preventDefault();
  const group_id = parseInt($('override-group-select').value, 10);
  if (isNaN(group_id) || group_id <= 0) {
    showToast('Please select a group first', 'err');
    return;
  }
  const domain = $('go-domain-input').value.trim();
  const action = $('go-action-input').value;
  const reason = $('go-reason-input').value.trim();

  if (!domain) {
    showToast('Domain is required', 'err');
    return;
  }

  try {
    const r = await fetch('/v1/group-overrides', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ group_id, domain, action, reason })
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Group override saved: ' + domain + ' -> ' + action, 'ok');
    $('go-domain-input').value = '';
    $('go-reason-input').value = '';
    await loadGroupOverrides();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

function openNewGroupModal() {
  $('modal-title').textContent = 'New Policy Group';
  $('group-id-input').value = '';
  $('group-name-input').value = '';
  $('group-name-input').disabled = false;
  $('group-desc-input').value = '';

  // Clear checkboxes
  document.querySelectorAll('input[name="block-cat"]').forEach(cb => cb.checked = false);
  $('group-phish-input').checked = false;
  $('group-malware-input').checked = false;

  openModalShell($('group-modal'));
}

function openEditGroupModal(id) {
  const g = state.clients.groups.find(group => group.id === id);
  if (!g) return;

  $('modal-title').textContent = 'Edit Policy Group';
  $('group-id-input').value = g.id;
  $('group-name-input').value = g.name;

  // Prevent renaming the default group to avoid breaking core assumptions
  if (g.id === 1 || g.name.toLowerCase() === 'default') {
    $('group-name-input').disabled = true;
  } else {
    $('group-name-input').disabled = false;
  }

  $('group-desc-input').value = g.description || '';

  const blockCats = g.block_categories || [];
  document.querySelectorAll('input[name="block-cat"]').forEach(cb => {
    cb.checked = blockCats.includes(cb.value);
  });

  $('group-phish-input').checked = !!g.strict_phishing;
  $('group-malware-input').checked = !!g.strict_malware;

  openModalShell($('group-modal'));
}

function closeGroupModal() {
  closeModalShell($('group-modal'));
}

$('group-modal').addEventListener('click', e => {
  if (e.target === $('group-modal')) closeGroupModal();
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && $('group-modal').classList.contains('active')) {
    closeGroupModal();
  }
});

async function handleGroupSubmit(e) {
  e.preventDefault();
  const idStr = $('group-id-input').value;
  const name = $('group-name-input').value.trim();
  const description = $('group-desc-input').value.trim();

  const blockCategories = [];
  document.querySelectorAll('input[name="block-cat"]:checked').forEach(cb => {
    blockCategories.push(cb.value);
  });

  const strictPhishing = $('group-phish-input').checked;
  const strictMalware = $('group-malware-input').checked;

  if (!name) {
    showToast('Group name is required', 'err');
    return;
  }

  try {
    const isEdit = idStr !== '';
    const url = isEdit ? '/v1/groups?id=' + idStr : '/v1/groups';
    const method = isEdit ? 'PUT' : 'POST';

    const r = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        description,
        block_categories: blockCategories,
        strict_phishing: strictPhishing,
        strict_malware: strictMalware
      })
    });

    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }

    showToast(isEdit ? 'Group updated successfully' : 'Group created successfully', 'ok');
    closeGroupModal();
    await loadGroups();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function deleteGroup(id, name) {
  if (id === 1 || name.toLowerCase() === 'default') {
    showToast('Cannot delete default group', 'err');
    return;
  }
  if (!confirm('Delete group "' + name + '"? This will remove all associated client mappings and overrides.')) return;

  try {
    const r = await fetch('/v1/groups?id=' + id, { method: 'DELETE' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Unknown error'); }
    showToast('Group "' + name + '" deleted successfully', 'ok');
    await loadClientsTab();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function handleLogout() {
  if (!confirm('Log out of Sentinel Command OS?')) return;
  try {
    const res = await fetch('/v1/auth/logout', { method: 'POST' });
    if (res.ok) {
      window.location.reload();
    } else {
      showToast('Logout failed', 'err');
    }
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

// ── Settings tab ──────────────────────────────────────────────────────────────
function togglePasswordVisibility(id) {
  const el = document.getElementById(id);
  if (el) {
    el.type = el.type === 'password' ? 'text' : 'password';
  }
}

async function loadSettings() {
  if (!state.session.canViewSettings) {
    return;
  }
  try {
    const bundleResponse = await fetch('/v1/settings/bundle');
    if (!bundleResponse.ok) { const err = await bundleResponse.json(); throw new Error(err.error || 'Failed to load settings'); }
    const bundle = await bundleResponse.json();
    const data = bundle.settings || {};
    
    const keyInput = document.getElementById('setting-gemini-api-key');
    const webhookInput = document.getElementById('setting-agent-webhook');
    
    if (keyInput) keyInput.value = data.gemini_api_key || '';
    if (webhookInput) webhookInput.value = data.agent_webhook_url || '';
    const analysisConfig = bundle.analysis_config || {};
    const configInput = document.getElementById('setting-analysis-config');
    if (configInput) configInput.value = JSON.stringify(analysisConfig, null, 2);
    renderGuestAccessStatus(bundle.guest_access || {});
  } catch (err) {
    showToast('Error loading settings: ' + err.message, 'err');
  }
}

async function saveSettings() {
  if (!state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    return;
  }
  try {
    const gemini_api_key = document.getElementById('setting-gemini-api-key').value.trim();
    const agent_webhook_url = document.getElementById('setting-agent-webhook').value.trim();
    
    const r = await fetch('/v1/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gemini_api_key,
        agent_webhook_url
      })
    });
    
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Failed to save settings'); }
    showToast('Settings saved successfully', 'ok');
    
    // Reload settings to get updated masks
    await loadSettings();
  } catch (err) {
    showToast('Error saving settings: ' + err.message, 'err');
  }
}

async function testAI() {
  if (!state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    return;
  }
  const resEl = document.getElementById('test-ai-result');
  if (resEl) {
    resEl.style.display = 'block';
    resEl.style.borderColor = 'var(--line)';
    resEl.style.color = 'var(--muted)';
    resEl.innerHTML = '<span class="status-inline-note">Executing dynamic AI engine test with mock prompt...</span>';
  }
  
  try {
    const r = await fetch('/v1/settings/test-ai', { method: 'POST' });
    const data = await r.json();
    
    if (!r.ok || data.status === 'error') {
      const errMsg = data.error || (data.status === 'error' ? data.error : 'Connection failed');
      if (resEl) {
        resEl.style.borderColor = 'var(--bad)';
        resEl.style.color = 'var(--bad)';
        resEl.innerHTML = `<strong>❌ AI Connection Test Failed</strong><br>${esc(errMsg)}`;
      }
    } else {
      if (resEl) {
        resEl.style.borderColor = 'var(--safe)';
        resEl.style.color = 'var(--safe)';
        resEl.innerHTML = `<strong>✅ AI Connection Test Successful</strong><br>Verdict: ${esc(data.verdict)}<br>Reasoning: ${esc(data.reason)}`;
      }
    }
  } catch (err) {
    if (resEl) {
      resEl.style.borderColor = 'var(--bad)';
      resEl.style.color = 'var(--bad)';
      resEl.innerHTML = `<strong>❌ Request Error</strong><br>${esc(err.message)}`;
    }
  }
}

async function sendTestAlert() {
  if (!state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    return;
  }
  const resEl = document.getElementById('test-alert-result');
  if (resEl) {
    resEl.style.display = 'block';
    resEl.style.borderColor = 'var(--line)';
    resEl.style.color = 'var(--muted)';
    resEl.innerHTML = '<span class="status-inline-note">Dispatching test notification payload to webhook...</span>';
  }
  
  try {
    const r = await fetch('/v1/settings/test-alert', { method: 'POST' });
    const data = await r.json();
    
    if (!r.ok || data.status === 'error') {
      const errMsg = data.error || (data.status === 'error' ? data.error : 'Notification dispatch failed');
      if (resEl) {
        resEl.style.borderColor = 'var(--bad)';
        resEl.style.color = 'var(--bad)';
        resEl.innerHTML = `<strong>❌ Webhook Dispatch Failed</strong><br>${esc(errMsg)}`;
      }
    } else {
      if (resEl) {
        resEl.style.borderColor = 'var(--safe)';
        resEl.style.color = 'var(--safe)';
        resEl.innerHTML = '<strong>✅ Webhook Dispatch Successful</strong><br>Test alert successfully sent to configured channel.';
      }
    }
  } catch (err) {
    if (resEl) {
      resEl.style.borderColor = 'var(--bad)';
      resEl.style.color = 'var(--bad)';
      resEl.innerHTML = `<strong>❌ Request Error</strong><br>${esc(err.message)}`;
    }
  }
}

// ── Polling & init ────────────────────────────────────────────────────────────
async function refreshShell() {
  await checkHealth();
  switch (state.activeTab) {
    case 'analysis':
      await loadRecent();
      break;
    case 'telemetry':
      await loadTelemetry();
      break;
    case 'system':
      await loadSystem();
      break;
    default:
      break;
  }
}

async function loadVersion() {
  try {
    const r = await fetch('/v1/version');
    const data = await r.json();
    const ver = data.version || '0.1.0';
    const tier = data.deployment_tier || 'prod';
    const commit = data.git_commit ? data.git_commit.substring(0, 7) : 'unknown';
    const stampEl = document.getElementById('system-version');
    if (stampEl) {
      stampEl.textContent = `v${ver}-${tier} (${commit})`;
    }
  } catch (err) {
    // Keep placeholder or fail silently
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(v) {
  return String(v || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}
function escAttr(v) {
  return esc(v).replace(/\r?\n/g, '&#10;');
}
function fmtTime(v) {
  if (!v) return '--';
  return new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtUptime(secs) {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return (d ? d + 'd ' : '') + (h ? h + 'h ' : '') + m + 'm';
}
function pct(n, total) { return total ? Math.round(n / total * 100) + '%' : '0%'; }
function clampScore(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}
function riskClass(verdict) {
  if (verdict === 'MALICIOUS') return 'risk-malicious';
  if (verdict === 'SUSPICIOUS') return 'risk-suspicious';
  if (verdict === 'SAFE') return 'risk-safe';
  return 'risk-unknown';
}
let toastTimer;
function showToast(msg, type) {
  toast.textContent = msg;
  toast.className = 'toast ' + type + ' show';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    if (motionOK()) toast.classList.add('is-closing');
    toast.classList.remove('show');
    window.setTimeout(() => toast.classList.remove('is-closing'), 190);
  }, 3000);
}

// State for reports queue
const reportFilterInputs = [
  ['reports-status-filter', 'status'],
  ['reports-search-filter', 'q'],
];
let reportFilterTimer;
reportFilterInputs.forEach(([id, key]) => {
  const el = $(id);
  if (!el) return;
  if (key === 'status') el.value = state.reports.filters.status;
  el.addEventListener('input', () => {
    state.reports.filters[key] = el.value.trim();
    state.reports.page = 0;
    clearTimeout(reportFilterTimer);
    reportFilterTimer = setTimeout(loadReports, 180);
  });
});
if ($('reports-clear-filters')) {
  $('reports-clear-filters').addEventListener('click', () => {
    state.reports.filters = { status: '', q: '' };
    reportFilterInputs.forEach(([id]) => {
      const el = $(id);
      if (el) el.value = '';
    });
    state.reports.page = 0;
    loadReports();
  });
}

async function saveAnalysisConfig() {
  if (!state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    return;
  }
  try {
    const input = document.getElementById('setting-analysis-config');
    const config = JSON.parse(input.value);
    const r = await fetch('/v1/config/analysis', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Failed to save analysis config'); }
    input.value = JSON.stringify(await r.json(), null, 2);
    showToast('Analysis scoring configuration saved', 'ok');
  } catch (err) {
    showToast('Error saving analysis config: ' + err.message, 'err');
  }
}

function renderGuestAccessStatus(payload) {
  const exists = !!(payload && payload.exists);
  const enabled = !!(payload && payload.enabled);
  const statusEl = $('guest-access-status');
  const detailEl = $('guest-access-detail');
  const statusText = !exists ? 'Not created' : (enabled ? 'Enabled' : 'Disabled');

  if (statusEl) {
    statusEl.className = 'chip' + (enabled ? ' ok' : '');
    setTextWithMotion(statusEl, statusText, statusEl);
  }
  if (detailEl) {
    detailEl.innerHTML =
      '<span>username: guest</span>' +
      '<span>status: ' + esc(statusText.toLowerCase()) + '</span>';
  }
}

async function createOrEnableGuestAccess() {
  const passwordInput = $('guest-password-input');
  const password = passwordInput ? passwordInput.value.trim() : '';
  if (!password) {
    showToast('Guest password is required', 'err');
    if (passwordInput) passwordInput.focus();
    return;
  }

  try {
    const r = await fetch('/v1/settings/guest-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true, password })
    });
    const payload = await r.json();
    if (!r.ok) throw new Error(payload.error || 'Failed to create guest account');
    renderGuestAccessStatus(payload);
    showToast('Guest account created or enabled', 'ok');
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function disableGuestAccess() {
  try {
    const r = await fetch('/v1/settings/guest-access', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: false })
    });
    const payload = await r.json();
    if (!r.ok) throw new Error(payload.error || 'Failed to disable guest account');
    renderGuestAccessStatus(payload);
    showToast('Guest account disabled', 'ok');
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function deleteGuestAccess() {
  if (!confirm('Delete the guest account configuration?')) return;
  try {
    const r = await fetch('/v1/settings/guest-access', { method: 'DELETE' });
    const payload = await r.json();
    if (!r.ok) throw new Error(payload.error || 'Failed to delete guest account');
    renderGuestAccessStatus({ exists: false, enabled: false });
    showToast('Guest account deleted', 'ok');
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function resetAnalysisConfig() {
  if (!state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    return;
  }
  if (!confirm('Reset analysis scoring configuration to defaults?')) return;
  try {
    const r = await fetch('/v1/config/analysis/reset', { method: 'POST' });
    if (!r.ok) { const err = await r.json(); throw new Error(err.error || 'Failed to reset analysis config'); }
    const input = document.getElementById('setting-analysis-config');
    if (input) input.value = JSON.stringify(await r.json(), null, 2);
    showToast('Analysis scoring configuration reset to defaults', 'ok');
  } catch (err) {
    showToast('Error resetting analysis config: ' + err.message, 'err');
  }
}

async function loadReports() {
  const offset = state.reports.page * state.reports.pageSize;
  try {
    const params = new URLSearchParams({
      limit: String(state.reports.pageSize),
      offset: String(offset),
    });
    const filters = state.reports.filters || {};
    if (filters.status) params.set('status', filters.status);
    if (filters.q) params.set('q', filters.q);
    const r = await fetch('/v1/reports?' + params.toString());
    if (!r.ok) throw new Error('API error');
    const data = await r.json();
    const reports = data.reports || [];
    state.reports.items = reports;

    // Update pagination
    $('reports-page-indicator').textContent = 'Page ' + (state.reports.page + 1);
    $('reports-prev').disabled = state.reports.page === 0;
    $('reports-next').disabled = reports.length < state.reports.pageSize;

    // Render reports
    const body = $('reports-body');
    if (!body) return;

    if (!reports.length) {
      body.innerHTML = '<div class="empty">No reports found</div>';
      $('reports-count-badge').classList.remove('is-visible');
      return;
    }

    // Count pending reports
    const pendingCount = reports.filter(x => x.status === 'pending').length;
    if (pendingCount > 0) {
      $('reports-count-badge').textContent = pendingCount;
      $('reports-count-badge').classList.add('is-visible');
    } else {
      $('reports-count-badge').classList.remove('is-visible');
    }

    body.innerHTML = reports.map(renderReportRow).join('');
    markInsertedRows(body, '.telemetry-row');
  } catch (err) {
    $('reports-body').innerHTML = '<div class="empty">Failed to load reports queue.</div>';
  }
}

function renderReportRow(report) {
  const isPending = report.status === 'pending';
  const escDomain = esc(report.domain);
  const escContact = esc(report.contact || '--');
  const escNote = esc(report.note || '--');
  const timeStr = fmtTime(report.created_at);

  let actions = '';
  if (isPending) {
    actions = state.session.readOnly
      ? `<span class="report-completed">Read only</span>`
      : `
        <div class="report-actions">
          <button class="ghost btn-sm ok text-safe" data-action="approve-report" data-report-id="${report.id}" data-domain="${escAttr(report.domain)}" data-note="${escAttr(report.note || '')}">Approve</button>
          <button class="ghost btn-sm bad text-bad" data-action="dismiss-report" data-report-id="${report.id}">Dismiss</button>
        </div>
      `;
  } else {
    actions = `<span class="report-completed">Completed</span>`;
  }

  // Use dynamic badge styling for status
  let statusBadge = '';
  if (report.status === 'pending') {
    statusBadge = `<span class="verdict SUSPICIOUS report-status">PENDING</span>`;
  } else if (report.status === 'resolved') {
    statusBadge = `<span class="verdict SAFE report-status">RESOLVED</span>`;
  } else {
    statusBadge = `<span class="verdict report-status archived">ARCHIVED</span>`;
  }

  return `
    <div class="telemetry-row report-row">
      <div class="report-domain">${escDomain}</div>
      <div class="report-contact" title="${escContact}">${escContact}</div>
      <div class="report-note" title="${escNote}">${escNote}</div>
      <div>${statusBadge}</div>
      <div class="report-time">${timeStr}</div>
      <div>${actions}</div>
    </div>
  `;
}

function changeReportsPage(dir) {
  state.reports.page += dir;
  if (state.reports.page < 0) state.reports.page = 0;
  loadReports();
}

async function approveReport(id, domain, note) {
  try {
    const r = await fetch('/v1/overrides/review-false-positive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: domain,
        reason: note || 'Approved from reports queue false positive submission',
        source: 'user_report_queue',
        previous_action: 'block'
      }),
    });
    if (!r.ok) {
      const err = await r.json();
      throw new Error(err.error || 'Failed to whitelist');
    }
    
    // Explicitly make sure status is updated to resolved just in case
    await fetch('/v1/reports/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: id,
        status: 'resolved'
      }),
    });

    showToast('Approved & whitelisted ' + domain, 'ok');
    await Promise.all([loadReports(), loadOverrides()]);
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

async function dismissReport(id) {
  try {
    const r = await fetch('/v1/reports/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: id,
        status: 'archived'
      }),
    });
    if (!r.ok) {
      const err = await r.json();
      throw new Error(err.error || 'Failed to archive');
    }
    showToast('Report archived', 'ok');
    await loadReports();
  } catch (err) {
    showToast('Error: ' + err.message, 'err');
  }
}

function toggleReportsQueue() {
  const content = $('reports-queue-content');
  const icon = $('reports-toggle-icon');
  if (content.style.display === 'none') {
    content.style.display = 'block';
    icon.style.transform = 'rotate(0deg)';
  } else {
    content.style.display = 'none';
    icon.style.transform = 'rotate(-90deg)';
  }
}

// Canvas Background Animation
(function() {
  const canvas = document.getElementById('appCanvasBackground');
  if (!canvas) return;
  if (!motionOK()) return;
  const ctx = canvas.getContext('2d');
  let cW, cH;
  let time = 0;
  
  function resize() {
    cW = window.innerWidth;
    cH = window.innerHeight;
    canvas.width = cW;
    canvas.height = cH;
  }
  window.addEventListener('resize', resize);
  resize();

  const particles = [];
  for (let i = 0; i < 40; i++) {
    particles.push({
      x: Math.random() * cW,
      y: Math.random() * cH,
      size: Math.random() * 1.5 + 0.5,
      speedY: -(Math.random() * 0.3 + 0.1),
      alpha: Math.random() * 0.3 + 0.1,
      freq: Math.random() * 0.02 + 0.01,
      phase: Math.random() * Math.PI * 2
    });
  }

  function draw() {
    ctx.clearRect(0, 0, cW, cH);
    time++;

    particles.forEach(p => {
      p.y += p.speedY;
      if (p.y < -10) {
        p.y = cH + 10;
        p.x = Math.random() * cW;
      }
      const drawX = p.x + Math.sin(time * p.freq + p.phase) * 10;
      ctx.beginPath();
      ctx.arc(drawX, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(96, 165, 250, ${p.alpha})`;
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }
  draw();
})();

// Trigger UI Animations on Analysis
document.addEventListener('DOMContentLoaded', () => {
  const analyzeForm = document.getElementById('analyze-form');
  const shockwave = document.getElementById('analyze-shockwave');
  const scanner = document.getElementById('result-scanner');
  
  if (analyzeForm) {
    analyzeForm.addEventListener('submit', (e) => {
      if (shockwave) {
        shockwave.classList.remove('active');
        void shockwave.offsetWidth;
        shockwave.classList.add('active');
      }
      if (scanner) {
        scanner.classList.remove('active');
        scanner.className = 'scanner-laser blue active';
        setTimeout(() => scanner.classList.remove('active'), 1500);
      }
    });
  }
});

// Telemetry Retention Control (Phase 5)
function updateRetentionSliderVal(val) {
  const slider = $('retention-days-slider');
  if (slider) {
    slider.value = val;
  }
  const display = $('retention-days-val');
  if (display) {
    setTextWithMotion(display, val + ' Days');
  }
}

async function saveRetentionDays(val) {
  try {
    const r = await fetch('/v1/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ telemetry_retention_days: parseInt(val, 10) }),
    });
    if (!r.ok) {
      const err = await r.json();
      throw new Error(err.error || 'Failed to update');
    }
    showToast('Telemetry retention updated to ' + val + ' days', 'ok');
  } catch (err) {
    showToast('Error saving retention days: ' + err.message, 'err');
  }
}

function readActionInt(actionEl, key) {
  const value = Number.parseInt(actionEl.dataset[key] || '', 10);
  return Number.isNaN(value) ? null : value;
}

async function dispatchDashboardAction(actionEl, event) {
  if (!actionEl || actionEl.disabled) return;
  const action = actionEl.dataset.action;
  if (!action) return;
  if (event) {
    event.preventDefault();
  }

  switch (action) {
    case 'logout':
      await handleLogout();
      break;
    case 'toggle-reports-queue':
      toggleReportsQueue();
      break;
    case 'change-reports-page':
      changeReportsPage(readActionInt(actionEl, 'pageDir') || 0);
      break;
    case 'open-new-group-modal':
      openNewGroupModal();
      break;
    case 'toggle-password-visibility':
      togglePasswordVisibility(actionEl.dataset.passwordTarget || '');
      break;
    case 'save-settings':
      await saveSettings();
      break;
    case 'test-ai':
      await testAI();
      break;
    case 'save-analysis-config':
      await saveAnalysisConfig();
      break;
    case 'reset-analysis-config':
      await resetAnalysisConfig();
      break;
    case 'send-test-alert':
      await sendTestAlert();
      break;
    case 'create-or-enable-guest-access':
      await createOrEnableGuestAccess();
      break;
    case 'disable-guest-access':
      await disableGuestAccess();
      break;
    case 'delete-guest-access':
      await deleteGuestAccess();
      break;
    case 'close-group-modal':
      closeGroupModal();
      break;
    case 'submit-false-positive-review':
      await submitFalsePositiveReview();
      break;
    case 'open-override-editor':
      openOverrideEditor(actionEl.dataset.domain || '', actionEl.dataset.overrideAction || 'allow');
      break;
    case 'open-dossier':
      openDossier(actionEl.dataset.domain || '');
      break;
    case 'open-false-positive-review':
      await openFalsePositiveReview(actionEl.dataset.domain || '');
      break;
    case 'delete-override':
      await deleteOverride(actionEl.dataset.domain || '');
      break;
    case 'edit-brand':
      editBrand(readActionInt(actionEl, 'brandId') || 0);
      break;
    case 'delete-brand':
      await deleteBrand(readActionInt(actionEl, 'brandId') || 0);
      break;
    case 'trigger-agent-task':
      await triggerAgentTask(actionEl.dataset.taskName || '');
      break;
    case 'delete-group':
      await deleteGroup(readActionInt(actionEl, 'groupId') || 0, actionEl.dataset.groupName || '');
      break;
    case 'open-edit-group-modal':
      openEditGroupModal(readActionInt(actionEl, 'groupId') || 0);
      break;
    case 'delete-mapping':
      await deleteMapping(readActionInt(actionEl, 'mappingId') || 0);
      break;
    case 'delete-group-override':
      await deleteGroupOverride(readActionInt(actionEl, 'groupId') || 0, actionEl.dataset.domain || '');
      break;
    case 'approve-report':
      await approveReport(
        readActionInt(actionEl, 'reportId') || 0,
        actionEl.dataset.domain || '',
        actionEl.dataset.note || ''
      );
      break;
    case 'dismiss-report':
      await dismissReport(readActionInt(actionEl, 'reportId') || 0);
      break;
  }
}

function bindDashboardFeatureControls() {
  document.addEventListener('click', event => {
    const actionEl = event.target.closest('[data-action]');
    if (!actionEl) return;
    void dispatchDashboardAction(actionEl, event);
  });

  document.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const actionEl = event.target.closest('[data-action]');
    if (!actionEl) return;
    if (/^(BUTTON|A|INPUT|SELECT|TEXTAREA)$/.test(actionEl.tagName)) return;
    void dispatchDashboardAction(actionEl, event);
  });

  const groupForm = $('group-form');
  if (groupForm) {
    groupForm.addEventListener('submit', handleGroupSubmit);
  }

  const brandForm = $('brand-form');
  if (brandForm) {
    brandForm.addEventListener('submit', handleBrandSubmit);
  }

  const mappingForm = $('mapping-form');
  if (mappingForm) {
    mappingForm.addEventListener('submit', handleMappingSubmit);
  }

  const groupOverrideForm = $('group-override-form');
  if (groupOverrideForm) {
    groupOverrideForm.addEventListener('submit', handleGroupOverrideSubmit);
  }

  const overrideGroupSelect = $('override-group-select');
  if (overrideGroupSelect) {
    overrideGroupSelect.addEventListener('change', () => {
      void loadGroupOverrides();
    });
  }

  const retentionSlider = $('retention-days-slider');
  if (retentionSlider) {
    retentionSlider.addEventListener('input', () => {
      updateRetentionSliderVal(retentionSlider.value);
    });
    retentionSlider.addEventListener('change', () => {
      void saveRetentionDays(retentionSlider.value);
    });
  }
}

bindDashboardFeatureControls();
initDashboard();
setInterval(refreshShell, 15000);
