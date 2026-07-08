function readSessionBootstrap() {
  const el = document.getElementById('session-bootstrap');
  if (!el) return null;
  try {
    const raw = (el.content && el.content.textContent) || el.textContent || '{}';
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function normalizeSessionState(payload) {
  if (!payload) {
    return {
      username: '',
      role: 'guest',
      readOnly: false,
      canMutate: false,
      canViewSettings: false,
      guestMessage: '',
    };
  }
  return {
    username: payload.username || '',
    role: payload.role || 'guest',
    readOnly: !!payload.read_only,
    canMutate: !!payload.can_mutate,
    canViewSettings: !!payload.can_view_settings,
    guestMessage: payload.guest_message || '',
  };
}

const sessionBootstrap = readSessionBootstrap();

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  activeTab: 'analysis',
  session: normalizeSessionState(sessionBootstrap),
  latest: null,
  recent: [],
  telemetry: { stats: {}, items: [], page: 0, pageSize: 20, period: '24h', total: 0, filters: { domain: '', verdict: '', source: '' } },
  reports: { page: 0, pageSize: 10, items: [], filters: { status: 'pending', q: '' } },
  overrides: { items: [], filter: '' },
  brands: { items: [] },
  system: { health: {}, metrics: {}, status: {} },
  chart: null,
  clients: { groups: [], mappings: [], overrides: [] },
};

// ── Element refs ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const analyzeForm     = $('analyze-form');
const domainInput     = $('domain-input');
const analyzeBtn      = $('analyze-btn');
const osintBtn        = $('osint-btn');
const resultEl        = $('result');
const recentEl        = $('recent');
const recentCount     = $('recent-count');
const cacheEngineState = $('cache-engine-state');
const apiStatus       = $('api-status');
const rlStatus        = $('rl-status');
const resultState     = $('result-state');
const metricTotal     = $('metric-total');
const metricSafe      = $('metric-safe');
const metricSusp      = $('metric-suspicious');
const metricMal       = $('metric-malicious');
const metricCache     = $('metric-cache');
const quickActions    = $('quick-actions');
const toast           = $('toast');
const commandShell    = document.querySelector('.command-shell');
const commandSidebar  = document.querySelector('.command-sidebar');
const sidebarToggle   = $('sidebar-toggle');
const mobileNavTrigger = $('mobile-nav-trigger');
const mobileNavBackdrop = $('mobile-nav-backdrop');
const currentPageTitle = $('current-page-title');
const guestBanner = $('guest-banner');
const guestBannerMessage = $('guest-banner-message');
const settingsTabButton = $('tab-btn-settings');
const pageTitles = {
  analysis: 'Domain Inspection',
  telemetry: 'Telemetry',
  overrides: 'Override Rules',
  clients: 'Policy Matrix',
  system: 'Runtime System',
  settings: 'System Settings',
};
const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
const motionOK = () => !motionQuery.matches;

function pulseNode(el, className) {
  if (!el || !motionOK()) return;
  el.classList.remove(className);
  void el.offsetWidth;
  el.classList.add(className);
}

function setTextWithMotion(el, value, pulseTarget) {
  if (!el) return;
  const next = String(value);
  const changed = el.textContent !== next;
  el.textContent = next;
  if (changed) {
    pulseNode(el, 'star-glint');
    if (pulseTarget) pulseNode(pulseTarget, 'stellar-pulse');
  }
}

function setHTMLWithMotion(el, value, pulseTarget) {
  if (!el) return;
  const changed = el.innerHTML !== value;
  el.innerHTML = value;
  if (changed && pulseTarget) pulseNode(pulseTarget, 'stellar-pulse');
}

const cometDelayClasses = [
  'comet-delay-0',
  'comet-delay-1',
  'comet-delay-2',
  'comet-delay-3',
  'comet-delay-4',
  'comet-delay-5',
  'comet-delay-6',
  'comet-delay-7',
];

function setCometDelayClass(el, delayIndex) {
  if (!el) return;
  cometDelayClasses.forEach(name => el.classList.remove(name));
  const normalizedIndex = Math.max(0, Math.min(delayIndex, cometDelayClasses.length - 1));
  el.classList.add(cometDelayClasses[normalizedIndex]);
}

function markInsertedRows(root, selector) {
  if (!root || !motionOK()) return;
  requestAnimationFrame(() => {
    root.querySelectorAll(selector).forEach((row, index) => {
      row.classList.add('comet-in');
      setCometDelayClass(row, Math.min(index, cometDelayClasses.length - 1));
    });
  });
}

function openModalShell(modal) {
  if (!modal) return;
  modal.classList.remove('is-closing');
  modal.classList.add('active');
}

function closeModalShell(modal) {
  if (!modal || !modal.classList.contains('active')) return;
  if (!motionOK()) {
    modal.classList.remove('active', 'is-closing');
    return;
  }
  modal.classList.add('is-closing');
  window.setTimeout(() => {
    modal.classList.remove('active', 'is-closing');
  }, 190);
}

const guestReadOnlyFallbackMessage = 'Khách không được quyền thay đổi hoặc áp dụng các chính sách mới vào hệ thống, nếu muốn hãy liên hệ với quản trị viên của Safe Zone DNS tại contact@quorix.io.vn.';
const nativeFetch = window.fetch.bind(window);

function sessionGuestMessage() {
  return (state.session && state.session.guestMessage) || guestReadOnlyFallbackMessage;
}

function isReadOnlySession() {
  return !!(state.session && state.session.readOnly);
}

function normalizeFetchPath(input) {
  const raw = typeof input === 'string' ? input : ((input && input.url) || '');
  try {
    return new URL(raw, window.location.origin).pathname;
  } catch {
    return String(raw || '');
  }
}

function isProtectedMutationRequest(input, init) {
  const method = String((init && init.method) || 'GET').toUpperCase();
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return false;

  const path = normalizeFetchPath(input);
  if (path === '/v1/analyze' || path === '/v1/auth/logout') return false;

  const protectedPrefixes = [
    '/v1/overrides',
    '/v1/reports/status',
    '/v1/brands',
    '/v1/agent/trigger',
    '/v1/groups',
    '/v1/mappings',
    '/v1/group-overrides',
    '/v1/settings',
    '/v1/config/analysis',
  ];
  return protectedPrefixes.some(prefix => path === prefix || path.startsWith(prefix + '/'));
}

function shouldRedirectToLogin(path, response) {
  if (!response || response.status !== 401) return false;
  return path.startsWith('/v1/') && path !== '/v1/auth/login';
}

window.fetch = async function(input, init) {
  if (isReadOnlySession() && isProtectedMutationRequest(input, init)) {
    const error = sessionGuestMessage();
    showToast(error, 'err');
    return Promise.resolve(new Response(JSON.stringify({ error }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    }));
  }
  const response = await nativeFetch(input, init);
  if (shouldRedirectToLogin(normalizeFetchPath(input), response)) {
    window.location.replace('/dashboard');
  }
  return response;
};

function applySessionState() {
  const canViewSettings = !!state.session.canViewSettings;
  if (settingsTabButton) {
    settingsTabButton.hidden = !canViewSettings;
  }

  const guestAccessPanel = $('guest-access-panel');
  if (guestAccessPanel) {
    guestAccessPanel.hidden = !canViewSettings;
  }

  if (guestBanner) {
    if (state.session.readOnly) {
      guestBanner.hidden = false;
      guestBanner.classList.add('active');
      setTextWithMotion(guestBannerMessage, sessionGuestMessage(), guestBanner);
    } else {
      guestBanner.hidden = true;
      guestBanner.classList.remove('active');
      if (guestBannerMessage) guestBannerMessage.textContent = '';
    }
  }

  document.body.classList.toggle('guest-read-only', !!state.session.readOnly);

  if (!canViewSettings && state.activeTab === 'settings') {
    state.activeTab = 'analysis';
    syncActiveTabState('analysis');
  }
}

async function loadSession() {
  try {
    const r = await nativeFetch('/v1/auth/session');
    if (r.status === 401 || r.status === 403) {
      window.location.replace('/dashboard');
      return false;
    }
    if (!r.ok) throw new Error('session unavailable');
    state.session = normalizeSessionState(await r.json());
  } catch {
    if (!state.session.username) {
      state.session = normalizeSessionState(sessionBootstrap);
    }
    if (!state.session.username) {
      showToast('Session status temporarily unavailable.', 'err');
      return false;
    }
  }
  applySessionState();
  return true;
}

// ── Command deck shell ────────────────────────────────────────────────────────
const mobileNavQuery = window.matchMedia('(max-width: 820px)');

function setNavCollapsed(collapsed) {
  commandShell.classList.toggle('nav-collapsed', collapsed);
  sidebarToggle.setAttribute('aria-expanded', String(!collapsed));
  sidebarToggle.setAttribute('title', collapsed ? 'Expand navigation' : 'Collapse navigation');
  sidebarToggle.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
  localStorage.setItem('safe-zone-nav-collapsed', collapsed ? '1' : '0');
}

function setMobileNavOpen(open) {
  commandShell.classList.toggle('mobile-nav-open', open);
  if (mobileNavTrigger) {
    mobileNavTrigger.setAttribute('aria-expanded', String(open));
    mobileNavTrigger.setAttribute('title', open ? 'Close navigation' : 'Open navigation');
    mobileNavTrigger.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  }
  if (commandSidebar) {
    commandSidebar.setAttribute('aria-hidden', mobileNavQuery.matches ? String(!open) : 'false');
  }
}

function closeMobileNav() {
  setMobileNavOpen(false);
}

function syncResponsiveNavState() {
  if (!mobileNavQuery.matches) {
    setMobileNavOpen(false);
    if (commandSidebar) commandSidebar.setAttribute('aria-hidden', 'false');
    return;
  }
  setMobileNavOpen(false);
}

setNavCollapsed(localStorage.getItem('safe-zone-nav-collapsed') === '1');
sidebarToggle.addEventListener('click', () => {
  setNavCollapsed(!commandShell.classList.contains('nav-collapsed'));
});
if (mobileNavTrigger) {
  mobileNavTrigger.addEventListener('click', () => {
    setMobileNavOpen(!commandShell.classList.contains('mobile-nav-open'));
  });
}
if (mobileNavBackdrop) {
  mobileNavBackdrop.addEventListener('click', closeMobileNav);
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && commandShell.classList.contains('mobile-nav-open')) {
    closeMobileNav();
  }
});
mobileNavQuery.addEventListener('change', syncResponsiveNavState);
syncResponsiveNavState();

function syncActiveTabState(name) {
  commandShell.dataset.activeTab = name;
  document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
    const active = btn.dataset.tab === name;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', String(active));
    btn.setAttribute('tabindex', active ? '0' : '-1');
  });
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + name));
  currentPageTitle.textContent = pageTitles[name] || 'Sentinel Command';
}

// ── Routing / Tab switching ───────────────────────────────────────────────────
document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function switchTab(name) {
  if (name === 'settings' && !state.session.canViewSettings) {
    showToast(sessionGuestMessage(), 'err');
    name = 'analysis';
  }
  state.activeTab = name;
  syncActiveTabState(name);
  if (mobileNavQuery.matches) closeMobileNav();
  // Entrance animation for tab content
  if (motionOK()) {
    const panel = document.getElementById('tab-' + name);
    if (panel) {
      panel.classList.remove('tab-enter');
      void panel.offsetWidth;
      panel.classList.add('tab-enter');
    }
  }
  loadTabData(name);
}

syncActiveTabState(state.activeTab);

async function loadTabData(name) {
  switch(name) {
    case 'analysis':  await loadRecent(); break;
    case 'telemetry': await loadTelemetry(); break;
    case 'overrides': await Promise.all([loadOverrides(), loadBrands()]); break;
    case 'system':    await loadSystem(); break;
    case 'clients':   await loadClientsTab(); break;
    case 'settings':  if (state.session.canViewSettings) await loadSettings(); break;
  }
}

async function initDashboard() {
  if (!state.session.username) {
    const hasSession = await loadSession();
    if (!hasSession) return;
  } else {
    applySessionState();
  }
  await Promise.all([refreshShell(), loadVersion()]);
}
