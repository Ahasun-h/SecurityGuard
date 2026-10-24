// Security Guard Desktop Frontend Logic - Neo-Modern Soft Minimalist

let appState = {
  guardStatus: { installed: false, version: '', path: '' },
  githubAuth: { authenticated: false, user: null },
  repos: [],          // all repos fetched from GitHub
  displayCount: 30,   // how many to show in cards / grid (grows with Load More)
  selectedRepoIds: new Set(),
  localTargets: [],
  selectedLocalPaths: new Set(),
  lastScanReport: null,
  activeFilter: 'all',
  searchQuery: '',
  aiSettings: { provider: 'gemini', model: 'gemini-1.5-flash', hasKey: false },
  // Fetch state
  reposFetching: false,
  reposFetched: false,
  // Accounts
  savedAccounts: [],
  activeGitHubLogin: null,
  lastSyncedAt: null
};

// --- Repository Local Storage & Session Cache Helpers ---
const REPO_CACHE_KEY_PREFIX = 'guard_repos_cache_';

function getLocalRepoCache(login) {
  try {
    const raw = localStorage.getItem(REPO_CACHE_KEY_PREFIX + (login || 'default'));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.repos) && parsed.repos.length > 0) {
      return parsed;
    }
  } catch (e) {
    console.warn('Failed reading localStorage repo cache', e);
  }
  return null;
}

function setLocalRepoCache(login, repos, lastSyncedAt = new Date().toISOString()) {
  try {
    const payload = {
      login: login || 'default',
      lastSyncedAt,
      repos
    };
    localStorage.setItem(REPO_CACHE_KEY_PREFIX + (login || 'default'), JSON.stringify(payload));
    sessionStorage.setItem('guard_active_repos_loaded', 'true');
  } catch (e) {
    console.warn('Failed saving localStorage repo cache', e);
  }
}

// --- Account-Scoped Scan Session & Historical Reports Store ---
const SCAN_SESSION_KEY_PREFIX = 'guard_scan_session_';

function getActiveAccountLogin() {
  return (appState.githubAuth && appState.githubAuth.user && appState.githubAuth.user.login) ||
         appState.activeGitHubLogin ||
         'guest';
}

function getAccountScanSession() {
  const login = getActiveAccountLogin();
  try {
    const raw = localStorage.getItem(SCAN_SESSION_KEY_PREFIX + login);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.scannedRepos === 'object') {
        return parsed;
      }
    }
  } catch (e) {
    console.warn('Failed reading scan session from localStorage', e);
  }
  return {
    account: login,
    lastUpdated: null,
    scannedRepos: {}, // full_name -> { scannedAt, status: 'clean'|'infected', findingsCount, findings }
    reports: []       // array of batch/full scan reports
  };
}

function saveAccountScanSession(session) {
  const login = getActiveAccountLogin();
  session.account = login;
  session.lastUpdated = new Date().toISOString();
  try {
    localStorage.setItem(SCAN_SESSION_KEY_PREFIX + login, JSON.stringify(session));
  } catch (e) {
    console.warn('Failed saving scan session to localStorage', e);
  }
}

function clearAccountScanSession() {
  const login = getActiveAccountLogin();
  try {
    localStorage.removeItem(SCAN_SESSION_KEY_PREFIX + login);
  } catch (_) {}
}

function markThreatNeutralized(repoTarget, findingWhere) {
  const session = getAccountScanSession();

  // 1. Update scannedRepos
  if (session.scannedRepos) {
    let targetKey = repoTarget;
    if (!session.scannedRepos[targetKey]) {
      targetKey = Object.keys(session.scannedRepos).find(k => k === repoTarget || k.endsWith(repoTarget) || repoTarget.endsWith(k));
    }

    if (targetKey && session.scannedRepos[targetKey]) {
      const repoEntry = session.scannedRepos[targetKey];
      if (Array.isArray(repoEntry.findings)) {
        repoEntry.findings.forEach(f => {
          const w = (f.detail && (f.detail.where || f.detail.fullPath)) || f.where;
          if (!findingWhere || w === findingWhere || repoEntry.findings.length === 1) {
            f.neutralized = true;
            f.neutralizedAt = new Date().toISOString();
            if (f.detail && typeof f.detail === 'object') {
              f.detail.neutralized = true;
              f.detail.neutralizedAt = f.neutralizedAt;
            }
          }
        });
      }
      const stillActive = (repoEntry.findings || []).some(f => !f.neutralized && !(f.detail && f.detail.neutralized));
      if (!stillActive) {
        repoEntry.status = 'clean';
        repoEntry.neutralized = true;
        repoEntry.neutralizedAt = new Date().toISOString();
      }
    }
  }

  // 2. Update historical batch reports in session
  if (Array.isArray(session.reports)) {
    session.reports.forEach(rep => {
      if (Array.isArray(rep.reposScanned)) {
        rep.reposScanned.forEach(r => {
          if (r.full_name === repoTarget || r.name === repoTarget || repoTarget.endsWith(r.name)) {
            if (Array.isArray(r.findings)) {
              r.findings.forEach(f => {
                const w = (f.detail && (f.detail.where || f.detail.fullPath)) || f.where;
                if (!findingWhere || w === findingWhere || r.findings.length === 1) {
                  f.neutralized = true;
                  f.neutralizedAt = new Date().toISOString();
                  if (f.detail && typeof f.detail === 'object') {
                    f.detail.neutralized = true;
                    f.detail.neutralizedAt = f.neutralizedAt;
                  }
                }
              });
            }
            const stillActive = (r.findings || []).some(f => !f.neutralized && !(f.detail && f.detail.neutralized));
            if (!stillActive) {
              r.status = 'clean';
            }
          }
        });
      }
      if (Array.isArray(rep.localScanned)) {
        rep.localScanned.forEach(l => {
          if (l.path === repoTarget) {
            if (Array.isArray(l.findings)) {
              l.findings.forEach(f => {
                f.neutralized = true;
                f.neutralizedAt = new Date().toISOString();
              });
            }
            l.status = 'clean';
          }
        });
      }
    });
  }

  saveAccountScanSession(session);
  updateRepoCounts();
  renderDashboardPillCards();
  renderGitHubFullGrid();
  populateReportTab(getAggregatedSessionReport());
}



// Ingest Background PC Malware Scan into Session and Update Reports Screen
function ingestBackgroundScanReport(report) {
  if (!report || !Array.isArray(report.localScanned)) return;
  const session = getAccountScanSession();
  if (!session.reports) session.reports = [];

  // Remove previous background_pc_scan report if already present to avoid duplication
  session.reports = session.reports.filter(r => r.scanType !== 'background_pc_scan');
  session.reports.unshift(report);
  saveAccountScanSession(session);

  // Update stat counters and populate report screen immediately
  const agg = getAggregatedSessionReport();
  populateReportTab(agg);
  renderDashboardPillCards();
}

function getAggregatedSessionReport() {
  const session = getAccountScanSession();
  const scannedReposMap = session.scannedRepos || {};
  const scannedFullNames = Object.keys(scannedReposMap);

  let cleanCount = 0;
  let infectedCount = 0;
  const allFindings = [];
  const reposScanned = [];

  for (const fullName of scannedFullNames) {
    const info = scannedReposMap[fullName];
    const findings = info.findings || [];
    const hasUnneutralized = findings.some(f => !f.neutralized && !(f.detail && f.detail.neutralized));
    const isInf = info.status === 'infected' && hasUnneutralized;
    if (isInf) infectedCount++;
    else cleanCount++;

    allFindings.push(...findings);

    const matchedRepo = appState.repos.find(x => x.full_name === fullName);

    reposScanned.push({
      full_name: fullName,
      name: fullName.split('/')[1] || fullName,
      is_private: matchedRepo ? matchedRepo.is_private : true,
      status: info.status,
      scannedAt: info.scannedAt,
      findings: findings
    });
  }

  // Also collect any local targets scanned from session reports
  const localScanned = [];
  (session.reports || []).forEach(rep => {
    if (Array.isArray(rep.localScanned)) {
      rep.localScanned.forEach(loc => {
        if (!localScanned.find(x => x.path === loc.path)) {
          localScanned.push(loc);
        }
      });
    }
  });

  return {
    startedAt: session.lastUpdated || new Date().toISOString(),
    finishedAt: session.lastUpdated || new Date().toISOString(),
    totalTargets: appState.repos.length + localScanned.length,
    scannedCount: scannedFullNames.length + localScanned.length,
    threatsFound: infectedCount + localScanned.filter(l => l.status === 'infected').length,
    reposScanned: reposScanned,
    localScanned: localScanned,
    summary: {
      clean: cleanCount + localScanned.filter(l => l.status === 'clean').length,
      infected: infectedCount + localScanned.filter(l => l.status === 'infected').length,
      warnings: 0,
      categories: {
        vscode: 0,
        magic: 0,
        fingerprint: 0,
        workflow_baseline: 0,
        malicious_deps: 0,
        av: 0
      }
    }
  };
}


function updateRepoCounts() {
  const session = getAccountScanSession();
  const scannedMap = session.scannedRepos || {};

  const scanned = appState.repos.filter(r => Boolean(scannedMap[r.full_name])).length;
  const unscanned = appState.repos.length - scanned;
  const privates = appState.repos.filter(r => r.is_private).length;
  const publics = appState.repos.length - privates;

  const countAll = document.getElementById('countAll');
  const countScanned = document.getElementById('countScanned');
  const countUnscanned = document.getElementById('countUnscanned');
  const countPrivate = document.getElementById('countPrivate');
  const countPublic = document.getElementById('countPublic');

  if (countAll) countAll.textContent = appState.repos.length;
  if (countScanned) countScanned.textContent = scanned;
  if (countUnscanned) countUnscanned.textContent = unscanned;
  if (countPrivate) countPrivate.textContent = privates;
  if (countPublic) countPublic.textContent = publics;

  if (appState.selectedRepoIds.size === 0 && appState.repos.length > 0) {
    appState.selectedRepoIds = new Set(appState.repos.map(r => r.id));
  }
  updateSelectedCounts();
}

function updateCacheSyncBadge(text, type = 'success') {
  const badge = document.getElementById('repoCacheSyncBadge');
  if (!badge) return;
  badge.style.display = 'inline-flex';
  if (type === 'syncing') {
    badge.style.background = '#fef6dc';
    badge.style.color = '#a47d06';
    badge.style.borderColor = 'rgba(164,125,6,0.2)';
    badge.innerHTML = '<span class="spinner-dot" style="width:6px; height:6px; margin:0 5px 0 0;"></span> ' + text;
  } else if (type === 'error') {
    badge.style.background = '#fdeae8';
    badge.style.color = '#d64739';
    badge.style.borderColor = 'rgba(214,71,57,0.2)';
    badge.innerHTML = '⚠️ ' + text;
  } else {
    badge.style.background = '#eef7f2';
    badge.style.color = '#1e7e51';
    badge.style.borderColor = 'rgba(30,126,81,0.2)';
    badge.innerHTML = '⚡ ' + text;
  }
}

function formatRelativeTime(isoString) {
  if (!isoString) return 'Just now';
  try {
    const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return new Date(isoString).toLocaleDateString();
  } catch (e) {
    return 'Recently';
  }
}

async function syncReposWithLiveServer({ silent = false, forceFull = false } = {}) {
  const btnSync = document.getElementById('btnSyncCloudData');
  if (btnSync && !silent) {
    btnSync.disabled = true;
    btnSync.textContent = 'Syncing Live Changes...';
  }

  updateCacheSyncBadge('Syncing live changes...', 'syncing');

  try {
    const userLogin = (appState.githubAuth && appState.githubAuth.user && appState.githubAuth.user.login) || 'Webgenius0';
    const res = await window.guardAPI.syncGitHubRepos({ forceFull, login: userLogin });

    if (res && res.success && Array.isArray(res.repos)) {
      appState.repos = res.repos;
      appState.reposFetched = true;
      appState.lastSyncedAt = res.lastSyncedAt;

      // Update local storage session
      setLocalRepoCache(userLogin, res.repos, res.lastSyncedAt);

      updateRepoCounts();
      renderDashboardPillCards();
      renderGitHubFullGrid();

      const changesMsg = res.mode === 'full'
        ? res.totalCount + ' repos synced'
        : (res.newCount > 0 || res.updatedCount > 0
            ? res.newCount + ' new, ' + res.updatedCount + ' updated'
            : 'Live server in sync');

      updateCacheSyncBadge('Live Synced (' + changesMsg + ')', 'success');
    }
  } catch (err) {
    console.error('Incremental sync error:', err);
    updateCacheSyncBadge('Sync failed: ' + err.message, 'error');
  } finally {
    if (btnSync) {
      btnSync.disabled = false;
      btnSync.textContent = 'Sync GitHub Repos';
    }
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  initDockNavigation();
  initEventListeners();

  // Register streaming repos progress listener
  window.guardAPI.onReposProgress((data) => {
    // Accumulate streamed repos
    if (data.chunk && Array.isArray(data.chunk)) {
      data.chunk.forEach(r => {
        if (!appState.repos.find(x => x.id === r.id)) {
          appState.repos.push(r);
        }
      });
    }
    // Update counts live
    const priv = appState.repos.filter(r => r.is_private).length;
    const pub = appState.repos.length - priv;
    const countAll = document.getElementById('countAll');
    const countPriv = document.getElementById('countPrivate');
    const countPub = document.getElementById('countPublic');
    if (countAll) countAll.textContent = appState.repos.length;
    if (countPriv) countPriv.textContent = priv;
    if (countPub) countPub.textContent = pub;

    // Re-render incrementally
    renderDashboardPillCards();
    renderGitHubFullGrid();
  });

  await refreshAllStatus();
});

// Dock Navigation
function initDockNavigation() {
  const dockItems = document.querySelectorAll('.dock-item');
  dockItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabId = item.getAttribute('data-tab');
      switchView(tabId);
    });
  });
}

function switchView(tabId) {
  document.querySelectorAll('.dock-item').forEach(i => i.classList.remove('active'));
  document.querySelectorAll('.view-pane').forEach(p => p.classList.remove('active'));

  const activeItem = document.querySelector(`.dock-item[data-tab="${tabId}"]`);
  const activePane = document.getElementById(tabId);

  if (activeItem) activeItem.classList.add('active');
  if (activePane) activePane.classList.add('active');

  if (tabId === 'view-reports') {
    populateReportTab(getAggregatedSessionReport());
  }
}

// Global Refresh
async function refreshAllStatus() {
  await Promise.all([
    checkGuardEngine(),
    checkGitHubAuth(),
    loadLocalTargets(),
    loadAiSettings()
  ]);
}

// Full Application Session & Cache Purge Helper
function clearAppSession() {
  console.log('[Session] Purging local session, cached repos, and state...');
  clearAccountScanSession();

  // In-memory state
  appState.repos = [];
  appState.selectedRepoIds.clear();
  appState.githubAuth = { authenticated: false, user: null };
  appState.activeGitHubLogin = null;
  appState.savedAccounts = [];
  appState.lastSyncedAt = null;
  appState.reposFetched = false;
  appState.reposFetching = false;
  appState.lastScanReport = null;

  // Browser LocalStorage & SessionStorage
  try {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith(REPO_CACHE_KEY_PREFIX) || k.startsWith('guard_'))) {
        keysToRemove.push(k);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
    sessionStorage.clear();
  } catch (e) {
    console.warn('Error clearing browser storage:', e);
  }

  // UI Counts & Badges
  const countAll = document.getElementById('countAll');
  const countPrivate = document.getElementById('countPrivate');
  const countPublic = document.getElementById('countPublic');
  if (countAll) countAll.textContent = '0';
  if (countPrivate) countPrivate.textContent = '0';
  if (countPublic) countPublic.textContent = '0';

  const syncBadge = document.getElementById('repoCacheSyncBadge');
  if (syncBadge) {
    syncBadge.style.display = 'none';
    syncBadge.innerHTML = '';
  }

  const searchBadge = document.getElementById('homeSearchCountBadge');
  if (searchBadge) {
    searchBadge.style.display = 'none';
  }

  // Sidebar & Settings User Badges
  const sideName = document.getElementById('sideUserName');
  const sideAvatarImg = document.getElementById('sideAvatarImg');
  const settUserTitle = document.getElementById('settingsGhUserTitle');
  const settUserSub = document.getElementById('settingsGhUserSub');
  if (sideName) sideName.textContent = 'Sign in';
  if (sideAvatarImg) sideAvatarImg.style.display = 'none';
  if (settUserTitle) settUserTitle.textContent = 'Not Connected';
  if (settUserSub) settUserSub.textContent = 'Configure PAT or log in with GitHub CLI.';

  // Re-render empty views
  renderDashboardPillCards();
  renderGitHubFullGrid();

  const tabSelectedCount = document.getElementById('selectedCountTab');
  if (tabSelectedCount) tabSelectedCount.textContent = '0';
}

// 1. Check Guard Engine
async function checkGuardEngine() {
  const tag = document.getElementById('engineStatusTag');
  try {
    const res = await window.guardAPI.checkGuardStatus();
    appState.guardStatus = res;
    if (res.installed) {
      const v = res.version.replace(/^guard\s+/i, '').replace(/^v/i, '');
      tag.innerHTML = `<span class="status-indicator-dot"></span> Guard v${v} Active`;
    } else {
      tag.innerHTML = `<span class="status-indicator-dot" style="background:#f5786c;"></span> Guard Not Installed`;
      tag.style.background = '#fdeae8';
      tag.style.color = '#d64739';
    }
  } catch (e) {
    console.error('Guard status check error:', e);
  }
}

// 2. Check GitHub Auth & Load Repos
async function checkGitHubAuth() {
  const sideName = document.getElementById('sideUserName');
  const sideAvatarImg = document.getElementById('sideAvatarImg');
  const settUserTitle = document.getElementById('settingsGhUserTitle');
  const settUserSub = document.getElementById('settingsGhUserSub');

  try {
    const res = await window.guardAPI.getGitHubAuthStatus();
    appState.githubAuth = res;

    if (res.authenticated && res.user) {
      sideName.textContent = res.user.login;
      sideAvatarImg.src = res.user.avatar_url;

      settUserTitle.textContent = `@${res.user.login} (${res.user.name || res.user.login})`;
      settUserSub.textContent = `Active via ${res.source === 'gh-cli' ? 'GitHub CLI (Keyring)' : 'Personal Access Token'}`;

      // Instant restore from Local Storage session or local disk cache
      const localCache = getLocalRepoCache(res.user.login);
      if (localCache && localCache.repos && localCache.repos.length > 0) {
        console.log('[Cache] Restored', localCache.repos.length, 'repos from localStorage');
        appState.repos = localCache.repos;
        appState.reposFetched = true;
        appState.lastSyncedAt = localCache.lastSyncedAt;
        updateRepoCounts();
        renderDashboardPillCards();
        renderGitHubFullGrid();
        updateCacheSyncBadge(`Local Session (${localCache.repos.length} repos) • Synced ${formatRelativeTime(localCache.lastSyncedAt)}`, 'success');

        // Fast background live server check without blocking the user
        syncReposWithLiveServer({ silent: true });
      } else {
        const diskCache = await window.guardAPI.getCachedRepos(res.user.login);
        if (diskCache && diskCache.repos && diskCache.repos.length > 0) {
          console.log('[Cache] Restored', diskCache.repos.length, 'repos from disk session cache');
          setLocalRepoCache(res.user.login, diskCache.repos, diskCache.lastSyncedAt);
          appState.repos = diskCache.repos;
          appState.reposFetched = true;
          appState.lastSyncedAt = diskCache.lastSyncedAt;
          updateRepoCounts();
          renderDashboardPillCards();
          renderGitHubFullGrid();
          updateCacheSyncBadge(`Local Session (${diskCache.repos.length} repos) • Synced ${formatRelativeTime(diskCache.lastSyncedAt)}`, 'success');

          syncReposWithLiveServer({ silent: true });
        } else {
          // No cache exists yet
          await loadGitHubRepos();
        }
      }
    } else {
      clearAppSession();
      // Launch screen redirects to GitHub connect when not authenticated
      switchView('view-account');
      renderAccountsView();
    }
  } catch (e) {
    console.error('GitHub auth check error:', e);
  }
}

async function loadGitHubRepos() {
  try {
    // Reset
    appState.repos = [];
    appState.displayCount = 30;
    appState.reposFetching = true;
    appState.reposFetched = false;

    const container = document.getElementById('dashboardCardsList');
    if (container) container.innerHTML = `
      <div class="loading-state-card">
        <div class="spinner-dot"></div>
        <span id="repoFetchStatus">Fetching repositories from GitHub...</span>
      </div>
    `;

    // This fires github:repos-progress events as pages come in,
    // then resolves when ALL pages are done.
    const allRepos = await window.guardAPI.fetchGitHubRepos();
    appState.repos = allRepos;
    appState.reposFetched = true;
    appState.reposFetching = false;

    const privates = allRepos.filter(r => r.is_private).length;
    const publics = allRepos.length - privates;

    document.getElementById('countAll').textContent = allRepos.length;
    document.getElementById('countPrivate').textContent = privates;
    document.getElementById('countPublic').textContent = publics;

    // Cache to local storage session
    const userLogin = (appState.githubAuth && appState.githubAuth.user && appState.githubAuth.user.login) || 'Webgenius0';
    appState.lastSyncedAt = new Date().toISOString();
    setLocalRepoCache(userLogin, allRepos, appState.lastSyncedAt);

    // Select all by default
    appState.selectedRepoIds = new Set(allRepos.map(r => r.id));
    updateSelectedCounts();

    renderDashboardPillCards();
    renderGitHubFullGrid();
    updateCacheSyncBadge(`Local Session (${allRepos.length} repos) • Up to date`, 'success');
  } catch (err) {
    appState.reposFetching = false;
    console.error('Load repos error:', err);
    document.getElementById('dashboardCardsList').innerHTML = `
      <div class="empty-state-box">
        <p style="color:#d64739;">Failed to load GitHub repositories: ${err.message}</p>
      </div>
    `;
  }
}

// Load More = just expand displayCount from the already-fetched allRepos array
function loadMoreGitHubRepos() {
  const STEP = 30;
  appState.displayCount = Math.min(appState.displayCount + STEP, appState.repos.length);
  renderDashboardPillCards();
  renderGitHubFullGrid();
}

// Render Dashboard Signature Colored Pill Cards
function renderDashboardPillCards() {
  const container = document.getElementById('dashboardCardsList');
  let items = [];

  if (appState.activeFilter === 'local') {
    // Show local targets
    items = appState.localTargets.map(t => ({
      type: 'local',
      title: t.name,
      sub: t.path,
      badge: 'Workstation',
      theme: 'theme-light',
      icon: '💻',
      raw: t
    }));
  } else {
    // Show GitHub Repos according to filter
    const session = getAccountScanSession();
    const scannedMap = session.scannedRepos || {};

    let filteredRepos = appState.repos.filter(r => {
      if (appState.activeFilter === 'private' && !r.is_private) return false;
      if (appState.activeFilter === 'public' && r.is_private) return false;
      if (appState.activeFilter === 'scanned' && !scannedMap[r.full_name]) return false;
      if (appState.activeFilter === 'unscanned' && Boolean(scannedMap[r.full_name])) return false;
      if (appState.searchQuery) {
        const q = appState.searchQuery.toLowerCase();
        return r.full_name.toLowerCase().includes(q) || (r.language || '').toLowerCase().includes(q);
      }
      return true;
    });

    const badge = document.getElementById('homeSearchCountBadge');
    if (badge) {
      badge.textContent = `${filteredRepos.length} matched`;
      badge.style.display = appState.searchQuery ? 'inline-block' : 'none';
    }

    const themes = ['theme-coral', 'theme-periwinkle', 'theme-turquoise'];

    items = filteredRepos.slice(0, appState.displayCount).map((r, idx) => {
      const theme = r.is_private ? 'theme-coral' : (idx % 2 === 0 ? 'theme-periwinkle' : 'theme-turquoise');
      const scanInfo = scannedMap[r.full_name];

      let scanBadgeText = '⏳ Not yet scanned';
      let scanBadgeColor = 'var(--text-muted)';
      let scanBadgeBg = 'var(--bg-canvas)';
      let scanBadgeBorder = '1px solid var(--border-light)';

      if (scanInfo) {
        if (scanInfo.status === 'clean') {
          scanBadgeText = `✅ Clean • ${formatRelativeTime(scanInfo.scannedAt)}`;
          scanBadgeColor = '#1e7e51';
          scanBadgeBg = '#eef7f2';
          scanBadgeBorder = '1px solid rgba(30,126,81,0.2)';
        } else if (scanInfo.status === 'infected') {
          scanBadgeText = `🚨 INFECTED (${scanInfo.findingsCount || 1} threats)`;
          scanBadgeColor = '#d64739';
          scanBadgeBg = '#fdeae8';
          scanBadgeBorder = '1px solid rgba(214,71,57,0.2)';
        } else {
          scanBadgeText = `⚠️ Scanned (${scanInfo.status})`;
          scanBadgeColor = '#a47d06';
          scanBadgeBg = '#fef6dc';
          scanBadgeBorder = '1px solid rgba(164,125,6,0.2)';
        }
      }

      return {
        type: 'github',
        id: r.id,
        title: r.name,
        sub: r.description || `Branch: ${r.default_branch || 'main'} • Size: ${r.size || 0} KB`,
        badge: r.is_private ? 'Private Repo' : 'Public Repo',
        scanBadgeText,
        scanBadgeColor,
        scanBadgeBg,
        scanBadgeBorder,
        theme: theme,
        icon: r.is_private ? '🔒' : '🌐',
        raw: r
      };
    });
  }

  if (items.length === 0) {
    if (!appState.githubAuth.authenticated && appState.activeFilter !== 'local') {
      container.innerHTML = `
        <div class="empty-state-box" style="padding: 32px 20px; text-align: center; color: var(--text-muted);">
          <p style="font-size: 14px; font-weight: 700; margin-bottom: 6px; color: var(--text-main);">GitHub Disconnected</p>
          <p style="font-size: 12px; margin-bottom: 14px;">Connect your GitHub account to load, monitor, and scan repositories.</p>
          <button class="btn-pill-primary" id="btnEmptyConnectGh" style="font-size: 11px; padding: 6px 16px;">Connect Account</button>
        </div>
      `;
      const btn = document.getElementById('btnEmptyConnectGh');
      if (btn) btn.addEventListener('click', () => switchView('view-account'));
    } else {
      container.innerHTML = `
        <div class="empty-state-box" style="padding: 24px; text-align: center; color: var(--text-muted);">
          <p>No repositories or targets found matching this view.</p>
        </div>
      `;
    }
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="pill-card-row ${item.theme}" data-id="${item.id || ''}">
      <div class="pill-card-left">
        <div class="pill-circle-badge">
          ${item.icon}
        </div>
        <div class="pill-card-text">
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <strong>${item.title}</strong>
            ${item.scanBadgeText ? `<span style="font-size:10px; font-weight:700; padding:2px 8px; border-radius:12px; color:${item.scanBadgeColor}; background:${item.scanBadgeBg}; border:${item.scanBadgeBorder};">${item.scanBadgeText}</span>` : ''}
          </div>
          <p>${item.sub}</p>
        </div>
      </div>
      <div class="pill-card-center-badge">
        ${item.badge}
      </div>
      <div class="pill-card-right">
        <button class="icon-action-btn btn-row-scan" title="Scan this target" data-id="${item.id || ''}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
        </button>
      </div>
    </div>
  `).join('');

  // Show / hide Load More button
  const loadMoreRow = document.getElementById('loadMoreRow');
  const loadMoreCount = document.getElementById('loadMoreCount');
  if (loadMoreRow) {
    const isGitHubView = appState.activeFilter !== 'local';
    const hasHiddenRepos = appState.repos.length > appState.displayCount;
    if (isGitHubView && hasHiddenRepos) {
      loadMoreRow.style.display = 'flex';
      if (loadMoreCount) {
        loadMoreCount.textContent = `(showing ${Math.min(appState.displayCount, appState.repos.length)} of ${appState.repos.length})`;
      }
    } else {
      loadMoreRow.style.display = 'none';
    }
  }

  // Attach click to scan single
  container.querySelectorAll('.btn-row-scan').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = Number(btn.dataset.id);
      const repo = appState.repos.find(r => r.id === id);
      if (repo) {
        startScanPipeline({ githubRepos: [repo], localPaths: [], scanLocalPc: false });
      }
    });
  });
}

// Render GitHub Full Grid Tab
function renderGitHubFullGrid() {
  const container = document.getElementById('githubRepoFullList');
  if (!container) return;

  if (!appState.repos.length) {
    container.innerHTML = '<div class="empty-state-box"><p>No repositories available. Authenticate with GitHub first.</p></div>';
    return;
  }

  const visibleRepos = appState.repos.slice(0, appState.displayCount);
  const totalCount = appState.repos.length;
  const hasMore = totalCount > appState.displayCount;

  container.innerHTML = `
    <div class="github-grid-meta">
      <span class="grid-meta-count">Showing <strong>${visibleRepos.length}</strong> of <strong>${totalCount}</strong> repositories</span>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        ${hasMore ? `<button class="btn-pill-secondary btn-grid-load-more">Load ${Math.min(30, totalCount - appState.displayCount)} More ▼</button>` : ''}
        <button class="btn-danger-outline btn-remove-all-collabs" style="font-size:11px; padding:5px 14px;">⛔ Remove All Collaborators</button>
      </div>
    </div>
    <div class="github-repo-cards" id="githubRepoCards">
    ${visibleRepos.map(r => {
      const isChecked = appState.selectedRepoIds.has(r.id);
      return `
        <div class="repo-card-soft">
          <div style="display: flex; align-items: center; gap: 12px;">
            <input type="checkbox" class="cb-repo-select" data-id="${r.id}" ${isChecked ? 'checked' : ''} style="accent-color: var(--accent-yellow); width: 16px; height: 16px;">
            <div>
              <strong style="font-size: 14px; color: var(--text-main);">${r.name}</strong>
              <p style="font-size: 11px; color: var(--text-muted);">${r.full_name} • ${r.is_private ? '🔒 Private' : '🌐 Public'} ${r.language ? '• ' + r.language : ''}</p>
            </div>
          </div>
          <div style="display:flex; gap:6px;">
            <button class="btn-pill-secondary btn-grid-scan" data-id="${r.id}">Audit</button>
          </div>
        </div>
      `;
    }).join('')}
    </div>
    ${hasMore ? `
      <div class="load-more-row">
        <button class="btn-load-more btn-grid-load-more-bottom">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" width="16" height="16"><polyline points="6 9 12 15 18 9"/></svg>
          Load More Repositories
          <span class="load-more-count">(showing ${visibleRepos.length} of ${totalCount})</span>
        </button>
      </div>` : ''}
  `;

  // Collaborator removal button
  container.querySelectorAll('.btn-remove-all-collabs').forEach(btn => {
    btn.addEventListener('click', () => startRemoveAllCollabs());
  });

  // Load more buttons in GitHub tab
  container.querySelectorAll('.btn-grid-load-more, .btn-grid-load-more-bottom').forEach(btn => {
    btn.addEventListener('click', () => {
      loadMoreGitHubRepos();
    });
  });

  container.querySelectorAll('.cb-repo-select').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const id = Number(e.target.dataset.id);
      if (e.target.checked) appState.selectedRepoIds.add(id);
      else appState.selectedRepoIds.delete(id);
      updateSelectedCounts();
    });
  });

  container.querySelectorAll('.btn-grid-scan').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = Number(btn.dataset.id);
      const repo = appState.repos.find(r => r.id === id);
      if (repo) startScanPipeline({ githubRepos: [repo], localPaths: [], scanLocalPc: false });
    });
  });
}

// Launch Remove All Collaborators workflow
async function startRemoveAllCollabs() {
  if (!confirm('⚠️ This will permanently remove ALL external collaborators from ALL your GitHub repositories.\n\nThis cannot be undone. Continue?')) return;

  // Show scanner modal as collab console
  const modal = document.getElementById('scannerModal');
  const logContainer = document.getElementById('modalConsoleLogs');
  const headingEl = document.querySelector('#scannerModal .scanner-box-head h3');
  const subEl = document.getElementById('modalCurrentTarget');
  const progressBar = document.getElementById('modalProgressBar');

  if (headingEl) headingEl.textContent = 'Removing All Collaborators';
  if (subEl) subEl.textContent = 'Scanning repositories...';
  if (progressBar) progressBar.style.width = '5%';
  if (logContainer) logContainer.innerHTML = '';
  if (modal) modal.classList.add('visible');

  // Listen for progress
  window.guardAPI.onCollabProgress((data) => {
    if (logContainer) {
      const line = document.createElement('div');
      line.className = data.type || 'info';
      line.textContent = data.msg;
      logContainer.appendChild(line);
      logContainer.scrollTop = logContainer.scrollHeight;
    }
    if (subEl) subEl.textContent = data.msg;
    if (progressBar) progressBar.style.width = '60%';
  });

  try {
    const result = await window.guardAPI.removeAllCollaborators();
    if (progressBar) progressBar.style.width = '100%';
    if (subEl) subEl.textContent = `Done — removed ${result.totalRemoved} collaborator(s)`;
    if (logContainer) {
      const line = document.createElement('div');
      line.className = 'success';
      line.textContent = `✓ Complete: ${result.totalRemoved} removed, ${result.totalErrors} errors`;
      logContainer.appendChild(line);
      logContainer.scrollTop = logContainer.scrollHeight;
    }
    // Auto-close after 4s
    setTimeout(() => { if (modal) modal.classList.remove('visible'); }, 4000);
  } catch (e) {
    if (subEl) subEl.textContent = 'Error: ' + e.message;
    if (progressBar) progressBar.style.background = 'var(--accent-coral)';
  }
}



function updateSelectedCounts() {
  document.getElementById('selectedCountTab').textContent = appState.selectedRepoIds.size;
}

// 3. Local Target & Disk Storage Management
async function loadLocalTargets() {
  try {
    const targets = await window.guardAPI.getLocalTargets();
    appState.localTargets = targets;
    
    // Default selection: select all existing targets if empty
    if (!appState.selectedLocalPaths || appState.selectedLocalPaths.size === 0) {
      appState.selectedLocalPaths = new Set(targets.filter(t => t.exists).map(t => t.path));
    }
    
    document.getElementById('countLocal').textContent = targets.length;
    renderLocalTargetsTab();
  } catch (e) {
    console.error('Failed to load local targets:', e);
  }
}

function renderLocalTargetsTab() {
  const disksContainer = document.getElementById('disksContainer');
  const foldersContainer = document.getElementById('localTargetsContainer');

  const disks = (appState.localTargets || []).filter(t => t.isDisk);
  const folders = (appState.localTargets || []).filter(t => !t.isDisk);

  const badgeDiskCount = document.getElementById('badgeDiskCount');
  if (badgeDiskCount) {
    badgeDiskCount.textContent = `${disks.length} Disk${disks.length === 1 ? '' : 's'}`;
  }

  const badgeFolderCount = document.getElementById('badgeFolderCount');
  if (badgeFolderCount) {
    badgeFolderCount.textContent = `${folders.length} Folder${folders.length === 1 ? '' : 's'}`;
  }

  // 1. Render Disks & Storage Drives
  if (disksContainer) {
    if (disks.length === 0) {
      disksContainer.innerHTML = `
        <div style="background:#ffffff; border:1px dashed var(--border-light); border-radius:12px; padding:24px; text-align:center; color:var(--text-muted);">
          <p style="margin:0; font-size:13px;">No physical storage disks detected. Click <strong>Refresh Disks</strong> to rescan.</p>
        </div>
      `;
    } else {
      disksContainer.innerHTML = disks.map(disk => {
        const isChecked = appState.selectedLocalPaths.has(disk.path);
        const fillClass = (disk.usedPercent > 90) ? 'fill-danger' : (disk.usedPercent > 70 ? 'fill-warn' : 'fill-safe');
        const avatarType = disk.isSystem ? 'disk-avatar-sys' : (disk.driveType === 'removable' ? 'disk-avatar-usb' : '');
        const avatarIcon = disk.isSystem ? '🖥️' : (disk.driveType === 'removable' ? '🔌' : '💾');

        return `
          <div class="disk-card" data-path="${disk.path}">
            <div class="disk-card-top">
              <div class="disk-card-info-group">
                <div class="disk-avatar ${avatarType}">
                  ${avatarIcon}
                </div>
                <div>
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <input type="checkbox" class="cb-target-select cb-disk-select" data-path="${disk.path}" ${isChecked ? 'checked' : ''} style="accent-color: var(--accent-yellow); width: 17px; height: 17px; cursor:pointer;">
                    <strong class="disk-title">${disk.name}</strong>
                    ${disk.isSystem ? '<span class="disk-tag disk-tag-system">SYSTEM BOOT</span>' : ''}
                    ${disk.driveType === 'removable' ? '<span class="disk-tag disk-tag-usb">EXTERNAL / REMOVABLE</span>' : ''}
                    <span class="disk-tag disk-tag-fs">${disk.fsType || 'Local Disk'}</span>
                  </div>
                  <div class="disk-path-line">
                    <span>Mount Point:</span>
                    <code>${disk.path}</code>
                  </div>
                </div>
              </div>
              <div class="disk-actions">
                <button class="btn-pill-primary btn-disk-scan" data-path="${disk.path}" style="font-size:12px; padding:6px 14px; display:inline-flex; align-items:center; gap:6px;">
                  ⚡ Scan Disk
                </button>
              </div>
            </div>
            
            <div class="disk-meter-container">
              <div class="disk-meter-track">
                <div class="disk-meter-fill ${fillClass}" style="width: ${Math.min(100, Math.max(2, disk.usedPercent))}%;"></div>
              </div>
              <div class="disk-meter-meta">
                <span class="disk-meter-text">
                  <strong>${disk.freeFormatted} free</strong> of ${disk.totalFormatted} (${disk.usedFormatted} used)
                </span>
                <span class="disk-meter-percent ${fillClass}">
                  ${disk.usedPercent}% Used
                </span>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // 2. Render Folders
  if (foldersContainer) {
    if (folders.length === 0) {
      foldersContainer.innerHTML = `
        <div style="background:#ffffff; border:1px dashed var(--border-light); border-radius:12px; padding:20px; text-align:center; color:var(--text-muted); font-size:13px;">
          No workstation directories added. Click <strong>+ Add Custom Folder / Drive</strong> to add one.
        </div>
      `;
    } else {
      foldersContainer.innerHTML = folders.map(f => {
        const isChecked = appState.selectedLocalPaths.has(f.path);
        return `
          <div class="target-card-soft">
            <div style="display: flex; align-items: center; gap: 12px;">
              <input type="checkbox" class="cb-local-select cb-folder-select" data-path="${f.path}" ${isChecked ? 'checked' : ''} style="accent-color: var(--accent-yellow); width: 16px; height: 16px; cursor:pointer;">
              <div>
                <strong style="font-size: 14px; color: var(--text-main); display:flex; align-items:center; gap:6px;">📁 ${f.name}</strong>
                <p style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin:2px 0 0 0;">${f.path}</p>
              </div>
            </div>
            <div>
              <button class="btn-pill-secondary btn-target-scan" data-path="${f.path}">Scan</button>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // 3. Bind Checkbox Events
  document.querySelectorAll('.cb-target-select, .cb-local-select').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const p = e.target.dataset.path;
      if (e.target.checked) appState.selectedLocalPaths.add(p);
      else appState.selectedLocalPaths.delete(p);
    });
  });

  // 4. Bind Individual Scan Buttons
  document.querySelectorAll('.btn-disk-scan, .btn-target-scan').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = btn.dataset.path;
      startScanPipeline({ githubRepos: [], localPaths: [p], scanLocalPc: true });
    });
  });
}

// 4. AI Settings
async function loadAiSettings() {
  try {
    const sett = await window.guardAPI.getAiSettings();
    appState.aiSettings = sett;
    document.getElementById('cfgAiProvider').value = sett.provider;
    document.getElementById('cfgAiModel').value = sett.model;
    document.getElementById('cfgOllamaEndpoint').value = sett.ollamaEndpoint;
    document.getElementById('aiProviderBadge').textContent = sett.provider.toUpperCase();
    if (sett.hasKey) {
      document.getElementById('cfgAiApiKey').value = sett.apiKey;
    }
  } catch (e) {
    console.error('Failed to load AI settings:', e);
  }
}

// 5. Scan Pipeline Execution with 10-Repo Batch Breakdown
let isScanPipelineRunning = false;
let shouldStopScanPipeline = false;

async function startScanPipeline(options) {
  if (isScanPipelineRunning) {
    alert('A scan is already currently running.');
    return;
  }
  isScanPipelineRunning = true;
  shouldStopScanPipeline = false;

  const modal = document.getElementById('scannerModal');
  const targetLabel = document.getElementById('modalCurrentTarget');
  const bar = document.getElementById('modalProgressBar');
  const percentTxt = document.getElementById('modalPercent');
  const countTxt = document.getElementById('modalCount');
  const logs = document.getElementById('modalConsoleLogs');

  logs.innerHTML = '';
  bar.style.width = '0%';
  percentTxt.textContent = '0%';
  countTxt.textContent = '0 Targets';
  targetLabel.textContent = 'Initializing Batch Scan Engine (10 repos per batch)...';
  modal.classList.add('active');

  const githubRepos = options.githubRepos || [];
  const localPaths = options.localPaths || Array.from(appState.selectedLocalPaths);
  const scanLocalPc = options.scanLocalPc !== false;
  const isAvEnabled = document.getElementById('chkFilterAv') ? document.getElementById('chkFilterAv').checked : true;
  const isGitDeep = document.getElementById('chkFilterGit') ? document.getElementById('chkFilterGit').checked : false;

  // Breakdown GitHub Repos into batches of 10
  const BATCH_SIZE = 10;
  const repoBatches = [];
  for (let i = 0; i < githubRepos.length; i += BATCH_SIZE) {
    repoBatches.push(githubRepos.slice(i, i + BATCH_SIZE));
  }

  const totalReposCount = githubRepos.length;
  let cumulativeScanned = 0;
  let cumulativeThreats = 0;

  window.guardAPI.onScanProgress(data => {
    targetLabel.textContent = `[${data.phase.toUpperCase()}] ${data.currentTarget}`;
  });

  window.guardAPI.onScanLog(log => {
    const div = document.createElement('div');
    div.className = log.type;
    div.textContent = `[${log.time}] ${log.message}`;
    logs.appendChild(div);
    logs.scrollTop = logs.scrollHeight;
  });

  try {
    const session = getAccountScanSession();

    // 1. Scan Local Workstation First if enabled
    if (scanLocalPc && localPaths.length > 0 && !shouldStopScanPipeline) {
      targetLabel.textContent = 'Inspecting Local Workstation Filesystem...';
      const localReport = await window.guardAPI.startScan({
        githubRepos: [],
        localPaths,
        scanLocalPc: true,
        runAntivirus: isAvEnabled,
        deepGitScan: isGitDeep
      });
      if (localReport) {
        session.reports.push(localReport);
        saveAccountScanSession(session);
        populateReportTab(getAggregatedSessionReport());
      }
    }

    // 2. Scan GitHub Repositories in Batches of 10
    if (repoBatches.length > 0) {
      for (let bIdx = 0; bIdx < repoBatches.length; bIdx++) {
        if (shouldStopScanPipeline) {
          const div = document.createElement('div');
          div.className = 'warning';
          div.textContent = `[STOPPED] Scan halted by user after Batch ${bIdx}/${repoBatches.length}.`;
          logs.appendChild(div);
          break;
        }

        const batch = repoBatches[bIdx];
        const batchNum = bIdx + 1;
        targetLabel.textContent = `Scanning Batch ${batchNum} of ${repoBatches.length} (10 Repositories)...`;

        const overallPercent = Math.round((cumulativeScanned / (totalReposCount || 1)) * 100);
        bar.style.width = `${overallPercent}%`;
        percentTxt.textContent = `${overallPercent}% (Batch ${batchNum}/${repoBatches.length})`;
        countTxt.textContent = `${cumulativeScanned} / ${totalReposCount} Repos`;

        // Execute scan for this batch of 10
        const batchReport = await window.guardAPI.startScan({
          githubRepos: batch,
          localPaths: [],
          scanLocalPc: false,
          runAntivirus: isAvEnabled,
          deepGitScan: isGitDeep
        });

        cumulativeScanned += (batchReport.reposScanned || []).length;
        cumulativeThreats += (batchReport.threatsFound || 0);

        // Store this batch of 10 in session
        (batchReport.reposScanned || []).forEach(r => {
          session.scannedRepos[r.full_name] = {
            scannedAt: new Date().toISOString(),
            status: r.status,
            findingsCount: (r.findings || []).length,
            findings: r.findings || []
          };
        });

        session.reports.push({
          batchNumber: batchNum,
          totalBatches: repoBatches.length,
          ...batchReport
        });
        saveAccountScanSession(session);

        // LIVE UPDATE: Generate/Update Report in real-time
        const currentAggReport = getAggregatedSessionReport();
        appState.lastScanReport = currentAggReport;
        populateReportTab(currentAggReport);

        // LIVE UPDATE: Update Dashboard Repos Badges & Counts
        updateRepoCounts();
        renderDashboardPillCards();
        renderGitHubFullGrid();

        // Telemetry log in modal
        const logDiv = document.createElement('div');
        logDiv.className = batchReport.threatsFound > 0 ? 'danger' : 'success';
        logDiv.textContent = `[REPORT GENERATED] Batch ${batchNum}/${repoBatches.length} (10 repos) complete! Generated report. Threats: ${batchReport.threatsFound}.`;
        logs.appendChild(logDiv);
        logs.scrollTop = logs.scrollHeight;

        const updatedPercent = Math.round((cumulativeScanned / (totalReposCount || 1)) * 100);
        bar.style.width = `${updatedPercent}%`;
        percentTxt.textContent = `${updatedPercent}%`;
        countTxt.textContent = `${cumulativeScanned} / ${totalReposCount} Repos`;

        // Small pause between batches to allow UI to breathe and user to cancel
        if (bIdx < repoBatches.length - 1 && !shouldStopScanPipeline) {
          await new Promise(r => setTimeout(r, 800));
        }
      }
    }

    setTimeout(() => {
      modal.classList.remove('active');
      switchView('view-reports');
      populateReportTab(getAggregatedSessionReport());
    }, 1000);

  } catch (e) {
    console.error('Scan error:', e);
    alert('Scan error: ' + e.message);
    modal.classList.remove('active');
  } finally {
    isScanPipelineRunning = false;
  }
}

// 6. Populate Threat Reports Tab (Persisted Per-Account Session Reports)
function populateReportTab(report) {
  const session = getAccountScanSession();
  const effectiveReport = report || getAggregatedSessionReport();

  // Update session header info in reports tab
  const tagEl = document.getElementById('reportSessionAccountTag');
  const sumEl = document.getElementById('reportSessionSummaryTxt');
  const lastEl = document.getElementById('reportSessionLastScannedTxt');

  if (tagEl) tagEl.textContent = `Active Session: @${session.account || 'Unknown'}`;
  if (sumEl) sumEl.textContent = `Scan Session: ${effectiveReport.scannedCount || 0} of ${appState.repos.length} Repos Scanned (${session.reports ? session.reports.length : 0} Batches)`;
  if (lastEl) lastEl.textContent = session.lastUpdated ? `Last Scan: ${formatRelativeTime(session.lastUpdated)}` : 'Last Scan: Never';

  document.getElementById('statScannedCount').textContent = effectiveReport.scannedCount || 0;
  document.getElementById('statThreatCount').textContent = effectiveReport.threatsFound || 0;
  document.getElementById('statCleanCount').textContent = effectiveReport.summary ? effectiveReport.summary.clean : 0;
  document.getElementById('statWarningsCount').textContent = effectiveReport.summary ? effectiveReport.summary.warnings : 0;

  const reportToRender = effectiveReport;

  const allItems = [
    ...(reportToRender.reposScanned || []).map(r => ({
      title: r.full_name,
      type: r.is_private ? '🔒 Private' : '🌐 Public',
      status: r.status,
      findings: r.findings
    })),
    ...(reportToRender.localScanned || []).map(l => ({
      title: l.path,
      type: '💻 Workstation',
      status: l.status,
      findings: l.findings
    }))
  ];

  const container = document.getElementById('reportFindingsList');
  if (allItems.length === 0) {
    container.innerHTML = '<div class="empty-state-box"><p>No items scanned.</p></div>';
    return;
  }

  container.innerHTML = allItems.map((item, itemIdx) => {
    const findingsList = item.findings || [];
    const hasUnneutralized = findingsList.some(f => !f.neutralized && !(f.detail && f.detail.neutralized));
    const isCleanOrNeutralized = item.status === 'clean' || (!hasUnneutralized && findingsList.length > 0);
    const badgeColor = isCleanOrNeutralized ? '#1e7e51' : '#d64739';
    const badgeBg = isCleanOrNeutralized ? '#e6f6ee' : '#fdeae8';
    const badgeText = isCleanOrNeutralized ? (findingsList.length > 0 ? 'NEUTRALIZED' : 'CLEAN') : 'INFECTED';
    const borderLeftColor = isCleanOrNeutralized ? 'var(--accent-green)' : 'var(--accent-coral)';

    return `
    <div style="background:#ffffff; border:1px solid var(--border-light); border-radius:12px; padding:14px 16px; margin-bottom:10px; border-left: 4px solid ${borderLeftColor};">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px; flex-wrap:wrap; gap:8px;">
        <div>
          <span style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">${item.type}</span>
          <strong style="font-size:14px; color:var(--text-main); display:block; margin-top:2px;">${item.title}</strong>
        </div>
        <span style="font-size:11px; font-weight:800; padding:4px 10px; border-radius:var(--radius-pill); background:${badgeBg}; color:${badgeColor};">
          ${badgeText}
        </span>
      </div>
      ${findingsList.length > 0 ? `
        <div style="display:flex; flex-direction:column; gap:8px; margin-top:10px;">
          ${findingsList.map(f => {
            const info = formatFinding(f);
            return `
              <div style="background:#f9f7f2; border:1px solid var(--border-light); border-radius:8px; padding:10px 12px; min-width:0; word-break:break-word;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                  <span style="font-size:10px; font-weight:800; padding:2px 7px; border-radius:4px; background:${info.isNeutralized ? '#e6f6ee' : (info.severity === 'CRITICAL' ? '#fdeae8' : '#fef6dc')}; color:${info.isNeutralized ? '#1e7e51' : (info.severity === 'CRITICAL' ? '#d64739' : '#a47d06')}; font-family:var(--font-mono);">
                    ${info.isNeutralized ? '✓ NEUTRALIZED' : `${info.severity} // ${info.category}`}
                  </span>
                  <strong style="font-size:12px; color:var(--text-main);">${info.title}</strong>
                </div>
                <p style="font-size:11px; color:var(--text-muted); margin:6px 0; line-height:1.4;">${info.desc}</p>
                ${info.where ? `<div style="font-size:10px; color:var(--text-main); font-family:var(--font-mono); background:#ffffff; padding:4px 8px; border-radius:4px; border:1px solid var(--border-light); word-break:break-all; overflow-wrap:anywhere;">📁 ${info.where}</div>` : ''}
                ${info.isNeutralized ? `
                  <div style="margin-top:8px;">
                    <span style="font-size:11px; font-weight:700; color:#1e7e51; background:#e6f6ee; padding:4px 10px; border-radius:var(--radius-pill); display:inline-flex; align-items:center; gap:5px;">
                      🛡️ Neutralized • Saved in Session
                    </span>
                  </div>
                ` : (info.isActionable ? `
                  <div style="margin-top:8px;">
                    <button class="btn-clean-action" data-repo="${item.title}" data-where="${info.where}" data-raw='${JSON.stringify(info.raw).replace(/'/g, "&apos;")}' style="background:var(--accent-yellow); color:var(--text-main); border:none; padding:5px 14px; border-radius:var(--radius-pill); font-size:11px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:4px;">
                      ⚡ Neutralize Threat
                    </button>
                  </div>
                ` : '')}
              </div>
            `;
          }).join('')}
        </div>
      ` : ''}
    </div>
  `;
  }).join('');

  // Wire auto-clean buttons to neutralize and persist to session
  container.querySelectorAll('.btn-clean-action').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const raw = JSON.parse(btn.getAttribute('data-raw'));
      const repoTarget = btn.getAttribute('data-repo') || raw.repoFullName || raw.where;
      const findingWhere = btn.getAttribute('data-where');

      btn.disabled = true;
      btn.textContent = 'Neutralizing...';

      try {
        const res = await window.guardAPI.autoCleanThreat(raw);
        if (res.success) {
          markThreatNeutralized(repoTarget, findingWhere);
          alert(res.message || 'Threat successfully neutralized and recorded in session.');
        } else {
          btn.disabled = false;
          btn.textContent = 'Fix manually';
          alert('Notice: ' + res.error);
        }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Retry Neutralize';
        alert('Error: ' + err.message);
      }
    });
  });
}

function formatFinding(f) {
  let data = f.detail;
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch (_) {}
  }

  const isNeutralized = Boolean(f.neutralized || (typeof data === 'object' && data.neutralized));
  let title = 'Security Anomaly';
  let desc = typeof data === 'string' ? data : (data.desc || data.details || JSON.stringify(data));
  let where = typeof data === 'object' && data.where ? data.where : (typeof data === 'object' && data.fullPath ? data.fullPath : '');
  let category = (f.category || (typeof data === 'object' && data.category) || 'THREAT').toUpperCase();
  let severity = (typeof data === 'object' && data.severity) ? data.severity.toUpperCase() : 'HIGH';
  let isActionable = Boolean(where || (typeof data === 'object' && data.fullPath));

  if (category === 'MALICIOUS_DEPS' || category === 'MALICIOUS-DEPENDENCY') {
    if (data.type === 'dependency_audit' || data.packages) {
      const count = data.count || (data.packages ? data.packages.length : 0);
      title = `Supply-Chain Advisory: ${count} Manifest References`;
      category = 'DEPENDENCY ADVISORY';
      severity = 'HIGH';
      isActionable = false;

      let pkgList = data.packages ? data.packages.slice(0, 8).map(p => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:4px 0; border-bottom:1px solid rgba(0,0,0,0.05); font-size:11px;">
          <span>📦 <strong>${p.name}</strong> <span style="color:#747886; font-size:10px;">(installed: ${p.yourVersion})</span></span>
          <span style="font-family:var(--font-mono); color:#a47d06; font-size:10px; background:#fef6dc; padding:2px 6px; border-radius:4px;">${p.manifest} &bull; range: ${p.maliciousRange}</span>
        </div>
      `).join('') : '';

      if (data.packages && data.packages.length > 8) {
        pkgList += `<div style="font-size:10px; color:#747886; margin-top:4px;">+ ${data.packages.length - 8} more references</div>`;
      }

      desc = `<div style="margin-bottom:6px;">Found ${count} package reference(s) matching known advisory databases:</div>
              <div style="background:#ffffff; border:1px solid var(--border-light); border-radius:8px; padding:6px 10px;">${pkgList}</div>
              <div style="margin-top:8px; font-size:11px; font-weight:700; color:var(--text-main);">Suggested action: Run <code>pnpm update --latest</code> or <code>npm audit fix</code></div>`;
    } else if (typeof data === 'string' && data.includes('[npm]')) {
      const regex = /\[([a-zA-Z0-9_-]+)\]\s+([a-zA-Z0-9_@\/\.-]+)\s+\(your version:\s*([^;]+);\s*malicious range:\s*([^)]+)\)\s*(?:in\s*([a-zA-Z0-9_\/\.-]+))?/gi;
      const pkgs = [];
      let m;
      while ((m = regex.exec(data)) !== null) {
        pkgs.push({ name: m[2], yourVersion: m[3].trim(), maliciousRange: m[4].trim(), manifest: m[5] ? m[5].trim() : 'manifest' });
      }

      if (pkgs.length > 0) {
        title = `Supply-Chain Advisory: ${pkgs.length} Manifest References`;
        category = 'DEPENDENCY ADVISORY';
        severity = 'HIGH';
        isActionable = false;

        let pkgList = pkgs.slice(0, 8).map(p => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:4px 0; border-bottom:1px solid rgba(0,0,0,0.05); font-size:11px;">
            <span>📦 <strong>${p.name}</strong> <span style="color:#747886; font-size:10px;">(installed: ${p.yourVersion})</span></span>
            <span style="font-family:var(--font-mono); color:#a47d06; font-size:10px; background:#fef6dc; padding:2px 6px; border-radius:4px;">${p.manifest} &bull; range: ${p.maliciousRange}</span>
          </div>
        `).join('');

        if (pkgs.length > 8) {
          pkgList += `<div style="font-size:10px; color:#747886; margin-top:4px;">+ ${pkgs.length - 8} more references</div>`;
        }

        desc = `<div style="margin-bottom:6px;">Found ${pkgs.length} package reference(s) matching known advisory databases:</div>
                <div style="background:#ffffff; border:1px solid var(--border-light); border-radius:8px; padding:6px 10px;">${pkgList}</div>
                <div style="margin-top:8px; font-size:11px; font-weight:700; color:var(--text-main);">Suggested action: Run <code>pnpm update --latest</code> or <code>npm audit fix</code></div>`;
      } else {
        title = `Poisoned Package: ${data.name || 'malicious package'}`;
        category = 'MALICIOUS DEPENDENCY';
      }
    } else {
      title = `Poisoned Package: ${data.name || 'malicious package'}`;
      category = 'MALICIOUS DEPENDENCY';
    }
  } else if (category === 'BEAVER_TAIL_DROPPER') {
    title = `Lazarus / BeaverTail: ${data.name || 'Dropper Injection'}`;
    category = 'BEAVERTAIL DROPPER';
    severity = 'CRITICAL';
  } else if (category === 'VSCODE') {
    title = 'VS Code Configuration Exploit';
  } else if (category === 'WORKFLOW_BASELINE') {
    title = 'CI/CD Workflow Tampering';
  } else if (category === 'AV') {
    title = 'Antivirus Signature Match';
  } else if (category === 'CODESIGN_TAMPERING' || category === 'CODESIGN') {
    title = (typeof data === 'object' && data.title) || 'VS Code Application Binary Tampering';
    category = 'BINARY INTEGRITY';
    severity = 'CRITICAL';
    isActionable = false;
  }

  if (isNeutralized) {
    severity = 'NEUTRALIZED';
    category = 'REMEDIATED';
    isActionable = false;
  }

  return { title, desc, where, category, severity, isActionable, isNeutralized, raw: typeof data === 'object' ? data : { where, desc } };
}

// 7. Event Listeners Setup
function initEventListeners() {
  // Hero Run Scan Button
  document.getElementById('btnHeroRunScan').addEventListener('click', () => {
    const reposToScan = appState.repos;
    const localToScan = Array.from(appState.selectedLocalPaths);
    startScanPipeline({ githubRepos: reposToScan, localPaths: localToScan, scanLocalPc: true });
  });

  // Hero Add Path
  document.getElementById('heroBtnAddPath').addEventListener('click', async () => {
    const chosen = await window.guardAPI.selectDirectory();
    if (chosen) {
      appState.localTargets.push({ id: 'custom_' + Date.now(), name: chosen.split('/').pop() || chosen, path: chosen, exists: true, isDisk: false });
      appState.selectedLocalPaths.add(chosen);
      document.getElementById('countLocal').textContent = appState.localTargets.length;
      renderDashboardPillCards();
      renderLocalTargetsTab();
    }
  });

  // Local PC: Add Custom Folder / Drive buttons
  const addFolderHandler = async () => {
    const chosen = await window.guardAPI.selectDirectory();
    if (chosen) {
      const base = chosen.split(/[\\/]/).filter(Boolean).pop() || chosen;
      appState.localTargets.push({ id: 'custom_' + Date.now(), name: base, path: chosen, exists: true, isDisk: false });
      appState.selectedLocalPaths.add(chosen);
      document.getElementById('countLocal').textContent = appState.localTargets.length;
      renderDashboardPillCards();
      renderLocalTargetsTab();
    }
  };

  const btnBrowseCustom = document.getElementById('btnBrowseCustomFolder');
  if (btnBrowseCustom) btnBrowseCustom.addEventListener('click', addFolderHandler);

  const btnSelectCustomDir = document.getElementById('btnSelectCustomDir');
  if (btnSelectCustomDir) btnSelectCustomDir.addEventListener('click', addFolderHandler);

  // Local PC: Select All Disks
  const btnSelectAllDisks = document.getElementById('btnSelectAllDisks');
  if (btnSelectAllDisks) {
    btnSelectAllDisks.addEventListener('click', () => {
      const disks = (appState.localTargets || []).filter(t => t.isDisk);
      const allSelected = disks.every(d => appState.selectedLocalPaths.has(d.path));
      disks.forEach(d => {
        if (allSelected) appState.selectedLocalPaths.delete(d.path);
        else appState.selectedLocalPaths.add(d.path);
      });
      btnSelectAllDisks.textContent = allSelected ? 'Select All Disks' : 'Deselect All Disks';
      renderLocalTargetsTab();
    });
  }

  // Local PC: Scan Selected Disks
  const btnScanAllDisks = document.getElementById('btnScanAllDisks');
  if (btnScanAllDisks) {
    btnScanAllDisks.addEventListener('click', () => {
      const disks = (appState.localTargets || []).filter(t => t.isDisk);
      let selectedDisks = disks.filter(d => appState.selectedLocalPaths.has(d.path));
      if (selectedDisks.length === 0) {
        // If none selected, scan all disks
        selectedDisks = disks;
        disks.forEach(d => appState.selectedLocalPaths.add(d.path));
      }
      if (selectedDisks.length === 0) {
        alert('No mounted storage disks detected to scan.');
        return;
      }
      startScanPipeline({
        githubRepos: [],
        localPaths: selectedDisks.map(d => d.path),
        scanLocalPc: true
      });
    });
  }

  // Local PC: Refresh Disks button
  const btnRefreshDisks = document.getElementById('btnRefreshDisks');
  if (btnRefreshDisks) {
    btnRefreshDisks.addEventListener('click', async () => {
      btnRefreshDisks.disabled = true;
      btnRefreshDisks.textContent = 'Refreshing...';
      try {
        await loadLocalTargets();
      } finally {
        btnRefreshDisks.disabled = false;
        btnRefreshDisks.textContent = '🔄 Refresh Disks';
      }
    });
  }

  // Local PC: Select All Folders
  const btnSelectAllFolders = document.getElementById('btnSelectAllFolders');
  if (btnSelectAllFolders) {
    btnSelectAllFolders.addEventListener('click', () => {
      const folders = (appState.localTargets || []).filter(t => !t.isDisk);
      const allSelected = folders.every(f => appState.selectedLocalPaths.has(f.path));
      folders.forEach(f => {
        if (allSelected) appState.selectedLocalPaths.delete(f.path);
        else appState.selectedLocalPaths.add(f.path);
      });
      btnSelectAllFolders.textContent = allSelected ? 'Select All Folders' : 'Deselect All Folders';
      renderLocalTargetsTab();
    });
  }

  // Local PC: Run Local Direct PC Scan
  const btnRunLocalDirect = document.getElementById('btnRunLocalDirect');
  if (btnRunLocalDirect) {
    btnRunLocalDirect.addEventListener('click', () => {
      let paths = Array.from(appState.selectedLocalPaths);
      if (paths.length === 0) {
        // Fallback: select all existing targets
        (appState.localTargets || []).forEach(t => appState.selectedLocalPaths.add(t.path));
        paths = Array.from(appState.selectedLocalPaths);
      }
      startScanPipeline({
        githubRepos: [],
        localPaths: paths,
        scanLocalPc: true
      });
    });
  }

  // Filter Pills (All / Private / Public / Local)
  document.querySelectorAll('#repoFilterPills .pill-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#repoFilterPills .pill-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      appState.activeFilter = tab.getAttribute('data-filter');
      renderDashboardPillCards();
    });
  });

  // Global Search Input
  
  // Home Screen Dedicated Repo Search
  const homeSearch = document.getElementById('homeRepoSearchInput');
  if (homeSearch) {
    homeSearch.addEventListener('input', (e) => {
      appState.searchQuery = e.target.value.trim();
      const topSearch = document.getElementById('globalSearchInput');
      if (topSearch && topSearch.value !== e.target.value) {
        topSearch.value = e.target.value;
      }
      renderDashboardPillCards();
    });
  }

document.getElementById('globalSearchInput').addEventListener('input', (e) => {
    appState.searchQuery = e.target.value.trim();
    renderDashboardPillCards();
  });

  // Quick Action in Dock
  document.getElementById('btnQuickDockAction').addEventListener('click', () => {
    startScanPipeline({
      githubRepos: appState.repos,
      localPaths: Array.from(appState.selectedLocalPaths),
      scanLocalPc: true
    });
  });

  // Right Panel "Apply filters & Scan"
  document.getElementById('btnRightApplyFilters').addEventListener('click', () => {
    const scanPrivate = document.getElementById('chkFilterPrivate').checked;
    const scanPublic = document.getElementById('chkFilterPublic').checked;

    let targetRepos = appState.repos.filter(r => {
      if (r.is_private && !scanPrivate) return false;
      if (!r.is_private && !scanPublic) return false;
      return true;
    });

    startScanPipeline({
      githubRepos: targetRepos,
      localPaths: Array.from(appState.selectedLocalPaths),
      scanLocalPc: true
    });
  });

  // Right Panel Watchpoint Rows
  document.querySelectorAll('.side-item-row').forEach(row => {
    row.addEventListener('click', () => {
      const targetKey = row.dataset.target;
      const found = appState.localTargets.find(t => t.id === targetKey);
      if (found) {
        startScanPipeline({ githubRepos: [], localPaths: [found.path], scanLocalPc: true });
      }
    });
  });

  // VS Code Codesign Direct Verify button
  const btnVerifyVsCode = document.getElementById('btnVerifyVsCodeDirect');
  const vsBanner = document.getElementById('vscodeCodesignBanner');
  const vsBadge = document.getElementById('vscodeCodesignBadge');
  const vsMsg = document.getElementById('vscodeCodesignMsg');
  const btnCloseVs = document.getElementById('btnCloseVsCodeBanner');

  if (btnCloseVs && vsBanner) {
    btnCloseVs.addEventListener('click', () => {
      vsBanner.style.display = 'none';
    });
  }

  if (btnVerifyVsCode) {
    btnVerifyVsCode.addEventListener('click', async () => {
      btnVerifyVsCode.disabled = true;
      btnVerifyVsCode.textContent = 'Verifying Terminal Signature...';

      if (vsBanner) {
        vsBanner.style.display = 'block';
        vsBadge.style.background = '#fef6dc';
        vsBadge.style.color = '#a47d06';
        vsBadge.textContent = 'RUNNING';
        vsMsg.textContent = 'Executing Apple strict deep verification on terminal...';
      }

      try {
        const res = await window.guardAPI.verifyVsCodeCodesign();
        if (res.success) {
          vsBadge.style.background = '#eef7f2';
          vsBadge.style.color = '#1e7e51';
          vsBadge.textContent = 'VERIFIED INTACT';
          vsMsg.innerHTML = '<span style="color:#1e7e51; font-weight:700;">✅ Safe:</span> ' + res.output;
        } else {
          vsBadge.style.background = '#fdeae8';
          vsBadge.style.color = '#d64739';
          vsBadge.textContent = 'TAMPERED / FAILED';
          vsMsg.innerHTML = '<span style="color:#d64739; font-weight:700;">⚠️ Threat Detected:</span> ' + res.output;
        }
      } catch (err) {
        if (vsBadge) {
          vsBadge.style.background = '#fdeae8';
          vsBadge.style.color = '#d64739';
          vsBadge.textContent = 'ERROR';
        }
        if (vsMsg) vsMsg.textContent = 'Execution failed: ' + err.message;
      } finally {
        btnVerifyVsCode.disabled = false;
        btnVerifyVsCode.innerHTML = '🛡️ Verify VS Code Signature';
      }
    });
  }

  
  // Antigravity Code Signature Direct Verify button
  const btnVerifyAntigravity = document.getElementById('btnVerifyAntigravityDirect');
  if (btnVerifyAntigravity) {
    btnVerifyAntigravity.addEventListener('click', async () => {
      btnVerifyAntigravity.disabled = true;
      btnVerifyAntigravity.textContent = 'Verifying Antigravity Signature...';

      if (vsBanner) {
        vsBanner.style.display = 'block';
        vsBadge.style.background = '#fef6dc';
        vsBadge.style.color = '#a47d06';
        vsBadge.textContent = 'RUNNING';
        const cmdEl = document.getElementById('vscodeCodesignCmd');
        if (cmdEl) cmdEl.textContent = 'codesign --verify --deep --strict "/Applications/Antigravity IDE.app"';
        vsMsg.textContent = 'Executing strict deep signature verification on Antigravity IDE...';
      }

      try {
        const res = await window.guardAPI.verifyAppSignature('antigravity');
        const cmdEl = document.getElementById('vscodeCodesignCmd');
        if (cmdEl && res.command) cmdEl.textContent = res.command;

        if (res.success) {
          vsBadge.style.background = '#eef7f2';
          vsBadge.style.color = '#1e7e51';
          vsBadge.textContent = 'VERIFIED INTACT';
          vsMsg.innerHTML = '<span style="color:#1e7e51; font-weight:700;">✅ Safe:</span> ' + res.appName + ' signature is sealed, valid, and untampered: ' + res.output;
        } else {
          vsBadge.style.background = '#fdeae8';
          vsBadge.style.color = '#d64739';
          vsBadge.textContent = 'TAMPERED / FAILED';
          vsMsg.innerHTML = '<span style="color:#d64739; font-weight:700;">⚠️ Threat Detected:</span> ' + res.output;
        }
      } catch (err) {
        if (vsBadge) {
          vsBadge.style.background = '#fdeae8';
          vsBadge.style.color = '#d64739';
          vsBadge.textContent = 'ERROR';
        }
        if (vsMsg) vsMsg.textContent = 'Verification error: ' + err.message;
      } finally {
        btnVerifyAntigravity.disabled = false;
        btnVerifyAntigravity.innerHTML = '🚀 Verify Antigravity';
      }
    });
  }

  // Cancel / Pause Scan Pipeline
  document.getElementById('btnCancelScan').addEventListener('click', async () => {
    shouldStopScanPipeline = true;
    await window.guardAPI.cancelScan();
  });

  // Reset Session Reports Button
  const btnClearReports = document.getElementById('btnClearSessionReports');
  if (btnClearReports) {
    btnClearReports.addEventListener('click', () => {
      if (confirm('Clear scan report history for this GitHub session?')) {
        clearAccountScanSession();
        updateRepoCounts();
        renderDashboardPillCards();
        renderGitHubFullGrid();
        populateReportTab(getAggregatedSessionReport());
      }
    });
  }

  // Universal Browser OAuth Authorization Flow
  let activeVerificationUri = 'https://github.com/login/device';

  async function startBrowserOAuthFlow() {
    const modal = document.getElementById('modalOAuthDevice');
    const codeEl = document.getElementById('oauthDeviceUserCode');
    const statusEl = document.getElementById('oauthStatusText');
    const badgeEl = document.getElementById('oauthCopyBadge');

    if (modal) modal.style.display = 'flex';
    if (codeEl) codeEl.textContent = '••••-••••';
    if (statusEl) statusEl.textContent = 'Contacting GitHub and opening browser...';
    if (badgeEl) badgeEl.style.display = 'none';

    try {
      const res = await window.guardAPI.loginGitHubBrowser();
      if (res && res.success) {
        if (statusEl) statusEl.textContent = `✓ Successfully authenticated @${res.user.login || 'GitHub'}!`;
        await checkGitHubAuth();
        await loadSavedAccountsInSettings();
        await renderAccountsView();
        setTimeout(() => {
          if (modal) modal.style.display = 'none';
        }, 1200);
      } else if (res && res.error) {
        if (statusEl) statusEl.textContent = 'Authorization status: ' + res.error;
      }
    } catch (err) {
      if (statusEl) statusEl.textContent = 'Error: ' + err.message;
    }
  }

  // Device Code event from backend
  if (window.guardAPI && window.guardAPI.onOAuthDeviceCode) {
    window.guardAPI.onOAuthDeviceCode((data) => {
      const codeEl = document.getElementById('oauthDeviceUserCode');
      const statusEl = document.getElementById('oauthStatusText');
      const badgeEl = document.getElementById('oauthCopyBadge');
      if (data && data.userCode) {
        if (codeEl) codeEl.textContent = data.userCode;
        if (badgeEl) badgeEl.style.display = 'block';
        if (statusEl) statusEl.textContent = 'Enter the code in your browser and click Authorize...';
        activeVerificationUri = data.verificationUri || 'https://github.com/login/device';
      }
    });
  }

  // Cancel OAuth button
  const btnCancelOAuth = document.getElementById('btnCancelOAuthDevice');
  if (btnCancelOAuth) {
    btnCancelOAuth.addEventListener('click', async () => {
      const modal = document.getElementById('modalOAuthDevice');
      if (modal) modal.style.display = 'none';
      if (window.guardAPI && window.guardAPI.cancelOAuthLogin) {
        await window.guardAPI.cancelOAuthLogin();
      }
    });
  }

  // Re-open browser button
  const btnOpenBrowserAgain = document.getElementById('oauthOpenBrowserBtn');
  if (btnOpenBrowserAgain) {
    btnOpenBrowserAgain.addEventListener('click', () => {
      window.open(activeVerificationUri, '_blank');
    });
  }

  // Account Tab: Browser OAuth button
  const btnAcctTabOAuth = document.getElementById('btnAccountTabOAuthBrowser');
  if (btnAcctTabOAuth) {
    btnAcctTabOAuth.addEventListener('click', () => {
      startBrowserOAuthFlow();
    });
  }

  // AI Analysis Trigger
  document.getElementById('btnGenerateAiTab').addEventListener('click', async () => {
    const container = document.getElementById('aiAnalysisContainer');
    if (!appState.lastScanReport) {
      alert('Please run a security scan first before generating an AI Report.');
      return;
    }

    container.innerHTML = `
      <div style="text-align: center; padding: 30px;">
        <span style="font-size: 28px; animation: pulse-dot 1.2s infinite;">🤖</span>
        <h4 style="margin-top: 10px; color: var(--text-main);">AI Security Analysis in Progress...</h4>
        <p style="color: var(--text-muted); font-size: 11px;">Evaluating supply chain attack vectors and generating remediation plan.</p>
      </div>
    `;

    try {
      const response = await window.guardAPI.generateAiAnalysis(appState.lastScanReport);
      renderAiMarkdown(response);
    } catch (e) {
      container.innerHTML = `
        <div style="text-align: center; padding: 24px; color: #d64739;">
          <h4>AI Generation Failed</h4>
          <p style="font-size: 12px; margin: 8px 0;">${e.message}</p>
          <button class="btn-pill-secondary" style="margin-top: 10px;" onclick="switchView('view-settings')">Configure API Key in Settings</button>
        </div>
      `;
    }
  });

  // Export JSON & HTML
  document.getElementById('btnExportJsonTab').addEventListener('click', async () => {
    if (!appState.lastScanReport) return alert('No report available yet.');
    const res = await window.guardAPI.exportReport({ format: 'json', data: appState.lastScanReport });
    if (res.success) alert('Exported to: ' + res.filePath);
  });

  document.getElementById('btnExportHtmlTab').addEventListener('click', async () => {
    if (!appState.lastScanReport) return alert('No report available yet.');
    const res = await window.guardAPI.exportReport({ format: 'html', data: appState.lastScanReport });
    if (res.success) alert('Exported to: ' + res.filePath);
  });

  // Settings Actions
  document.getElementById('cfgAiProvider').addEventListener('change', (e) => {
    const isOllama = e.target.value === 'ollama';
    document.getElementById('grpOllamaEndpoint').style.display = isOllama ? 'block' : 'none';
    document.getElementById('grpApiKey').style.display = isOllama ? 'none' : 'block';
  });

  document.getElementById('btnToggleKeyVis').addEventListener('click', () => {
    const inp = document.getElementById('cfgAiApiKey');
    const btn = document.getElementById('btnToggleKeyVis');
    if (inp.type === 'password') {
      inp.type = 'text';
      btn.textContent = 'Hide';
    } else {
      inp.type = 'password';
      btn.textContent = 'Show';
    }
  });

  document.getElementById('btnSaveAiCfg').addEventListener('click', async () => {
    const feedback = document.getElementById('aiFeedbackMsg');
    feedback.textContent = 'Saving...';
    try {
      await window.guardAPI.saveAiSettings({
        provider: document.getElementById('cfgAiProvider').value,
        apiKey: document.getElementById('cfgAiApiKey').value,
        model: document.getElementById('cfgAiModel').value,
        ollamaEndpoint: document.getElementById('cfgOllamaEndpoint').value
      });
      feedback.textContent = '✓ Saved successfully!';
      setTimeout(() => feedback.textContent = '', 3000);
    } catch (e) {
      feedback.textContent = 'Error: ' + e.message;
    }
  });

  document.getElementById('btnSaveGhCfg').addEventListener('click', async () => {
    const feedback = document.getElementById('ghFeedbackMsg');
    feedback.textContent = 'Validating token...';
    try {
      const res = await window.guardAPI.saveGitHubToken(document.getElementById('cfgGhToken').value);
      if (res.success) {
        feedback.textContent = '✓ Token authenticated!';
        await checkGitHubAuth();
      } else {
        feedback.textContent = 'Error: ' + res.error;
      }
      setTimeout(() => feedback.textContent = '', 4000);
    } catch (e) {
      feedback.textContent = 'Error: ' + e.message;
    }
  });

  
  const btnOAuth = document.getElementById('btnOAuthBrowser');
  if (btnOAuth) {
    btnOAuth.addEventListener('click', async () => {
      const feedback = document.getElementById('ghFeedbackMsg');
      feedback.textContent = 'Authenticating with GitHub in browser...';
      try {
        const res = await window.guardAPI.loginGitHubBrowser();
        if (res.success) {
          feedback.textContent = '✓ Successfully connected @' + (res.user.login || 'GitHub');
          await checkGitHubAuth();
          await loadSavedAccountsInSettings();
          await renderAccountsView();
        } else {
          feedback.textContent = 'OAuth Error: ' + res.error;
        }
      } catch (err) {
        feedback.textContent = 'OAuth Failed: ' + err.message;
      }
      setTimeout(() => feedback.textContent = '', 5000);
    });
  }

const btnResyncCli = document.getElementById('btnResyncGhCli');
  if (btnResyncCli) {
    btnResyncCli.addEventListener('click', async () => {
      const tokInput = document.getElementById('cfgGhToken');
      if (tokInput) tokInput.value = '';
      await window.guardAPI.reconnectGitHubCli();
      await checkGitHubAuth();
      await loadSavedAccountsInSettings();
      await renderAccountsView();
    });
  }

  // Load More Repos button
  const btnLoadMore = document.getElementById('btnLoadMoreRepos');
  if (btnLoadMore) {
    btnLoadMore.addEventListener('click', loadMoreGitHubRepos);
  }

  // Sync GitHub Repos button (details section) - Syncs changes with live server
  const btnSync = document.getElementById('btnSyncCloudData');
  if (btnSync) {
    btnSync.addEventListener('click', async (e) => {
      const forceFull = Boolean(e.shiftKey);
      await syncReposWithLiveServer({ silent: false, forceFull });
    });
  }

  // Scan Local Files button
  const btnLocalScan = document.getElementById('btnTriggerLocalScan');
  if (btnLocalScan) {
    btnLocalScan.addEventListener('click', () => {
      startScanPipeline({ githubRepos: [], localPaths: Array.from(appState.selectedLocalPaths), scanLocalPc: true });
    });
  }

  // GitHub Account Manager (Settings card)
  const btnAddGhAccount = document.getElementById('btnAddGhAccount');
  if (btnAddGhAccount) {
    btnAddGhAccount.addEventListener('click', async () => {
      const fb = document.getElementById('ghFeedbackMsg');
      const token = document.getElementById('cfgGhToken').value.trim();
      if (!token) { fb.textContent = 'Please enter a token.'; return; }
      fb.textContent = 'Validating...';
      const res = await window.guardAPI.addGitHubAccount(token);
      if (res.success) {
        fb.textContent = `✓ Connected as @${res.user.login}`;
        document.getElementById('cfgGhToken').value = '';
        await checkGitHubAuth();
        await loadSavedAccountsInSettings();
        await renderAccountsView();
      } else {
        fb.textContent = 'Error: ' + res.error;
      }
      setTimeout(() => fb.textContent = '', 4000);
    });
  }

  // Toggle PAT visibility in settings card
  const btnToggleGhVis = document.getElementById('btnToggleGhVis');
  if (btnToggleGhVis) {
    btnToggleGhVis.addEventListener('click', () => {
      const inp = document.getElementById('cfgGhToken');
      if (inp.type === 'password') { inp.type = 'text'; btnToggleGhVis.textContent = 'Hide'; }
      else { inp.type = 'password'; btnToggleGhVis.textContent = 'Show'; }
    });
  }

  // Disconnect All Accounts
  const btnDisconnectAll = document.getElementById('btnDisconnectAll');
  if (btnDisconnectAll) {
    btnDisconnectAll.addEventListener('click', async () => {
      if (!confirm('Disconnect all GitHub accounts? This removes all stored tokens and clears the app session.')) return;
      await window.guardAPI.disconnectGitHub();
      clearAppSession();
      await checkGitHubAuth();
      await loadSavedAccountsInSettings();
      await renderAccountsView();
    });
  }

  // Account Tab: Refresh
  const btnRefresh = document.getElementById('btnRefreshAccounts');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', async () => {
      await checkGitHubAuth();
      await loadSavedAccountsInSettings();
      await renderAccountsView();
    });
  }

  // Account Tab: Open Add Account & start Browser OAuth
  const btnOpenAdd = document.getElementById('btnOpenAddAccountModal');
  if (btnOpenAdd) {
    btnOpenAdd.addEventListener('click', () => {
      startBrowserOAuthFlow();
    });
  }

  // Account Tab: Toggle add-account token vis
  const btnToggleAddTokVis = document.getElementById('btnToggleAddTokenVis');
  if (btnToggleAddTokVis) {
    btnToggleAddTokVis.addEventListener('click', () => {
      const inp = document.getElementById('addAccountTokenInput');
      if (inp.type === 'password') { inp.type = 'text'; btnToggleAddTokVis.textContent = 'Hide'; }
      else { inp.type = 'password'; btnToggleAddTokVis.textContent = 'Show'; }
    });
  }

  // Account Tab: Confirm Add Account
  const btnConfirmAdd = document.getElementById('btnConfirmAddAccount');
  if (btnConfirmAdd) {
    btnConfirmAdd.addEventListener('click', async () => {
      const fb = document.getElementById('addAccountFeedback');
      const token = document.getElementById('addAccountTokenInput').value.trim();
      if (!token) { fb.textContent = 'Please enter a token.'; return; }
      fb.textContent = 'Validating token...';
      btnConfirmAdd.disabled = true;
      const res = await window.guardAPI.addGitHubAccount(token);
      if (res.success) {
        fb.textContent = `✓ Connected @${res.user.login} successfully!`;
        document.getElementById('addAccountTokenInput').value = '';
        await checkGitHubAuth();
        await loadSavedAccountsInSettings();
        await renderAccountsView();
      } else {
        fb.textContent = 'Error: ' + res.error;
      }
      btnConfirmAdd.disabled = false;
      setTimeout(() => fb.textContent = '', 5000);
    });
  }

  // Account Tab: Active Account Disconnect
  const acctDisconnectBtn = document.getElementById('acctDisconnectBtn');
  if (acctDisconnectBtn) {
    acctDisconnectBtn.addEventListener('click', async () => {
      const targetLogin = appState.activeGitHubLogin || (appState.githubAuth && appState.githubAuth.user ? appState.githubAuth.user.login : null);
      const promptMsg = targetLogin ? `Disconnect @${targetLogin} from Security Guard?` : 'Disconnect active GitHub session?';
      if (!confirm(promptMsg)) return;

      try {
        if (targetLogin) {
          await window.guardAPI.removeGitHubAccount(targetLogin);
        }
        await window.guardAPI.disconnectGitHub();
      } catch (err) {
        console.error('Disconnect error:', err);
      }

      clearAppSession();
      await checkGitHubAuth();
      await loadSavedAccountsInSettings();
      await renderAccountsView();
    });
  }

  // Load initial accounts view when Account tab is navigated to
  document.querySelectorAll('.dock-item').forEach(item => {
    item.addEventListener('click', () => {
      if (item.getAttribute('data-tab') === 'view-account') {
        renderAccountsView();
      }
    });
  });
}

// Load and render saved accounts inside the Settings card
async function loadSavedAccountsInSettings() {
  const list = document.getElementById('savedAccountsList');
  if (!list) return;

  try {
    const res = await window.guardAPI.getGitHubAccounts();
    appState.savedAccounts = res.accounts || [];
    appState.activeGitHubLogin = res.activeLogin;

    if (appState.savedAccounts.length === 0) {
      list.innerHTML = '<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">No saved accounts yet.</div>';
      return;
    }

    list.innerHTML = appState.savedAccounts.map(acct => `
      <div class="saved-account-row ${acct.login === appState.activeGitHubLogin ? 'active-account' : ''}">
        <img src="${acct.avatar_url || ''}" alt="" style="width:32px;height:32px;border-radius:50%;object-fit:cover;flex-shrink:0;">
        <div style="flex:1; min-width:0;">
          <div style="font-size:13px; font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
            @${acct.login}
            ${acct.login === appState.activeGitHubLogin ? '<span style="font-size:10px; background:#e6f6ee; color:#1e7e51; padding:1px 6px; border-radius:4px; font-weight:700; margin-left:6px;">ACTIVE</span>' : ''}
          </div>
          <div style="font-size:11px; color:var(--text-muted);">${acct.public_repos || 0} public · ${acct.total_private_repos || 0} private</div>
        </div>
        ${acct.login !== appState.activeGitHubLogin ? `
          <button class="btn-micro btn-switch-account" data-token="${acct.token}" title="Switch to this account">Switch</button>
        ` : ''}
        <button class="btn-micro btn-danger-micro btn-remove-account" data-login="${acct.login}" title="Remove account">✕</button>
      </div>
    `).join('');

    // Wire switch buttons
    list.querySelectorAll('.btn-switch-account').forEach(btn => {
      btn.addEventListener('click', async () => {
        btn.textContent = 'Switching...';
        const res = await window.guardAPI.switchGitHubAccount(btn.dataset.token);
        if (res.success) {
          await checkGitHubAuth();
          await loadSavedAccountsInSettings();
          await renderAccountsView();
        }
      });
    });

    // Wire remove buttons
    list.querySelectorAll('.btn-remove-account').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm(`Remove @${btn.dataset.login}?`)) return;
        await window.guardAPI.removeGitHubAccount(btn.dataset.login);
        await checkGitHubAuth();
        await loadSavedAccountsInSettings();
        await renderAccountsView();
      });
    });
  } catch (e) {
    list.innerHTML = '<div style="font-size:12px; color:#d64739;">Failed to load accounts.</div>';
  }
}

// Render the full Account tab view
async function renderAccountsView() {
  // Update hero card with active account
  const heroAvatar = document.getElementById('acctHeroAvatarImg');
  const heroName = document.getElementById('acctHeroName');
  const heroHandle = document.getElementById('acctHeroHandle');
  const heroPub = document.getElementById('acctRepoPub');
  const heroPriv = document.getElementById('acctRepoPriv');
  const acctOpenProfile = document.getElementById('acctOpenProfile');

  const activeAcct = appState.savedAccounts.find(a => a.login === appState.activeGitHubLogin)
    || (appState.githubAuth.authenticated ? appState.githubAuth.user : null);

  if (activeAcct) {
    if (heroAvatar) heroAvatar.src = activeAcct.avatar_url || '';
    if (heroName) heroName.textContent = activeAcct.name || activeAcct.login;
    if (heroHandle) heroHandle.textContent = '@' + activeAcct.login;
    if (heroPub) heroPub.textContent = activeAcct.public_repos || 0;
    if (heroPriv) heroPriv.textContent = activeAcct.total_private_repos || 0;
    if (acctOpenProfile) acctOpenProfile.href = activeAcct.html_url || '#';
  } else {
    if (heroName) heroName.textContent = 'Not Connected';
    if (heroHandle) heroHandle.textContent = '@unknown';
    if (heroPub) heroPub.textContent = '0';
    if (heroPriv) heroPriv.textContent = '0';
  }

  // Render accounts grid
  const grid = document.getElementById('accountsGrid');
  if (!grid) return;

  await loadSavedAccountsInSettings();
  const accounts = appState.savedAccounts;

  if (accounts.length === 0) {
    grid.innerHTML = '<div class="empty-state-box"><p>No saved accounts yet. Add one using your GitHub Personal Access Token.</p></div>';
    return;
  }

  grid.innerHTML = accounts.map(acct => `
    <div class="account-card ${acct.login === appState.activeGitHubLogin ? 'account-card-active' : ''}">
      <div class="account-card-top">
        <img src="${acct.avatar_url || ''}" alt="" class="account-card-avatar">
        ${acct.login === appState.activeGitHubLogin ? '<div class="account-active-badge">Active</div>' : ''}
      </div>
      <div class="account-card-name">@${acct.login}</div>
      <div class="account-card-sub">${acct.name || acct.login}</div>
      <div class="account-card-stats">
        <span>${acct.public_repos || 0} public</span>
        <span>${acct.total_private_repos || 0} private</span>
      </div>
      <div class="account-card-actions">
        ${acct.login !== appState.activeGitHubLogin
          ? `<button class="btn-pill-primary btn-switch-acct-grid" data-token="${acct.token}" style="font-size:11px; padding:5px 14px;">Set Active</button>`
          : '<span style="font-size:11px; color:#1e7e51; font-weight:700;">✓ Currently Active</span>'
        }
        <button class="btn-danger-outline btn-remove-acct-grid" data-login="${acct.login}" style="font-size:11px; padding:5px 14px;">Remove</button>
      </div>
    </div>
  `).join('');

  // Wire grid buttons
  grid.querySelectorAll('.btn-switch-acct-grid').forEach(btn => {
    btn.addEventListener('click', async () => {
      btn.textContent = 'Switching...';
      await window.guardAPI.switchGitHubAccount(btn.dataset.token);
      await checkGitHubAuth();
      await renderAccountsView();
    });
  });

  grid.querySelectorAll('.btn-remove-acct-grid').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm(`Remove @${btn.dataset.login}?`)) return;
      await window.guardAPI.removeGitHubAccount(btn.dataset.login);
      await checkGitHubAuth();
      await renderAccountsView();
    });
  });
}

function renderAiMarkdown(markdown) {
  const container = document.getElementById('aiAnalysisContainer');
  let html = markdown
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*)\*/gim, '<em>$1</em>')
    .replace(/```([a-z]*)\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>')
    .replace(/`([^`]+)`/gim, '<code style="background:#f4f0e8; padding:2px 4px; border-radius:4px; font-family:var(--font-mono);">$1</code>')
    .replace(/\n$/gim, '<br />');

  container.innerHTML = html;
}


  // Handle tab navigation requests from notifications
  if (window.guardAPI && window.guardAPI.onNavigateToTab) {
    window.guardAPI.onNavigateToTab((tabName) => {
      const tabBtn = document.querySelector(`.dock-item[data-tab="${tabName}"]`);
      if (tabBtn) tabBtn.click();
    });
  }
