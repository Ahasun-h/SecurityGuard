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
  activeGitHubLogin: null
};

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

      await loadGitHubRepos();
    } else {
      sideName.textContent = 'Sign in';
      sideAvatarImg.style.display = 'none';
      settUserTitle.textContent = 'Not Connected';
      settUserSub.textContent = 'Configure PAT or log in with GitHub CLI.';
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

    // Select all by default
    appState.selectedRepoIds = new Set(allRepos.map(r => r.id));
    updateSelectedCounts();

    renderDashboardPillCards();
    renderGitHubFullGrid();
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
    let filteredRepos = appState.repos.filter(r => {
      if (appState.activeFilter === 'private' && !r.is_private) return false;
      if (appState.activeFilter === 'public' && r.is_private) return false;
      if (appState.searchQuery) {
        const q = appState.searchQuery.toLowerCase();
        return r.full_name.toLowerCase().includes(q) || (r.language || '').toLowerCase().includes(q);
      }
      return true;
    });

    const themes = ['theme-coral', 'theme-periwinkle', 'theme-turquoise'];

    items = filteredRepos.slice(0, appState.displayCount).map((r, idx) => {
      const theme = r.is_private ? 'theme-coral' : (idx % 2 === 0 ? 'theme-periwinkle' : 'theme-turquoise');
      return {
        type: 'github',
        id: r.id,
        title: r.name,
        sub: r.description || `Branch: ${r.default_branch || 'main'} • Size: ${r.size || 0} KB`,
        badge: r.is_private ? 'Private Repo' : 'Public Repo',
        theme: theme,
        icon: r.is_private ? '🔒' : '🌐',
        raw: r
      };
    });
  }

  if (items.length === 0) {
    container.innerHTML = `
      <div class="empty-state-box" style="padding: 24px; text-align: center; color: var(--text-muted);">
        <p>No repositories or targets found matching this view.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="pill-card-row ${item.theme}" data-id="${item.id || ''}">
      <div class="pill-card-left">
        <div class="pill-circle-badge">
          ${item.icon}
        </div>
        <div class="pill-card-text">
          <strong>${item.title}</strong>
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

// 3. Local Target Management
async function loadLocalTargets() {
  try {
    const targets = await window.guardAPI.getLocalTargets();
    appState.localTargets = targets;
    appState.selectedLocalPaths = new Set(targets.filter(t => t.exists).map(t => t.path));
    document.getElementById('countLocal').textContent = targets.length;
    renderLocalTargetsTab();
  } catch (e) {
    console.error('Failed to load local targets:', e);
  }
}

function renderLocalTargetsTab() {
  const container = document.getElementById('localTargetsContainer');
  container.innerHTML = appState.localTargets.map(t => {
    const isChecked = appState.selectedLocalPaths.has(t.path);
    return `
      <div class="target-card-soft">
        <div style="display: flex; align-items: center; gap: 12px;">
          <input type="checkbox" class="cb-local-select" data-path="${t.path}" ${isChecked ? 'checked' : ''} style="accent-color: var(--accent-yellow); width: 16px; height: 16px;">
          <div>
            <strong style="font-size: 14px; color: var(--text-main);">${t.name}</strong>
            <p style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${t.path}</p>
          </div>
        </div>
        <div>
          <button class="btn-pill-secondary btn-target-scan" data-path="${t.path}">Scan</button>
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.cb-local-select').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const p = e.target.dataset.path;
      if (e.target.checked) appState.selectedLocalPaths.add(p);
      else appState.selectedLocalPaths.delete(p);
    });
  });

  container.querySelectorAll('.btn-target-scan').forEach(btn => {
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

// 5. Scan Pipeline Execution
async function startScanPipeline(options) {
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
  targetLabel.textContent = 'Bootstrapping Guard supply-chain pipeline...';
  modal.classList.add('active');

  window.guardAPI.onScanProgress(data => {
    bar.style.width = `${data.percent}%`;
    percentTxt.textContent = `${data.percent}%`;
    countTxt.textContent = `${data.current} / ${data.total} Targets`;
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
    const isAvEnabled = document.getElementById('chkFilterAv').checked;
    const isGitDeep = document.getElementById('chkFilterGit').checked;

    const payload = {
      githubRepos: options.githubRepos || [],
      localPaths: options.localPaths || Array.from(appState.selectedLocalPaths),
      scanLocalPc: options.scanLocalPc !== false,
      runAntivirus: isAvEnabled,
      deepGitScan: isGitDeep
    };

    const report = await window.guardAPI.startScan(payload);
    appState.lastScanReport = report;

    setTimeout(() => {
      modal.classList.remove('active');
      switchView('view-reports');
      populateReportTab(report);
    }, 1200);

  } catch (e) {
    alert('Scan error: ' + e.message);
    modal.classList.remove('active');
  }
}

// 6. Populate Threat Reports Tab
function populateReportTab(report) {
  if (!report) return;

  document.getElementById('statScannedCount').textContent = report.scannedCount || 0;
  document.getElementById('statThreatCount').textContent = report.threatsFound || 0;
  document.getElementById('statCleanCount').textContent = report.summary ? report.summary.clean : 0;
  document.getElementById('statWarningsCount').textContent = report.summary ? report.summary.warnings : 0;

  const allItems = [
    ...(report.reposScanned || []).map(r => ({
      title: r.full_name,
      type: r.is_private ? '🔒 Private' : '🌐 Public',
      status: r.status,
      findings: r.findings
    })),
    ...(report.localScanned || []).map(l => ({
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

  container.innerHTML = allItems.map((item, itemIdx) => `
    <div style="background:#ffffff; border:1px solid var(--border-light); border-radius:12px; padding:14px 16px; margin-bottom:10px; border-left: 4px solid ${item.status === 'infected' ? 'var(--accent-coral)' : 'var(--accent-green)'}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
        <div>
          <span style="font-size:10px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">${item.type}</span>
          <strong style="font-size:14px; color:var(--text-main); display:block; margin-top:2px;">${item.title}</strong>
        </div>
        <span style="font-size:11px; font-weight:800; padding:4px 10px; border-radius:var(--radius-pill); background:${item.status === 'infected' ? '#fdeae8' : '#e6f6ee'}; color:${item.status === 'infected' ? '#d64739' : '#1e7e51'};">
          ${item.status.toUpperCase()}
        </span>
      </div>
      ${item.findings && item.findings.length > 0 ? `
        <div style="display:flex; flex-direction:column; gap:8px; margin-top:10px;">
          ${item.findings.map(f => {
            const info = formatFinding(f);
            return `
              <div style="background:#f9f7f2; border:1px solid var(--border-light); border-radius:8px; padding:10px 12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span style="font-size:10px; font-weight:800; padding:2px 7px; border-radius:4px; background:${info.severity === 'CRITICAL' ? '#fdeae8' : '#fef6dc'}; color:${info.severity === 'CRITICAL' ? '#d64739' : '#a47d06'}; font-family:var(--font-mono);">
                    ${info.severity} // ${info.category}
                  </span>
                  <strong style="font-size:12px; color:var(--text-main);">${info.title}</strong>
                </div>
                <p style="font-size:11px; color:var(--text-muted); margin:6px 0;">${info.desc}</p>
                ${info.where ? `<div style="font-size:10px; color:var(--text-main); font-family:var(--font-mono); background:#ffffff; padding:4px 8px; border-radius:4px; border:1px solid var(--border-light); word-break:break-all;">📁 ${info.where}</div>` : ''}
                ${info.isActionable ? `
                  <div style="margin-top:8px;">
                    <button class="btn-clean-action" data-where="${info.where}" data-raw='${JSON.stringify(info.raw).replace(/'/g, "&apos;")}' style="background:var(--accent-yellow); color:var(--text-main); border:none; padding:4px 12px; border-radius:var(--radius-pill); font-size:11px; font-weight:700; cursor:pointer;">
                      ⚡ Auto-Clean Threat
                    </button>
                  </div>
                ` : ''}
              </div>
            `;
          }).join('')}
        </div>
      ` : ''}
    </div>
  `).join('');

  // Wire auto-clean buttons
  container.querySelectorAll('.btn-clean-action').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const raw = JSON.parse(btn.getAttribute('data-raw'));
      btn.textContent = 'Cleaning...';
      try {
        const res = await window.guardAPI.autoCleanThreat(raw);
        if (res.success) {
          btn.textContent = '✓ Neutralized';
          btn.style.background = '#e6f6ee';
          btn.style.color = '#1e7e51';
          alert(res.message);
        } else {
          btn.textContent = 'Fix manually';
          alert('Notice: ' + res.error);
        }
      } catch (err) {
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
  }

  return { title, desc, where, category, severity, isActionable, raw: typeof data === 'object' ? data : { where, desc } };
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
      appState.localTargets.push({ id: 'custom_' + Date.now(), name: chosen.split('/').pop() || chosen, path: chosen, exists: true });
      appState.selectedLocalPaths.add(chosen);
      document.getElementById('countLocal').textContent = appState.localTargets.length;
      renderDashboardPillCards();
      renderLocalTargetsTab();
    }
  });

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

  // Cancel Scan
  document.getElementById('btnCancelScan').addEventListener('click', async () => {
    await window.guardAPI.cancelScan();
  });

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

  document.getElementById('btnResyncGhCli').addEventListener('click', async () => {
    document.getElementById('cfgGhToken').value = '';
    await window.guardAPI.saveGitHubToken('');
    await checkGitHubAuth();
  });

  // Load More Repos button
  const btnLoadMore = document.getElementById('btnLoadMoreRepos');
  if (btnLoadMore) {
    btnLoadMore.addEventListener('click', loadMoreGitHubRepos);
  }

  // Sync GitHub Repos button (details section)
  const btnSync = document.getElementById('btnSyncCloudData');
  if (btnSync) {
    btnSync.addEventListener('click', async () => {
      btnSync.textContent = 'Syncing...';
      await loadGitHubRepos();
      btnSync.textContent = 'Sync GitHub Repos';
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
      if (!confirm('Disconnect all GitHub accounts? This removes all stored tokens.')) return;
      await window.guardAPI.disconnectGitHub();
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

  // Account Tab: Open Add Account box
  const btnOpenAdd = document.getElementById('btnOpenAddAccountModal');
  if (btnOpenAdd) {
    btnOpenAdd.addEventListener('click', () => {
      const box = document.getElementById('addAccountBox');
      if (box) box.scrollIntoView({ behavior: 'smooth' });
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
      if (!appState.activeGitHubLogin) return;
      if (!confirm(`Remove @${appState.activeGitHubLogin} from Security Guard?`)) return;
      await window.guardAPI.removeGitHubAccount(appState.activeGitHubLogin);
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
