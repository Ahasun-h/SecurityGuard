const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guardAPI', {
  // Guard Binary & Continuous Background Shield
  checkGuardStatus: () => ipcRenderer.invoke('guard:check-status'),
  installGuard: () => ipcRenderer.invoke('guard:install'),
  getDaemonStatus: () => ipcRenderer.invoke('guard:get-daemon-status'),
  runHostTriage: () => ipcRenderer.invoke('guard:run-triage'),
  toggleDaemon: (action) => ipcRenderer.invoke('guard:toggle-daemon', action),
  bootstrapGuard: () => ipcRenderer.invoke('guard:bootstrap'),

  // GitHub Auth & Repos
  getGitHubAuthStatus: () => ipcRenderer.invoke('github:get-auth-status'),
  saveGitHubToken: (token) => ipcRenderer.invoke('github:save-token', token),
  fetchGitHubRepos: () => ipcRenderer.invoke('github:fetch-repos'),
  getCachedRepos: (login) => ipcRenderer.invoke('github:get-cached-repos', login),
  syncGitHubRepos: (options) => ipcRenderer.invoke('github:sync-repos', options),
  onReposSyncProgress: (callback) => {
    ipcRenderer.removeAllListeners('github:repos-sync-progress');
    ipcRenderer.on('github:repos-sync-progress', (_event, value) => callback(value));
  },
  fetchGitHubReposPage: (page, perPage) => ipcRenderer.invoke('github:fetch-repos-page', page, perPage),
  loginGitHubBrowser: () => ipcRenderer.invoke('github:login-browser'),
  cancelOAuthLogin: () => ipcRenderer.invoke('github:cancel-oauth-login'),
  onOAuthDeviceCode: (callback) => {
    ipcRenderer.removeAllListeners('github:oauth-device-code');
    ipcRenderer.on('github:oauth-device-code', (_event, value) => callback(value));
  },
  disconnectGitHub: () => ipcRenderer.invoke('github:disconnect'),
  reconnectGitHubCli: () => ipcRenderer.invoke('github:reconnect-cli'),
  getGitHubAccounts: () => ipcRenderer.invoke('github:get-accounts'),
  switchGitHubAccount: (token) => ipcRenderer.invoke('github:switch-account', token),
  addGitHubAccount: (token) => ipcRenderer.invoke('github:add-account', token),
  removeGitHubAccount: (login) => ipcRenderer.invoke('github:remove-account', login),
  removeAllCollaborators: () => ipcRenderer.invoke('github:remove-all-collaborators'),
  onReposProgress: (callback) => {
    ipcRenderer.removeAllListeners('github:repos-progress');
    ipcRenderer.on('github:repos-progress', (_event, value) => callback(value));
  },
  onCollabProgress: (callback) => {
    ipcRenderer.removeAllListeners('collab:progress');
    ipcRenderer.on('collab:progress', (_event, value) => callback(value));
  },

  // Repo Disinfection
  disinfectRepo: (repoFullName) => ipcRenderer.invoke('github:disinfect-repo', repoFullName),
  disinfectAllRepos: (repoList) => ipcRenderer.invoke('github:disinfect-all', repoList),
  auditCollaborators: (repoFullName) => ipcRenderer.invoke('github:audit-collaborators', repoFullName),

  // Local System Targets
  getLocalTargets: () => ipcRenderer.invoke('system:get-local-targets'),
  getAvailableDisks: () => ipcRenderer.invoke('system:get-available-disks'),
  selectDirectory: () => ipcRenderer.invoke('system:select-directory'),
  verifyAppSignature: (appName) => ipcRenderer.invoke('system:verify-app-signature', appName),
  verifyVsCodeCodesign: () => ipcRenderer.invoke('system:verify-vscode-codesign'),
  getLatestBackgroundScan: () => ipcRenderer.invoke('system:get-latest-background-scan'),
  runBackgroundPcScan: () => ipcRenderer.invoke('system:run-background-pc-scan'),
  onNavigateToTab: (callback) => {
    ipcRenderer.removeAllListeners('navigate-to-tab');
    ipcRenderer.on('navigate-to-tab', (_event, tab) => callback(tab));
  },
  onBackgroundPcScanFinished: (callback) => {
    ipcRenderer.removeAllListeners('system:background-pc-scan-finished');
    ipcRenderer.on('system:background-pc-scan-finished', (_event, report) => callback(report));
  },
  onRealtimeThreatAlert: (callback) => {
    ipcRenderer.removeAllListeners('guard:realtime-threat-alert');
    ipcRenderer.on('guard:realtime-threat-alert', (_event, alert) => callback(alert));
  },

  // Scanner Orchestration
  startScan: (options) => ipcRenderer.invoke('scanner:start-scan', options),
  cancelScan: () => ipcRenderer.invoke('scanner:cancel'),
  onScanProgress: (callback) => {
    ipcRenderer.removeAllListeners('scanner:progress');
    ipcRenderer.on('scanner:progress', (_event, value) => callback(value));
  },
  onScanLog: (callback) => {
    ipcRenderer.removeAllListeners('scanner:log');
    ipcRenderer.on('scanner:log', (_event, value) => callback(value));
  },

  // AI Security Intelligence
  generateAiAnalysis: (scanResults) => ipcRenderer.invoke('ai:generate-analysis', scanResults),
  getAiSettings: () => ipcRenderer.invoke('ai:get-settings'),
  saveAiSettings: (settings) => ipcRenderer.invoke('ai:save-settings', settings),

  // Export & Remediation
  exportReport: (options) => ipcRenderer.invoke('report:export', options),
  autoCleanThreat: (threat) => ipcRenderer.invoke('threat:auto-clean', threat),
  deleteThreat: (threat) => ipcRenderer.invoke('threat:delete', threat)
});
