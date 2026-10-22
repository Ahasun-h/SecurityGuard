const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guardAPI', {
  // Guard Binary
  checkGuardStatus: () => ipcRenderer.invoke('guard:check-status'),
  installGuard: () => ipcRenderer.invoke('guard:install'),

  // GitHub Auth & Repos
  getGitHubAuthStatus: () => ipcRenderer.invoke('github:get-auth-status'),
  saveGitHubToken: (token) => ipcRenderer.invoke('github:save-token', token),
  fetchGitHubRepos: () => ipcRenderer.invoke('github:fetch-repos'),
  fetchGitHubReposPage: (page, perPage) => ipcRenderer.invoke('github:fetch-repos-page', page, perPage),
  disconnectGitHub: () => ipcRenderer.invoke('github:disconnect'),
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
  selectDirectory: () => ipcRenderer.invoke('system:select-directory'),

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
  autoCleanThreat: (threat) => ipcRenderer.invoke('threat:auto-clean', threat)
});
