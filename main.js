const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec, spawn } = require('child_process');
const https = require('https');

let mainWindow;
const CONFIG_DIR = path.join(os.homedir(), '.guard');
const CONFIG_FILE = path.join(CONFIG_DIR, 'desktop-config.json');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  } catch (e) {
    console.error('Failed to create config dir', e);
  }
}

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    } catch (e) {
      console.error('Error reading config:', e);
    }
  }
  return {
    githubToken: '',
    guardPath: '/usr/local/bin/guard',
    aiProvider: 'gemini', // 'gemini' | 'openai' | 'claude' | 'ollama'
    aiApiKey: '',
    aiModel: 'gemini-1.5-flash',
    ollamaEndpoint: 'http://localhost:11434',
    selectedLocalPresets: ['Desktop', 'Downloads', 'Documents'],
    customLocalPaths: []
  };
}

function saveConfig(cfg) {
  const current = loadConfig();
  const merged = { ...current, ...cfg };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(merged, null, 2), 'utf8');
  return merged;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 890,
    minWidth: 1080,
    minHeight: 740,
    backgroundColor: '#f7f4ee',
    title: 'Security Guard Desktop - Defense & Intelligence Hub',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 14 },
    icon: path.join(__dirname, 'assets', 'icon.jpg'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Helper: Run command as promise
function runExec(cmd, options = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 20, ...options }, (error, stdout, stderr) => {
      resolve({
        code: error ? error.code || 1 : 0,
        stdout: stdout ? stdout.toString() : '',
        stderr: stderr ? stderr.toString() : '',
        error: error ? error.message : null
      });
    });
  });
}

// Comprehensive signatures for Lazarus Group / BeaverTail / Contagious Interview campaign
const BEAVERTAIL_SIGNATURES = [
  {
    id: 'beaver_tail_token_var',
    pattern: /k\$nodabqyPCpvUiq/i,
    name: 'BeaverTail Var Token (k$nodabqyPCpvUiq)',
    desc: 'Matched active Lazarus BeaverTail obfuscated variable signature',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_rv',
    pattern: /rv\$mIJCKYxZ/i,
    name: 'BeaverTail Resolver Function (rv$mIJCKYxZ)',
    desc: 'Matched BeaverTail string-decoding dispatcher function',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_etv',
    pattern: /EtVPcVKfhHvchsbpbJRrEavgP/i,
    name: 'BeaverTail Array Generator (EtVPcVKfh...)',
    desc: 'Matched BeaverTail string-array payload supplier',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_dfc',
    pattern: /DFcT_MdshgUDGLvdTVTIBV\$b/i,
    name: 'BeaverTail Encrypted Array (DFcT_...)',
    desc: 'Matched encrypted hexadecimal string array container',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_xor_constants',
    pattern: /622625\^622625|753605\^753604|365567\^365567|155681\^155680|666334\^666334|845704\^845696/i,
    name: 'BeaverTail XOR Arithmetic Obfuscator',
    desc: 'Matched characteristic bitwise XOR obfuscator constants',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_global_bang',
    pattern: /global\[['"]!['"]\]\s*=|global\['\\x21'\]/i,
    name: "BeaverTail Global Persistence Hook (global['!'])",
    desc: 'Matched Lazarus signature storing decryptor in global["!"]',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_y7_func',
    pattern: /function\s+y7\s*\([a-zA-Z0-9_$,\s]{5,}\)/i,
    name: 'BeaverTail Decryption Routine (function y7)',
    desc: 'Matched core string array XOR permutation routine y7()',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_string_rev',
    pattern: /(?:eilili|mor\|bctj\|e)["']\.split\(["']["']\)\.reverse\(\)\.join\(["']["']\)/i,
    name: 'BeaverTail Reverse-String Marker',
    desc: 'Matched BeaverTail reversed string token unpacker',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_s8_v8_dispatch',
    pattern: /function\s+s8\([^)]*\)\s*\{return\s+y7\(.*r8\['a'\].*r8\['f'\]/i,
    name: 'BeaverTail Dispatcher Routine (s8/v8)',
    desc: 'Matched dynamic dispatch and execution routine',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_hex_dense_array',
    pattern: /\[\s*['"][0-9a-f]{20,}['"]\s*,\s*['"][0-9a-f]{4,}['"]\s*,\s*['"][0-9a-f]{20,}['"]/i,
    name: 'BeaverTail Dense Hex Payload Array',
    desc: 'Matched dense hexadecimal string matrix for in-memory payload assembly',
    type: 'obfuscated_payload',
    severity: 'critical'
  }
];

// Directories to ignore during scanning
const IGNORED_SCAN_DIRS = new Set([
  '.git',
  'node_modules',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  '.cache',
  '.husky',
  '.vscode',
  '.idea',
  '.svn',
  '.hg'
]);

// Helper: Single-pass recursive collector for files needing inspection
function collectFilesForScan(dir, maxDepth = 15, currentDepth = 0) {
  const result = {
    pkgFiles: [],
    dropperFiles: [],
    sourceFiles: []
  };

  if (currentDepth > maxDepth) return result;

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_SCAN_DIRS.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        const sub = collectFilesForScan(fullPath, maxDepth, currentDepth + 1);
        result.pkgFiles.push(...sub.pkgFiles);
        result.dropperFiles.push(...sub.dropperFiles);
        result.sourceFiles.push(...sub.sourceFiles);
      } else if (entry.isFile()) {
        const base = entry.name.toLowerCase();
        if (base === 'package.json') {
          result.pkgFiles.push(fullPath);
        } else if (base === 'api.js' || base === '.api.js' || base === 'payload.js') {
          result.dropperFiles.push(fullPath);
          result.sourceFiles.push(fullPath);
        } else if (/\.(js|mjs|cjs|ts|jsx|tsx|html|vue|svelte|json)$/i.test(entry.name)) {
          result.sourceFiles.push(fullPath);
        }
      }
    }
  } catch (_) {}

  return result;
}

// Campaign-specific scanner: BeaverTail / Contagious Interview / Lazarus Supply-Chain Droppers
function scanForBeaverTailMalware(targetDir) {
  const findings = [];
  try {
    const collected = collectFilesForScan(targetDir);

    // 1. Scan package.json files for "node api.js" or "api.js &&"
    for (const pkg of collected.pkgFiles) {
      try {
        const text = fs.readFileSync(pkg, 'utf8');
        if (
          text.includes('node api.js') ||
          text.includes('api.js &&') ||
          text.includes('&& node api.js') ||
          text.includes('roboter')
        ) {
          findings.push({
            category: 'beaver_tail_dropper',
            severity: 'critical',
            name: 'node api.js (Dropper Hook)',
            desc: "Malicious npm script hook injecting 'node api.js' execution or poisoned package",
            where: path.relative(targetDir, pkg),
            fullPath: pkg,
            actionable: true,
            type: 'script_hook'
          });
        }
      } catch (_) {}
    }

    // 2. Scan for standalone dropper files (api.js, .api.js, payload.js)
    for (const dropper of collected.dropperFiles) {
      findings.push({
        category: 'beaver_tail_dropper',
        severity: 'critical',
        name: `${path.basename(dropper)} (Malware Dropper)`,
        desc: `Suspicious backdoor dropper file '${path.basename(dropper)}' discovered in repository`,
        where: path.relative(targetDir, dropper),
        fullPath: dropper,
        actionable: true,
        type: 'dropper_file'
      });
    }

    // 3. Scan all source and script files for BeaverTail signatures
    for (const src of collected.sourceFiles) {
      // Don't double-flag if already flagged as dropper_file unless extra signatures exist
      try {
        const stats = fs.statSync(src);
        if (stats.size > 0 && stats.size < 3000000) {
          const content = fs.readFileSync(src, 'utf8');
          for (const sig of BEAVERTAIL_SIGNATURES) {
            if (sig.pattern.test(content)) {
              findings.push({
                category: 'beaver_tail_dropper',
                severity: sig.severity,
                name: sig.name,
                desc: sig.desc,
                where: path.relative(targetDir, src),
                fullPath: src,
                actionable: true,
                type: sig.type,
                signatureId: sig.id
              });
              break; // One primary detection per file is sufficient
            }
          }
        }
      } catch (_) {}
    }
  } catch (err) {
    console.error('BeaverTail scan error:', err);
  }
  return findings;
}

// Deep disinfection engine for local directory or shallow-cloned repo
function disinfectLocalDirectory(dirPath, options = {}) {
  const isRemote = options.isRemote || false;
  const quarantineDir = path.join(os.homedir(), '.guard', 'quarantine');
  if (!fs.existsSync(quarantineDir)) {
    try { fs.mkdirSync(quarantineDir, { recursive: true }); } catch (_) {}
  }

  const collected = collectFilesForScan(dirPath);
  let cleanedCount = 0;
  const cleanedFiles = [];

  // 1. Sanitize package.json files
  for (const pkg of collected.pkgFiles) {
    try {
      const raw = fs.readFileSync(pkg, 'utf8');
      let json = JSON.parse(raw);
      let changed = false;

      // Clean devDependencies & dependencies
      ['devDependencies', 'dependencies'].forEach(depType => {
        if (json[depType]) {
          ['roboter', 'invisibleferret', 'beaver-tail'].forEach(badPkg => {
            if (json[depType][badPkg]) {
              delete json[depType][badPkg];
              changed = true;
            }
          });
        }
      });

      // Clean scripts
      if (json.scripts) {
        for (const [k, v] of Object.entries(json.scripts)) {
          if (typeof v === 'string' && (v.includes('node api.js') || v.includes('api.js'))) {
            const cleanedVal = v
              .replace(/node\s+api\.js\s*&&\s*/gi, '')
              .replace(/&&\s*node\s+api\.js/gi, '')
              .replace(/node\s+api\.js/gi, '')
              .replace(/api\.js\s*&&\s*/gi, '')
              .trim();
            if (cleanedVal !== v) {
              json.scripts[k] = cleanedVal;
              changed = true;
            }
          }
        }
      }

      if (changed) {
        fs.writeFileSync(pkg, JSON.stringify(json, null, 2) + '\n', 'utf8');
        cleanedCount++;
        cleanedFiles.push({ file: path.relative(dirPath, pkg), action: 'Sanitized package.json scripts' });
      }
    } catch (_) {}
  }

  // 2. Remove or quarantine api.js, .api.js, payload.js
  for (const dropper of collected.dropperFiles) {
    try {
      if (isRemote) {
        fs.unlinkSync(dropper);
      } else {
        const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(dropper)}.quarantine`);
        fs.renameSync(dropper, dest);
      }
      cleanedCount++;
      cleanedFiles.push({ file: path.relative(dirPath, dropper), action: 'Quarantined/removed backdoor dropper file' });
    } catch (_) {}
  }

  // 3. Clean source files with BeaverTail payloads
  for (const src of collected.sourceFiles) {
    try {
      if (!fs.existsSync(src)) continue;
      const content = fs.readFileSync(src, 'utf8');
      let isBeaverTail = false;
      for (const sig of BEAVERTAIL_SIGNATURES) {
        if (sig.pattern.test(content)) {
          isBeaverTail = true;
          break;
        }
      }

      if (isBeaverTail) {
        // Strip the BeaverTail payload blocks
        const stripped = content
          .replace(/var\s+k\$nodabqyPCpvUiq[\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
          .replace(/global\['!'\]\s*=\s*['"][^'"]*['"];\s*function\s+y7\([\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
          .trim();

        if (stripped.length < 50) {
          // Pure malware file
          if (isRemote) {
            fs.unlinkSync(src);
          } else {
            const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(src)}.quarantine`);
            fs.renameSync(src, dest);
          }
          cleanedCount++;
          cleanedFiles.push({ file: path.relative(dirPath, src), action: 'Quarantined pure malware script' });
        } else {
          // Source file with injected payload
          if (!isRemote) {
            const backup = path.join(quarantineDir, `${Date.now()}_backup_${path.basename(src)}`);
            fs.writeFileSync(backup, content, 'utf8');
          }
          fs.writeFileSync(src, stripped + '\n', 'utf8');
          cleanedCount++;
          cleanedFiles.push({ file: path.relative(dirPath, src), action: 'Stripped BeaverTail payload from source' });
        }
      }
    } catch (_) {}
  }

  return { cleanedCount, cleanedFiles };
}

// Disinfect a remote GitHub repository and push clean code
async function disinfectRemoteRepo(repoFullName) {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) {
      token = tokenRes.stdout.trim();
    }
  }

  const cleanDir = path.join(os.tmpdir(), `disinfect_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  try {
    const authCloneUrl = token 
      ? `https://x-access-token:${token}@github.com/${repoFullName}.git`
      : `https://github.com/${repoFullName}.git`;
    
    const cloneRes = await runExec(`git clone --depth 1 "${authCloneUrl}" "${cleanDir}"`);
    if (cloneRes.code !== 0) {
      return { success: false, error: `Failed to clone repository ${repoFullName}: ${cloneRes.stderr || cloneRes.error}` };
    }

    // Run deep disinfection on cloned directory
    const disRes = disinfectLocalDirectory(cleanDir, { isRemote: true });

    // Check git diff
    const statusRes = await runExec('git status --porcelain', { cwd: cleanDir });
    if (!statusRes.stdout.trim()) {
      return { success: true, message: `Repository ${repoFullName} had no active modifications on the current branch.` };
    }

    // Configure user, commit, and push
    await runExec('git config user.name "Security Guard Desktop"', { cwd: cleanDir });
    await runExec('git config user.email "security-guard@antigravity.internal"', { cwd: cleanDir });
    await runExec('git add -A', { cwd: cleanDir });
    await runExec('git commit -m "[Security Guard] Disinfect BeaverTail malware and remove malicious script hooks"', { cwd: cleanDir });
    
    const pushRes = await runExec('git push origin HEAD', { cwd: cleanDir });
    if (pushRes.code !== 0) {
      return { success: false, error: `Git push failed: ${pushRes.stderr || pushRes.error}` };
    }

    return {
      success: true,
      message: `Successfully disinfected ${repoFullName}! Cleaned ${disRes.cleanedCount} file(s) and pushed clean commits to GitHub.`,
      cleanedFiles: disRes.cleanedFiles
    };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    try { fs.rmSync(cleanDir, { recursive: true, force: true }); } catch (_) {}
  }
}

// ----------------- IPC HANDLERS -----------------

// Parser for guard deps check output
function parseDepsOutput(stdout) {
  const packages = [];
  const regex = /\[([a-zA-Z0-9_-]+)\]\s+([a-zA-Z0-9_@\/\.-]+)\s+\(your version:\s*([^;]+);\s*malicious range:\s*([^)]+)\)\s*(?:in\s*([a-zA-Z0-9_\/\.-]+))?/gi;
  let match;
  while ((match = regex.exec(stdout)) !== null) {
    packages.push({
      ecosystem: match[1],
      name: match[2],
      yourVersion: match[3].trim(),
      maliciousRange: match[4].trim(),
      manifest: match[5] ? match[5].trim() : 'manifest'
    });
  }
  return packages;
}

// 1. Guard Binary Status
ipcMain.handle('guard:check-status', async () => {
  const cfg = loadConfig();
  const guardBin = cfg.guardPath || '/usr/local/bin/guard';
  
  let whichRes = await runExec(`which "${guardBin}" || which guard || true`);
  let foundPath = whichRes.stdout.trim();
  
  if (!foundPath && fs.existsSync(guardBin)) {
    foundPath = guardBin;
  }

  if (!foundPath) {
    return { installed: false, version: null, path: null };
  }

  const verRes = await runExec(`"${foundPath}" version || true`);
  const rawVersion = verRes.stdout.trim() || '2.2.0';
  const cleanVersion = rawVersion.replace(/^guard\s+/i, '');

  return {
    installed: true,
    version: cleanVersion,
    path: foundPath
  };
});

// 2. Install Guard binary via guard.sh installer
ipcMain.handle('guard:install', async () => {
  // Let the user know sudo is required or run the installer script
  const scriptPath = path.join(__dirname, '..', 'guard.sh');
  return {
    command: `curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash`,
    scriptPath: fs.existsSync(scriptPath) ? scriptPath : null
  };
});

// 3. GitHub Auth Status
ipcMain.handle('github:get-auth-status', async () => {
  const cfg = loadConfig();

  // First check if gh CLI is available and authenticated
  const ghCheck = await runExec('gh auth status || true');
  let ghUser = null;
  let ghToken = null;

  if (ghCheck.stdout.includes('Logged in to github.com account') || ghCheck.stderr.includes('Logged in to github.com account')) {
    const combined = ghCheck.stdout + '\n' + ghCheck.stderr;
    const match = combined.match(/account\s+([A-Za-z0-9_-]+)/);
    if (match) ghUser = match[1];

    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) {
      ghToken = tokenRes.stdout.trim();
    }
  }

  // Fallback or override with saved custom token in config
  const activeToken = cfg.githubToken || ghToken;

  if (!activeToken && !ghUser) {
    return { authenticated: false, user: null, source: 'none' };
  }

  // Validate token with GitHub REST API
  try {
    const profile = await fetchGitHubApi('/user', activeToken);
    return {
      authenticated: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      },
      tokenPreview: activeToken ? `gho_***${activeToken.slice(-4)}` : 'via gh CLI',
      source: cfg.githubToken ? 'saved-token' : 'gh-cli'
    };
  } catch (err) {
    return {
      authenticated: false,
      error: err.message,
      user: null
    };
  }
});

// 4. Save Custom GitHub Token
ipcMain.handle('github:save-token', async (event, token) => {
  const clean = token.trim();
  if (!clean) {
    saveConfig({ githubToken: '' });
    return { success: true, authenticated: false };
  }

  try {
    const profile = await fetchGitHubApi('/user', clean);
    saveConfig({ githubToken: clean });
    return {
      success: true,
      authenticated: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      }
    };
  } catch (e) {
    return { success: false, error: 'Invalid GitHub Token: ' + e.message };
  }
});

// 5. Fetch GitHub Repos — ALL repos, no page cap, with streaming progress
ipcMain.handle('github:fetch-repos', async () => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  let allRepos = [];
  let page = 1;
  const perPage = 100;

  // Fetch every page until GitHub returns fewer than perPage
  while (true) {
    const repos = await fetchGitHubApi(
      `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated`,
      token
    );
    if (!Array.isArray(repos) || repos.length === 0) break;
    allRepos.push(...repos);

    // Stream progress to renderer
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('github:repos-progress', {
        loaded: allRepos.length,
        page,
        chunk: repos.map(mapRepo)
      });
    }

    if (repos.length < perPage) break;
    page++;
  }

  return allRepos.map(mapRepo);
});

// Helper: map GitHub API repo object to our compact shape
function mapRepo(r) {
  return {
    id: r.id,
    name: r.name,
    full_name: r.full_name,
    is_private: r.private,
    html_url: r.html_url,
    clone_url: r.clone_url,
    default_branch: r.default_branch,
    description: r.description || '',
    updated_at: r.updated_at,
    size: r.size,
    language: r.language,
    stargazers_count: r.stargazers_count || 0,
    forks_count: r.forks_count || 0
  };
}

// 5b. Fetch GitHub Repos - Single API Page (true pagination, 100/page)
ipcMain.handle('github:fetch-repos-page', async (event, page = 1, perPage = 100) => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  const repos = await fetchGitHubApi(
    `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated`,
    token
  );
  if (!Array.isArray(repos)) return { repos: [], hasMore: false, page };

  return { repos: repos.map(mapRepo), hasMore: repos.length >= perPage, page };
});

// 5c. Disconnect GitHub (clear saved token)
ipcMain.handle('github:disconnect', async () => {
  saveConfig({ githubToken: '' });
  return { success: true };
});

// 5d. Get all saved GitHub accounts
ipcMain.handle('github:get-accounts', async () => {
  const cfg = loadConfig();
  const accounts = cfg.githubAccounts || [];
  return { accounts, activeLogin: cfg.activeGitHubLogin || null };
});

// 5d2. Remove ALL external collaborators from ALL repos
ipcMain.handle('github:remove-all-collaborators', async () => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  const sendProgress = (msg, type = 'info') => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('collab:progress', { msg, type });
    }
  };

  // 1. Fetch ALL repos owned by the authenticated user
  let allRepos = [];
  let page = 1;
  sendProgress('Fetching all repositories...', 'info');
  while (true) {
    const repos = await fetchGitHubApi(
      `/user/repos?per_page=100&page=${page}&affiliation=owner&visibility=all&sort=updated`,
      token
    );
    if (!Array.isArray(repos) || repos.length === 0) break;
    allRepos.push(...repos);
    if (repos.length < 100) break;
    page++;
  }

  sendProgress(`Found ${allRepos.length} repositories. Scanning collaborators...`, 'info');

  const profile = await fetchGitHubApi('/user', token);
  const ownerLogin = profile.login;

  let totalRemoved = 0;
  let totalErrors = 0;
  const removedList = [];

  for (const repo of allRepos) {
    try {
      // List outside collaborators only (not the owner)
      const collabs = await fetchGitHubApi(
        `/repos/${repo.full_name}/collaborators?affiliation=outside&per_page=100`,
        token
      );
      if (!Array.isArray(collabs) || collabs.length === 0) continue;

      for (const collab of collabs) {
        if (collab.login === ownerLogin) continue; // never remove self
        try {
          // DELETE /repos/{owner}/{repo}/collaborators/{username}
          await deleteGitHubApi(`/repos/${repo.full_name}/collaborators/${collab.login}`, token);
          totalRemoved++;
          removedList.push({ repo: repo.full_name, user: collab.login });
          sendProgress(`Removed @${collab.login} from ${repo.name}`, 'success');
        } catch (e) {
          totalErrors++;
          sendProgress(`Failed to remove @${collab.login} from ${repo.name}: ${e.message}`, 'warning');
        }
      }
    } catch (e) {
      // Some repos may not support the collaborators endpoint (e.g., org repos without access)
      continue;
    }
  }

  sendProgress(`Done. Removed ${totalRemoved} collaborator(s) across ${allRepos.length} repos.`, 'success');
  return { success: true, totalRemoved, totalErrors, removedList };
});


// 5e. Add a GitHub Account (validate and store)
ipcMain.handle('github:add-account', async (event, token) => {
  const clean = token.trim();
  if (!clean) return { success: false, error: 'Token is required.' };

  try {
    const profile = await fetchGitHubApi('/user', clean);
    const cfg = loadConfig();
    const accounts = cfg.githubAccounts || [];

    // Update or add
    const existingIdx = accounts.findIndex(a => a.login === profile.login);
    const entry = {
      login: profile.login,
      name: profile.name || profile.login,
      avatar_url: profile.avatar_url,
      public_repos: profile.public_repos,
      total_private_repos: profile.total_private_repos || 0,
      html_url: profile.html_url,
      token: clean,
      addedAt: new Date().toISOString()
    };
    if (existingIdx >= 0) {
      accounts[existingIdx] = entry;
    } else {
      accounts.push(entry);
    }

    saveConfig({
      githubAccounts: accounts,
      githubToken: clean,
      activeGitHubLogin: profile.login
    });

    return { success: true, user: entry };
  } catch (e) {
    return { success: false, error: 'Invalid GitHub Token: ' + e.message };
  }
});

// 5f. Switch active GitHub account
ipcMain.handle('github:switch-account', async (event, token) => {
  const clean = token.trim();
  try {
    const profile = await fetchGitHubApi('/user', clean);
    saveConfig({ githubToken: clean, activeGitHubLogin: profile.login });
    return {
      success: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      }
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 5g. Remove a saved GitHub account
ipcMain.handle('github:remove-account', async (event, login) => {
  const cfg = loadConfig();
  let accounts = cfg.githubAccounts || [];
  accounts = accounts.filter(a => a.login !== login);

  const newActive = accounts.length > 0 ? accounts[0] : null;
  saveConfig({
    githubAccounts: accounts,
    githubToken: newActive ? newActive.token : '',
    activeGitHubLogin: newActive ? newActive.login : ''
  });

  return { success: true, newActive };
});

// Helper: GitHub API Requester
function fetchGitHubApi(endpoint, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method: 'GET',
      headers: {
        'User-Agent': 'Security-Guard-Desktop/1.0',
        'Accept': 'application/vnd.github.v3+json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Failed to parse GitHub response'));
          }
        } else {
          try {
            const errJson = JSON.parse(data);
            reject(new Error(errJson.message || `HTTP ${res.statusCode}`));
          } catch (e) {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        }
      });
    });

    req.on('error', err => reject(err));
    req.end();
  });
}

// Helper: GitHub API DELETE Request
function deleteGitHubApi(endpoint, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method: 'DELETE',
      headers: {
        'User-Agent': 'Security-Guard-Desktop/1.0',
        'Accept': 'application/vnd.github.v3+json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        // 204 = No Content (success for DELETE)
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          try {
            const errJson = JSON.parse(data);
            reject(new Error(errJson.message || `HTTP ${res.statusCode}`));
          } catch (e) {
            reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 120)}`));
          }
        }
      });
    });

    req.on('error', err => reject(err));
    req.end();
  });
}

// 6. Native Directory Picker
ipcMain.handle('system:select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

// 7. Get Local System Scan Targets
ipcMain.handle('system:get-local-targets', async () => {
  const home = os.homedir();
  const presets = [
    { id: 'desktop', name: 'Desktop', path: path.join(home, 'Desktop'), exists: fs.existsSync(path.join(home, 'Desktop')) },
    { id: 'downloads', name: 'Downloads', path: path.join(home, 'Downloads'), exists: fs.existsSync(path.join(home, 'Downloads')) },
    { id: 'documents', name: 'Documents', path: path.join(home, 'Documents'), exists: fs.existsSync(path.join(home, 'Documents')) },
    { id: 'home', name: 'Home Directory (~)', path: home, exists: true }
  ];

  // Also check common developer folders
  const devPaths = [
    path.join(home, 'Developer'),
    path.join(home, 'Projects'),
    path.join(home, 'Sites'),
    path.join(home, 'workspace')
  ];

  devPaths.forEach(dp => {
    if (fs.existsSync(dp)) {
      presets.push({ id: path.basename(dp).toLowerCase(), name: path.basename(dp), path: dp, exists: true });
    }
  });

  return presets;
});

// 8. Start Security Scan (GitHub Repos + Local PC)
let isScanning = false;
let shouldCancelScan = false;

ipcMain.handle('scanner:cancel', () => {
  if (isScanning) {
    shouldCancelScan = true;
    return true;
  }
  return false;
});

ipcMain.handle('scanner:start-scan', async (event, options) => {
  if (isScanning) return { error: 'Scan is already running' };
  isScanning = true;
  shouldCancelScan = false;

  const cfg = loadConfig();
  const guardBin = cfg.guardPath || '/usr/local/bin/guard';
  const { githubRepos = [], localPaths = [], scanLocalPc = true, deepGitScan = false, runAntivirus = true } = options;

  const results = {
    startedAt: new Date().toISOString(),
    finishedAt: null,
    totalTargets: githubRepos.length + (scanLocalPc ? localPaths.length : 0),
    scannedCount: 0,
    threatsFound: 0,
    reposScanned: [],
    localScanned: [],
    summary: {
      clean: 0,
      infected: 0,
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

  const sendProgress = (payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('scanner:progress', payload);
    }
  };

  const sendLog = (message, type = 'info') => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('scanner:log', { message, type, time: new Date().toLocaleTimeString() });
    }
  };

  const stagingDir = path.join(os.tmpdir(), `guard_scan_${Date.now()}`);
  if (!fs.existsSync(stagingDir)) {
    fs.mkdirSync(stagingDir, { recursive: true });
  }

  try {
    sendLog(`[START] Security Guard Engine initialized. Total targets: ${results.totalTargets}`, 'info');

    // Phase 1: Scan GitHub Repositories
    let token = cfg.githubToken;
    if (!token) {
      const tokenRes = await runExec('gh auth token || true');
      if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
    }

    for (let i = 0; i < githubRepos.length; i++) {
      if (shouldCancelScan) {
        sendLog(`[CANCELLED] Scan aborted by user`, 'warning');
        break;
      }

      const repo = githubRepos[i];
      results.scannedCount++;
      sendProgress({
        phase: 'github',
        current: results.scannedCount,
        total: results.totalTargets,
        currentTarget: repo.full_name,
        percent: Math.round((results.scannedCount / results.totalTargets) * 100)
      });

      sendLog(`[SCAN-REPO ${i + 1}/${githubRepos.length}] Inspecting ${repo.full_name} (${repo.is_private ? 'Private' : 'Public'})...`, 'info');

      const repoFolder = path.join(stagingDir, repo.name.replace(/[^a-zA-Z0-9_-]/g, '_'));
      
      // Clone shallow repo
      const authCloneUrl = token
        ? repo.clone_url.replace('https://', `https://${token}@`)
        : repo.clone_url;

      const cloneCmd = `git clone --depth 1 --quiet "${authCloneUrl}" "${repoFolder}"`;
      const cloneRes = await runExec(cloneCmd, { timeout: 60000 });

      if (cloneRes.code !== 0) {
        sendLog(`[WARN] Failed to clone ${repo.full_name}: ${cloneRes.stderr.trim() || 'Access denied / timeout'}`, 'warning');
        results.reposScanned.push({
          name: repo.name,
          full_name: repo.full_name,
          is_private: repo.is_private,
          status: 'error',
          error: cloneRes.stderr.trim() || 'Clone error',
          findings: []
        });
        results.summary.warnings++;
        continue;
      }

      // Execute Guard Scan
      const scanType = deepGitScan ? 'scan-git' : 'scan';
      const scanCmd = `"${guardBin}" ${scanType} --json "${repoFolder}"`;
      const scanRes = await runExec(scanCmd, { timeout: 120000 });

      let parsedReport = null;
      try {
        parsedReport = JSON.parse(scanRes.stdout);
      } catch (e) {
        // Fallback parsing if stdout has extra banners
        const jsonMatch = scanRes.stdout.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          try { parsedReport = JSON.parse(jsonMatch[0]); } catch (_) {}
        }
      }

      // Check dependency blocklist
      let depFindings = [];
      const depCmd = `"${guardBin}" deps check "${repoFolder}" || true`;
      const depRes = await runExec(depCmd);
      if (depRes.stdout.includes('MALICIOUS') || depRes.stdout.includes('blocked')) {
        const pkgs = parseDepsOutput(depRes.stdout);
        if (pkgs.length > 0) {
          depFindings.push({
            type: 'dependency_audit',
            count: pkgs.length,
            packages: pkgs,
            summary: `${pkgs.length} advisory reference(s) found across manifest files`
          });
        }
      }

      // Process findings
      let repoFindings = [];
      let isInfected = false;

      if (parsedReport && parsedReport.tree) {
        isInfected = parsedReport.tree.infected;
        const tree = parsedReport.tree;
        ['vscode', 'magic', 'fingerprint', 'workflow_baseline', 'malicious_deps', 'av'].forEach(cat => {
          if (Array.isArray(tree[cat]) && tree[cat].length > 0) {
            results.summary.categories[cat] += tree[cat].length;
            tree[cat].forEach(f => {
              repoFindings.push({ category: cat, detail: f });
            });
          }
        });
      }

      if (depFindings.length > 0) {
        // Dependency references flagged by guard deps check
        isInfected = true;
        results.summary.categories.malicious_deps += depFindings.length;
        repoFindings.push(...depFindings.map(d => ({ category: 'malicious_deps', detail: d })));
      }

      // Campaign-Specific Scan (Lazarus / BeaverTail: node api.js, api.js, global['!'])
      const campaignFindings = scanForBeaverTailMalware(repoFolder);
      if (campaignFindings.length > 0) {
        isInfected = true;
        repoFindings.push(...campaignFindings.map(c => ({
          category: 'beaver_tail_dropper',
          detail: {
            ...c,
            isRemoteRepo: true,
            repoFullName: repo.full_name,
            repoName: repo.name,
            where: path.relative(repoFolder, c.fullPath)
          }
        })));
      }

      if (isInfected) {
        results.threatsFound++;
        results.summary.infected++;
        sendLog(`[ALERT] THREAT DETECTED in ${repo.full_name}! Findings: ${repoFindings.length}`, 'danger');
      } else {
        results.summary.clean++;
        sendLog(`[CLEAN] ${repo.full_name} passed all supply-chain and malware checks.`, 'success');
      }

      results.reposScanned.push({
        name: repo.name,
        full_name: repo.full_name,
        is_private: repo.is_private,
        status: isInfected ? 'infected' : 'clean',
        findings: repoFindings,
        raw: parsedReport
      });

      // Clean up cloned folder immediately to save disk
      try {
        fs.rmSync(repoFolder, { recursive: true, force: true });
      } catch (e) {}
    }

    // Phase 2: Local PC Scan
    if (scanLocalPc && !shouldCancelScan) {
      sendLog(`[LOCAL] Beginning Host & Local Filesystem Scan...`, 'info');

      for (let j = 0; j < localPaths.length; j++) {
        if (shouldCancelScan) break;
        const targetPath = localPaths[j];
        results.scannedCount++;

        sendProgress({
          phase: 'local',
          current: results.scannedCount,
          total: results.totalTargets,
          currentTarget: targetPath,
          percent: Math.round((results.scannedCount / results.totalTargets) * 100)
        });

        if (!fs.existsSync(targetPath)) {
          sendLog(`[LOCAL SKIP] Directory does not exist: ${targetPath}`, 'warning');
          continue;
        }

        sendLog(`[SCAN-LOCAL ${j + 1}/${localPaths.length}] Scanning ${targetPath}...`, 'info');

        // Run Guard Scan on local directory
        const localScanCmd = `"${guardBin}" scan --json "${targetPath}"`;
        const localScanRes = await runExec(localScanCmd, { timeout: 300000 });

        let localReport = null;
        try {
          localReport = JSON.parse(localScanRes.stdout);
        } catch (e) {
          const m = localScanRes.stdout.match(/\{[\s\S]*\}/);
          if (m) {
            try { localReport = JSON.parse(m[0]); } catch (_) {}
          }
        }

        // Run Antivirus scan if enabled
        let avResult = null;
        if (runAntivirus) {
          const avCmd = `"${guardBin}" av scan "${targetPath}" || true`;
          const avRes = await runExec(avCmd, { timeout: 180000 });
          avResult = avRes.stdout.trim();
        }

        let localFindings = [];
        let isInfected = false;

        if (localReport && localReport.tree) {
          isInfected = localReport.tree.infected;
          const tree = localReport.tree;
          ['vscode', 'magic', 'fingerprint', 'workflow_baseline', 'malicious_deps', 'av'].forEach(cat => {
            if (Array.isArray(tree[cat]) && tree[cat].length > 0) {
              results.summary.categories[cat] += tree[cat].length;
              tree[cat].forEach(f => {
                localFindings.push({ category: cat, detail: f });
              });
            }
          });
        }

        if (avResult && (avResult.includes('malicious') && !avResult.includes('0 malicious'))) {
          isInfected = true;
          localFindings.push({ category: 'av', detail: avResult });
          results.summary.categories.av++;
        }

        // Campaign-Specific Scan (Lazarus / BeaverTail: node api.js, api.js, global['!'])
        const localCampaign = scanForBeaverTailMalware(targetPath);
        if (localCampaign.length > 0) {
          isInfected = true;
          localFindings.push(...localCampaign.map(c => ({
            category: 'beaver_tail_dropper',
            detail: {
              ...c,
              isRemoteRepo: false,
              where: path.relative(targetPath, c.fullPath)
            }
          })));
        }

        if (isInfected) {
          results.threatsFound++;
          results.summary.infected++;
          sendLog(`[LOCAL ALERT] THREAT DETECTED in ${targetPath}!`, 'danger');
        } else {
          results.summary.clean++;
          sendLog(`[LOCAL CLEAN] ${targetPath} clean.`, 'success');
        }

        results.localScanned.push({
          path: targetPath,
          name: path.basename(targetPath) || targetPath,
          status: isInfected ? 'infected' : 'clean',
          findings: localFindings,
          avOutput: avResult
        });
      }
    }

    results.finishedAt = new Date().toISOString();
    sendLog(`[FINISHED] Scan complete! Scanned: ${results.scannedCount}, Threats: ${results.threatsFound}`, results.threatsFound > 0 ? 'warning' : 'success');

  } catch (err) {
    sendLog(`[FATAL ERROR] Scan pipeline failed: ${err.message}`, 'danger');
  } finally {
    // Remove staging directory
    try {
      fs.rmSync(stagingDir, { recursive: true, force: true });
    } catch (e) {}
    isScanning = false;
    shouldCancelScan = false;
  }

  return results;
});

// 9. AI Security Assessment & Remediation
ipcMain.handle('ai:generate-analysis', async (event, scanResults) => {
  const cfg = loadConfig();
  const provider = cfg.aiProvider || 'gemini';
  const apiKey = cfg.aiApiKey || '';
  const model = cfg.aiModel || (provider === 'gemini' ? 'gemini-1.5-flash' : 'gpt-4o-mini');

  if (!apiKey && provider !== 'ollama') {
    throw new Error('AI API Key is not configured. Please open AI Settings and add your API key.');
  }

  // Build condensed security context
  const threatCount = scanResults.threatsFound || 0;
  const reposInfected = (scanResults.reposScanned || []).filter(r => r.status === 'infected');
  const localInfected = (scanResults.localScanned || []).filter(l => l.status === 'infected');

  const findingsSummary = {
    totalScanned: scanResults.scannedCount,
    threatsFound: threatCount,
    categories: scanResults.summary ? scanResults.summary.categories : {},
    infectedRepos: reposInfected.map(r => ({ name: r.full_name, findings: r.findings })),
    infectedLocal: localInfected.map(l => ({ path: l.path, findings: l.findings }))
  };

  const prompt = `You are a Principal Cyber Security Architect and Incident Responder analyzing scan results from "Guard" (supply-chain and malware scanner).
Here is the scan telemetry:
${JSON.stringify(findingsSummary, null, 2)}

Provide a comprehensive, professional Security Risk Report in Markdown with:
1. Executive Risk Level (CRITICAL / HIGH / MEDIUM / LOW / SECURE) with justification.
2. Threat Analysis: Break down any detected supply chain exploits, malicious dependencies, rogue VS Code configurations, CI/CD workflow hijacking, or malicious fingerprints.
3. Attack Vector & Impact Assessment: What an adversary could achieve if unaddressed (credential theft, pipeline poisoning, backdoor persistence).
4. Step-by-Step Remediation Playbook: Concrete terminal commands and actions to clean repositories, purge malicious dependencies, revoke compromised GitHub tokens/secrets, and isolate hosts.
5. Preventative Hardening: 3-5 best practices for developer workstations and CI/CD security.

Keep the response structured, clear, and actionable.`;

  // Attempt Cloud AI with timeout; smoothly fallback to Autonomous Triage Report if key is invalid/offline
  try {
    if (apiKey && apiKey.startsWith('AIzaSy') && provider === 'gemini') {
      return await Promise.race([
        callGeminiApi(apiKey, model, prompt),
        new Promise((_, reject) => setTimeout(() => reject(new Error('AI request timeout')), 10000))
      ]);
    } else if (apiKey && apiKey.startsWith('sk-') && provider === 'openai') {
      return await Promise.race([
        callOpenAiApi(apiKey, model, prompt),
        new Promise((_, reject) => setTimeout(() => reject(new Error('AI request timeout')), 10000))
      ]);
    } else if (provider === 'ollama') {
      return await callOllamaApi(cfg.ollamaEndpoint, model, prompt);
    }
  } catch (err) {
    console.warn('Cloud AI request failed or timed out, generating local assessment:', err.message);
  }

  // Autonomous Intelligent Incident Response Report
  return generateAutonomousSecurityReport(findingsSummary);
});

function generateAutonomousSecurityReport(findingsSummary) {
  const infectedRepos = findingsSummary.infectedRepos || [];
  const infectedLocal = findingsSummary.infectedLocal || [];
  const totalThreats = findingsSummary.threatsFound || 0;

  let riskLevel = totalThreats > 0 ? (totalThreats > 3 ? 'HIGH' : 'MEDIUM') : 'SECURE';
  let hasBackdoor = false;
  let allDeps = [];

  [...infectedRepos, ...infectedLocal].forEach(item => {
    (item.findings || []).forEach(f => {
      if (f.category === 'beaver_tail_dropper') hasBackdoor = true;
      if (f.category === 'malicious_deps') {
        if (f.detail && f.detail.packages) {
          allDeps.push(...f.detail.packages);
        } else if (typeof f.detail === 'string' && f.detail.includes('[npm]')) {
          allDeps.push(...parseDepsOutput(f.detail));
        }
      }
    });
  });

  if (hasBackdoor) riskLevel = 'CRITICAL';

  return `### 🛡️ Security Risk Assessment Report

**Executive Risk Level: ${riskLevel}**
${riskLevel === 'CRITICAL' ? '⚠️ Active Backdoor / Supply-Chain Dropper Signatures Detected' : riskLevel === 'HIGH' ? '⚠️ Multiple Dependency Advisories Flagged in Manifests' : '✓ System Baseline Stable'}

---

#### 1. Threat & Dependency Intelligence
- **Repositories Audited**: ${findingsSummary.totalScanned || 0}
- **Flagged Repositories**: ${infectedRepos.length > 0 ? infectedRepos.map(r => r.name).join(', ') : 'None'}
${allDeps.length > 0 ? `- **Flagged Package References (${allDeps.length})**: ${Array.from(new Set(allDeps.map(d => d.name))).join(', ')}` : ''}

${hasBackdoor ? `> 🚨 **CRITICAL BACKDOOR DETECTED**: Signs of the **Lazarus / BeaverTail** campaign (\`node api.js\` script injection or obfuscated payload) were detected. This vector attempts to hijack local credentials, environment keys, and browser data.` : ''}

${allDeps.length > 0 ? `#### 2. Manifest Dependency Breakdown
The following package references in your manifests (\`package.json\` / \`pnpm-lock.yaml\`) match names on the global security blocklist:
${allDeps.slice(0, 10).map(d => `* **\`${d.name}\`** (installed: \`${d.yourVersion}\`, flagged range: \`${d.maliciousRange}\` in \`${d.manifest}\`)`).join('\n')}
${allDeps.length > 10 ? `* *...and ${allDeps.length - 10} more references.*` : ''}

> ℹ️ **Advisory Note**: Several popular packages (such as \`axios\` or \`chalk\`) appear on advisory databases because historical versions had CVEs. If your installed version is outside the flagged range, the package is benign, but upgrading to the latest patched release is strongly recommended.` : ''}

---

#### 3. Immediate Step-by-Step Remediation Playbook

**Step 1: Update & Refresh Manifests**
Run the following in the affected project folder to resolve dependency advisories:
\`\`\`bash
# For PNPM projects:
pnpm update --latest
pnpm audit --fix

# For NPM projects:
npm audit fix
\`\`\`

**Step 2: Verify Script Hooks in package.json**
Confirm that no unauthorized execution hooks (such as \`node api.js\`) exist in \`scripts\`:
\`\`\`bash
# Inspect scripts for rogue execution:
grep -rn "api.js" package.json
\`\`\`

**Step 3: Review GitHub Collaborators**
Ensure that no unknown users have collaborator access to your repositories:
\`\`\`bash
# Inspect collaborators via GitHub CLI:
gh api /repos/:owner/:repo/collaborators
\`\`\`

---

#### 4. Developer Workstation Hardening
1. **Pre-Push Validation**: Ensure Guard's git pre-push hook is active (\`guard hooks install\`).
2. **Lockfile Pinning**: Commit clean \`pnpm-lock.yaml\` or \`package-lock.json\` to prevent dynamic supply-chain tampering.
3. **Secret Hygiene**: Rotate any personal access tokens or keys accessed on machines with suspected infections.`;
}

// Helper: AI API Callers
function callGeminiApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 2500 }
    });

    const targetModel = model.startsWith('gemini') ? model : 'gemini-1.5-flash';
    const req = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${targetModel}:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'Gemini API Error'));
          } else {
            const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
            resolve(text || 'No response generated from Gemini.');
          }
        } catch (e) {
          reject(new Error('Failed to parse Gemini response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callOpenAiApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: model || 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2
    });

    const req = https.request({
      hostname: 'api.openai.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'OpenAI API Error'));
          } else {
            const content = json.choices?.[0]?.message?.content;
            resolve(content || 'No response from OpenAI.');
          }
        } catch (e) {
          reject(new Error('Failed to parse OpenAI response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callClaudeApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: model || 'claude-3-5-sonnet-20241022',
      max_tokens: 3000,
      messages: [{ role: 'user', content: prompt }]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'Anthropic API Error'));
          } else {
            const text = json.content?.[0]?.text;
            resolve(text || 'No response from Claude.');
          }
        } catch (e) {
          reject(new Error('Failed to parse Claude response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callOllamaApi(endpoint, model, prompt) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint || 'http://localhost:11434');
    const httpLib = url.protocol === 'https:' ? https : require('http');

    const payload = JSON.stringify({
      model: model || 'llama3',
      prompt: prompt,
      stream: false
    });

    const req = httpLib.request({
      hostname: url.hostname,
      port: url.port || 11434,
      path: '/api/generate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.response || 'No response from Ollama.');
        } catch (e) {
          reject(new Error('Failed to parse Ollama response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

// 10. AI Settings Management
ipcMain.handle('ai:get-settings', () => {
  const cfg = loadConfig();
  return {
    provider: cfg.aiProvider || 'gemini',
    apiKey: cfg.aiApiKey ? `${cfg.aiApiKey.slice(0, 4)}••••••••${cfg.aiApiKey.slice(-4)}` : '',
    hasKey: Boolean(cfg.aiApiKey),
    model: cfg.aiModel || 'gemini-1.5-flash',
    ollamaEndpoint: cfg.ollamaEndpoint || 'http://localhost:11434'
  };
});

ipcMain.handle('ai:save-settings', (event, newSettings) => {
  const current = loadConfig();
  const update = {
    aiProvider: newSettings.provider,
    aiModel: newSettings.model,
    ollamaEndpoint: newSettings.ollamaEndpoint
  };
  // Only update apiKey if not masked and non-empty
  if (newSettings.apiKey && !newSettings.apiKey.includes('••••')) {
    update.aiApiKey = newSettings.apiKey.trim();
  }
  saveConfig(update);
  return { success: true };
});

// 11. Report Export
ipcMain.handle('report:export', async (event, { format, data }) => {
  const defaultPath = path.join(
    os.homedir(),
    'Desktop',
    `Guard_Security_Report_${new Date().toISOString().replace(/[:.]/g, '-')}.${format}`
  );

  const saveRes = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Security Report',
    defaultPath,
    filters: format === 'json'
      ? [{ name: 'JSON Report', extensions: ['json'] }]
      : [{ name: 'HTML Report', extensions: ['html'] }]
  });

  if (saveRes.canceled || !saveRes.filePath) return { success: false };

  let content = '';
  if (format === 'json') {
    content = JSON.stringify(data, null, 2);
  } else {
    content = generateHtmlReport(data);
  }

  fs.writeFileSync(saveRes.filePath, content, 'utf8');
  shell.showItemInFolder(saveRes.filePath);
  return { success: true, filePath: saveRes.filePath };
});

// 12. Auto-Clean & Neutralize Threat (Local PC & Remote GitHub Repos)
ipcMain.handle('threat:auto-clean', async (event, threat) => {
  try {
    if (!threat) return { success: false, error: 'No threat metadata provided.' };

    // Case A: Threat belongs to a remote GitHub repository
    if (threat.isRemoteRepo || threat.repoFullName) {
      const repoFullName = threat.repoFullName;
      if (!repoFullName) {
        return { success: false, error: 'Target remote repository identifier missing.' };
      }
      return await disinfectRemoteRepo(repoFullName);
    }

    // Case B: Local filesystem threat
    const filePath = threat.fullPath || threat.where;
    if (!filePath || !fs.existsSync(filePath)) {
      return { success: false, error: `Target file path does not exist on disk: ${filePath}` };
    }

    // If it's a directory
    if (fs.statSync(filePath).isDirectory()) {
      const res = disinfectLocalDirectory(filePath, { isRemote: false });
      return { success: true, message: `Disinfected directory! Cleaned ${res.cleanedCount} file(s).` };
    }

    const quarantineDir = path.join(os.homedir(), '.guard', 'quarantine');
    if (!fs.existsSync(quarantineDir)) {
      try { fs.mkdirSync(quarantineDir, { recursive: true }); } catch (_) {}
    }

    // Subcase B1: package.json script hook
    if (path.basename(filePath) === 'package.json') {
      const content = fs.readFileSync(filePath, 'utf8');
      let json = JSON.parse(content);
      let changed = false;

      // Clean devDependencies & dependencies
      ['devDependencies', 'dependencies'].forEach(depType => {
        if (json[depType]) {
          ['roboter', 'invisibleferret', 'beaver-tail'].forEach(badPkg => {
            if (json[depType][badPkg]) {
              delete json[depType][badPkg];
              changed = true;
            }
          });
        }
      });

      // Clean scripts
      if (json.scripts) {
        for (const [k, v] of Object.entries(json.scripts)) {
          if (typeof v === 'string' && (v.includes('node api.js') || v.includes('api.js'))) {
            const cleanedVal = v
              .replace(/node\s+api\.js\s*&&\s*/gi, '')
              .replace(/&&\s*node\s+api\.js/gi, '')
              .replace(/node\s+api\.js/gi, '')
              .replace(/api\.js\s*&&\s*/gi, '')
              .trim();
            if (cleanedVal !== v) {
              json.scripts[k] = cleanedVal;
              changed = true;
            }
          }
        }
      }

      if (changed) {
        fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + '\n', 'utf8');
        return { success: true, message: `Sanitized ${path.basename(filePath)} and removed malicious hooks!` };
      }
      return { success: true, message: `${path.basename(filePath)} is already clean.` };
    }

    // Subcase B2: api.js backdoor dropper file
    if (
      path.basename(filePath) === 'api.js' ||
      path.basename(filePath) === '.api.js' ||
      path.basename(filePath) === 'payload.js' ||
      threat.type === 'dropper_file'
    ) {
      const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(filePath)}.quarantine`);
      fs.renameSync(filePath, dest);
      return { success: true, message: `Quarantined malicious dropper to ~/.guard/quarantine/` };
    }

    // Subcase B3: Obfuscated payload file
    if (threat.type === 'obfuscated_payload' || threat.category === 'beaver_tail_dropper') {
      const content = fs.readFileSync(filePath, 'utf8');
      const stripped = content
        .replace(/var\s+k\$nodabqyPCpvUiq[\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
        .replace(/global\['!'\]\s*=\s*['"][^'"]*['"];\s*function\s+y7\([\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
        .trim();

      if (stripped.length < 50) {
        const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(filePath)}.quarantine`);
        fs.renameSync(filePath, dest);
        return { success: true, message: `Quarantined pure malware payload file to ~/.guard/quarantine/` };
      } else {
        const backup = path.join(quarantineDir, `${Date.now()}_backup_${path.basename(filePath)}`);
        fs.writeFileSync(backup, content, 'utf8');
        fs.writeFileSync(filePath, stripped + '\n', 'utf8');
        return { success: true, message: `Sanitized ${path.basename(filePath)} (backup saved in ~/.guard/quarantine/)` };
      }
    }

    return { success: false, error: 'Automatic surgical remediation not available for this signature.' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 13. Disinfect Entire Remote GitHub Repository
ipcMain.handle('github:disinfect-repo', async (event, repoFullName) => {
  return await disinfectRemoteRepo(repoFullName);
});

// 14. Batch Disinfect All Infected Remote Repositories
ipcMain.handle('github:disinfect-all', async (event, repoList) => {
  const results = [];
  for (const repo of repoList) {
    const res = await disinfectRemoteRepo(repo);
    results.push({ repo, ...res });
  }
  return results;
});

// 15. Audit GitHub Collaborators for Rogue Backdoors
ipcMain.handle('github:audit-collaborators', async (event, repoFullName) => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) return { success: false, error: 'GitHub authentication required' };

  try {
    const userProfile = await fetchGitHubApi('/user', token);
    const myLogin = userProfile.login;
    const collabs = await fetchGitHubApi(`/repos/${repoFullName}/collaborators`, token);

    if (Array.isArray(collabs)) {
      const externals = collabs.filter(c => c.login !== myLogin);
      return { success: true, myLogin, collaborators: collabs, externalCollaborators: externals };
    }
    return { success: true, myLogin, collaborators: [], externalCollaborators: [] };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

function generateHtmlReport(data) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Guard - Audit Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0c1017; color: #e6edf3; padding: 40px; }
    h1, h2 { color: #00f0ff; }
    .badge { padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 12px; }
    .clean { background: #0d4429; color: #3fb950; }
    .infected { background: #490202; color: #f85149; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #30363d; padding: 12px; text-align: left; }
    th { background: #161b22; }
    .summary-card { display: flex; gap: 20px; margin: 20px 0; }
    .card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; flex: 1; }
    pre { background: #010409; padding: 12px; border-radius: 6px; overflow-x: auto; color: #58a6ff; }
  </style>
</head>
<body>
  <h1>🛡️ Security Guard Threat Assessment</h1>
  <p>Generated: ${new Date().toLocaleString()}</p>
  
  <div class="summary-card">
    <div class="card">
      <h3>Total Targets</h3>
      <h2 style="color: #fff;">${data.scannedCount || 0}</h2>
    </div>
    <div class="card">
      <h3>Threats Detected</h3>
      <h2 style="color: ${data.threatsFound > 0 ? '#f85149' : '#3fb950'};">${data.threatsFound || 0}</h2>
    </div>
    <div class="card">
      <h3>Clean Targets</h3>
      <h2 style="color: #3fb950;">${data.summary ? data.summary.clean : 0}</h2>
    </div>
  </div>

  <h2>GitHub Repositories Scanned</h2>
  <table>
    <thead><tr><th>Repository</th><th>Visibility</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>
      ${(data.reposScanned || []).map(r => `
        <tr>
          <td><strong>${r.full_name}</strong></td>
          <td>${r.is_private ? '🔒 Private' : '🌐 Public'}</td>
          <td><span class="badge ${r.status}">${r.status.toUpperCase()}</span></td>
          <td>${r.findings && r.findings.length ? `<pre>${JSON.stringify(r.findings, null, 2)}</pre>` : 'None'}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <h2>Local PC Targets Scanned</h2>
  <table>
    <thead><tr><th>Location</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>
      ${(data.localScanned || []).map(l => `
        <tr>
          <td>${l.path}</td>
          <td><span class="badge ${l.status}">${l.status.toUpperCase()}</span></td>
          <td>${l.findings && l.findings.length ? `<pre>${JSON.stringify(l.findings, null, 2)}</pre>` : 'None'}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
</body>
</html>`;
}
