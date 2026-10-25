/**
 * Security Guard Server Edition - Headless Cyber Defense Daemon & Web Dashboard
 * 
 * Features:
 * - 24/7 Continuous File System Observer (Real-time malware & webshell interception)
 * - Immediate Email Alerts to Server Owner upon threat detection
 * - Executive Web View Dashboard with Live Telemetry & Threat Management
 * - Full Forensic Threat Reports (Exact matched code line, SHA-256, severity, timestamp)
 * - 1-Click Neutralization (Quarantine) and Permanent File Deletion
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const Mailer = require('./mailer');

const PORT = parseInt(process.env.PORT || '8888', 10);
const HOST = process.env.HOST || '0.0.0.0';

// Config directories
const CONFIG_DIR = path.join(os.homedir(), '.guard');
const CONFIG_FILE = path.join(CONFIG_DIR, 'server-config.json');
const ALERTS_LOG = path.join(CONFIG_DIR, 'alerts.jsonl');
const REPORTS_DIR = path.join(CONFIG_DIR, 'reports');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Ensure config and reports dirs exist
[CONFIG_DIR, REPORTS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  }
});

// Default configuration
const defaultConfig = {
  ownerEmail: process.env.OWNER_EMAIL || '',
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: process.env.SMTP_PORT || '465',
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  smtpFrom: process.env.SMTP_FROM || '',
  resendApiKey: process.env.RESEND_API_KEY || '',
  sendgridApiKey: process.env.SENDGRID_API_KEY || '',
  dashboardUrl: process.env.DASHBOARD_URL || `http://${os.hostname()}:${PORT}`,
  authToken: process.env.AUTH_TOKEN || '',
  watchPaths: ['/var/www', '/home', '/etc/cron.d', '/tmp', '/dev/shm']
};

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      return { ...defaultConfig, ...data };
    } catch (e) {
      console.error('[CONFIG] Error reading config file:', e);
    }
  }
  return { ...defaultConfig };
}

function saveConfig(cfg) {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('[CONFIG] Failed to save config:', e);
    return false;
  }
}

let serverConfig = loadConfig();
const mailer = new Mailer(serverConfig);

// In-memory threat incidents log
let threats = [];
let scanInProgress = false;
let currentScanLog = '';
let sseClients = [];
let recentDetectionsCache = new Map(); // file:timestamp to prevent spam duplicates

// Load existing alerts from alerts.jsonl if present
function loadExistingAlerts() {
  if (fs.existsSync(ALERTS_LOG)) {
    try {
      const lines = fs.readFileSync(ALERTS_LOG, 'utf8').trim().split('\n');
      for (const line of lines) {
        if (!line) continue;
        try {
          const item = JSON.parse(line);
          threats.unshift({
            id: item.id || ('alert_' + Math.random().toString(36).substring(2, 9)),
            file: item.path || item.file || 'Unknown path',
            name: item.name || item.rule || 'Malware Payload / Dropper',
            category: item.category || 'malware',
            severity: item.severity || 'CRITICAL',
            matchedSnippet: item.matchedSnippet || '',
            sha256: item.sha256 || '',
            timestamp: item.timestamp || new Date().toISOString(),
            status: item.status || 'ACTIVE'
          });
        } catch (_) {}
      }
      threats = threats.slice(0, 100);
    } catch (e) {
      console.error('[ALERTS] Failed reading existing alerts:', e);
    }
  }
}
loadExistingAlerts();

// Broadcast event to all active SSE web dashboards
function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => {
    try { client.write(payload); } catch (_) {}
  });
}

// Helper: Get primary IP address of this server
function getPrimaryIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

// Comprehensive Server Malware Signatures
const MALWARE_SIGNATURES = [
  // 1. PHP Webshells & Backdoors
  {
    id: 'php_eval_base64',
    name: 'Obfuscated PHP eval(base64_decode) Webshell',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /eval\s*\(\s*base64_decode\s*\(/i,
    desc: 'Malicious PHP backdoor payload dynamically evaluating base64 encoded code'
  },
  {
    id: 'php_eval_gzinflate',
    name: 'Obfuscated Compressed Webshell eval(gzinflate)',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /eval\s*\(\s*(?:gzinflate|gzuncompress|str_rot13)\s*\(/i,
    desc: 'Backdoor decoding and evaluating compressed PHP payload'
  },
  {
    id: 'php_cmd_exec_superglobals',
    name: 'PHP Arbitrary Command Execution Superglobal',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /(?:passthru|shell_exec|system|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/i,
    desc: 'Webshell executing arbitrary shell commands directly from unvalidated HTTP inputs'
  },
  {
    id: 'php_assert_eval',
    name: 'PHP assert() Code Injection Webshell',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/i,
    desc: 'PHP code injection backdoor using assert() function'
  },
  {
    id: 'known_webshell_markers',
    name: 'Known Webshell Framework Signature (c99/r57/WSO)',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /(?:c99shell|r57shell|WSO_VERSION|FilesMan|phpspy|b374k|alfa\s*team|wso\s*web\s*shell|b374k-shell)/i,
    desc: 'Identified signature of known public webshell framework (c99, r57, WSO, b374k)'
  },
  {
    id: 'polyglot_image_webshell',
    name: 'Polyglot Image-Embedded Webshell',
    category: 'webshell',
    severity: 'CRITICAL',
    pattern: /^(?:GIF89a|\xFF\xD8\xFF)[\s\S]*<\?php/i,
    desc: 'Stealth webshell disguised inside image header magic bytes (GIF/JPG polyglot)'
  },
  // 2. Reverse Shells & Interactive Backdoors
  {
    id: 'bash_dev_tcp_reverse_shell',
    name: 'Bash /dev/tcp Interactive Reverse Shell',
    category: 'reverse_shell',
    severity: 'CRITICAL',
    pattern: /\/bin\/(?:sh|bash)\s+-i\s+>&?\s+\/dev\/tcp\/\d+/i,
    desc: 'Interactive Bash socket redirection connecting out to remote command-and-control server'
  },
  {
    id: 'netcat_reverse_shell',
    name: 'Netcat Command-Execution Reverse Shell',
    category: 'reverse_shell',
    severity: 'CRITICAL',
    pattern: /(?:nc|netcat|ncat)\s+(?:-e|-c)\s+\/bin\/(?:sh|bash)/i,
    desc: 'Netcat utility spawned with shell execution flag (-e /bin/sh)'
  },
  {
    id: 'python_reverse_shell',
    name: 'Python Socket Interactive Reverse Shell',
    category: 'reverse_shell',
    severity: 'CRITICAL',
    pattern: /python(?:\d)?\s+-c\s+['"]import\s+socket,subprocess,os;s=socket\.socket/i,
    desc: 'Python in-memory reverse shell socket connecting to external attacker host'
  },
  {
    id: 'named_pipe_fifo_shell',
    name: 'FIFO Named-Pipe Reverse Shell',
    category: 'reverse_shell',
    severity: 'CRITICAL',
    pattern: /mkfifo\s+\/tmp\/\w+;\s*cat\s+\/tmp\/\w+\s*\|\s*\/bin\/(?:sh|bash)/i,
    desc: 'Persistence backdoor redirecting shell I/O through a Linux named pipe'
  },
  // 3. Crypto-Miners & Unauthorized Droppers
  {
    id: 'stratum_cryptominer',
    name: 'Stratum Mining Protocol Cryptominer Dropper',
    category: 'cryptominer',
    severity: 'CRITICAL',
    pattern: /stratum\+(?:tcp|ssl):\/\/[a-zA-Z0-9.-]+:\d+/i,
    desc: 'Mining pool connection string for Monero / XMRig cryptojacking attack'
  },
  {
    id: 'xmrig_binary_marker',
    name: 'XMRig Mining Tool Binary Marker',
    category: 'cryptominer',
    severity: 'CRITICAL',
    pattern: /(?:xmrig|minerd|xmr-stak|pool\.supportxmr\.com|mine\.moneropool\.com)/i,
    desc: 'Signatures of unauthorized background cryptocurrency mining software'
  },
  {
    id: 'cron_pipe_bash_dropper',
    name: 'Cron Job Remote Pipe-to-Bash Payload Dropper',
    category: 'dropper',
    severity: 'CRITICAL',
    pattern: /(?:curl\s+-[fsSLk]+\s+|wget\s+-[qO-]+\s+)[^|]+\|\s*(?:bash|sh)/i,
    desc: 'Malicious scheduled task pipe-to-shell remote payload downloader'
  },
  // 4. Supply Chain / Lazarus BeaverTail Droppers
  {
    id: 'beaver_tail_dropper',
    name: 'BeaverTail / Lazarus Supply-Chain Dropper Hook',
    category: 'supply_chain',
    severity: 'CRITICAL',
    pattern: /(?:node\s+api\.js|api\.js\s*&&|&&\s*node\s+api\.js|mor\|bctj\|e)/i,
    desc: 'Malicious package execution hook linked to Lazarus Group / BeaverTail infostealer'
  }
];

/**
 * Real-Time Continuous Server File System Observer
 * Monitors critical directories 24/7, analyzes modified files in milliseconds,
 * and intercepts malware threats the moment they touch the disk.
 */
class ServerMalwareObserver {
  constructor(options = {}) {
    this.watchPaths = options.watchPaths || [];
    this.watchers = new Map();
    this.observedFilesCount = 0;
    this.lastObservedFile = null;
    this.lastObservedTime = null;
    this.debounceTimers = new Map();
    this.status = 'INITIALIZING';
  }

  start() {
    const candidatePaths = [...this.watchPaths];

    // Auto-detect available server docroots and target directories
    ['/var/www', '/var/www/html', '/home', '/tmp', '/dev/shm', '/etc/cron.d'].forEach(p => {
      if (!candidatePaths.includes(p) && fs.existsSync(p)) {
        candidatePaths.push(p);
      }
    });

    // In case running on dev/macOS where /var/www doesn't exist, watch project & Downloads
    if (!candidatePaths.some(p => fs.existsSync(p))) {
      candidatePaths.push(path.join(os.homedir(), 'Downloads'));
      candidatePaths.push(process.cwd());
    }

    const activePaths = candidatePaths.filter(p => fs.existsSync(p));
    console.log(`[OBSERVER] Initializing 24/7 File System Watcher on ${activePaths.length} target locations:`);
    activePaths.forEach(p => console.log(`  👁️  ${p}`));

    activePaths.forEach(dir => this.attachWatcherRecursive(dir, 0, 4));
    this.status = 'ACTIVE';
  }

  attachWatcherRecursive(dirPath, depth = 0, maxDepth = 4) {
    if (depth > maxDepth || this.watchers.has(dirPath)) return;

    try {
      const watcher = fs.watch(dirPath, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(dirPath, filename);
        this.scheduleScan(fullPath);
      });

      watcher.on('error', (err) => {
        // Silently remove failed watchers
        this.watchers.delete(dirPath);
      });

      this.watchers.set(dirPath, watcher);

      // Enumerate immediate subdirectories
      try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            this.attachWatcherRecursive(path.join(dirPath, entry.name), depth + 1, maxDepth);
          }
        }
      } catch (_) {}
    } catch (e) {
      // Permission denied on system path
    }
  }

  scheduleScan(filePath) {
    if (this.debounceTimers.has(filePath)) {
      clearTimeout(this.debounceTimers.get(filePath));
    }

    const timer = setTimeout(() => {
      this.debounceTimers.delete(filePath);
      this.inspectFile(filePath);
    }, 120);

    this.debounceTimers.set(filePath, timer);
  }

  inspectFile(filePath) {
    try {
      if (!fs.existsSync(filePath)) return;
      const stat = fs.statSync(filePath);

      // If it's a directory, dynamically attach a watcher
      if (stat.isDirectory()) {
        this.attachWatcherRecursive(filePath);
        return;
      }

      // Skip large media, logs, or archives (> 4MB)
      if (stat.size > 4 * 1024 * 1024 || stat.size === 0) return;

      const ext = path.extname(filePath).toLowerCase();
      const base = path.basename(filePath).toLowerCase();

      // Skip common binary media unless polyglot image
      const ignoredExts = ['.mp4', '.avi', '.zip', '.tar', '.gz', '.iso', '.woff', '.ttf'];
      if (ignoredExts.includes(ext)) return;

      const t0 = Date.now();
      const buffer = fs.readFileSync(filePath);
      const content = buffer.toString('utf8');

      // Check against all malware rules
      for (const sig of MALWARE_SIGNATURES) {
        if (sig.pattern.test(content)) {
          // Check cache to avoid duplicate spam within 30 seconds
          const lastReported = recentDetectionsCache.get(filePath);
          if (lastReported && Date.now() - lastReported < 30000) {
            return;
          }
          recentDetectionsCache.set(filePath, Date.now());

          // Extract exact line snippet
          let matchedSnippet = '';
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (sig.pattern.test(lines[i])) {
              matchedSnippet = lines[i].trim().substring(0, 180);
              break;
            }
          }

          const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

          const threatObj = {
            id: 'threat_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
            name: sig.name,
            category: sig.category,
            severity: sig.severity,
            desc: sig.desc,
            file: filePath,
            ruleId: sig.id,
            matchedSnippet: matchedSnippet || 'Malicious payload pattern matched',
            sha256,
            fileSizeBytes: stat.size,
            timestamp: new Date().toISOString(),
            status: 'ACTIVE'
          };

          handleNewThreat(threatObj);
          return;
        }
      }

      // Clean observation
      this.observedFilesCount++;
      this.lastObservedFile = filePath;
      this.lastObservedTime = new Date().toISOString();
      const latencyMs = Date.now() - t0;

      // Broadcast pulse event to web dashboards
      broadcastSSE('observer_pulse', {
        file: filePath,
        latencyMs,
        totalObserved: this.observedFilesCount,
        timestamp: this.lastObservedTime
      });

    } catch (err) {
      // Non-fatal inspection error
    }
  }
}

const serverObserver = new ServerMalwareObserver({
  watchPaths: serverConfig.watchPaths
});

// Handle an intercepted threat: Log it, save report, broadcast it, and EMAIL the server owner immediately!
async function handleNewThreat(threat) {
  const threatObj = {
    id: threat.id || ('threat_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6)),
    file: threat.path || threat.file || 'Unknown path',
    name: threat.name || threat.rule || threat.reason || 'Malicious Payload',
    category: threat.category || 'webshell',
    severity: threat.severity || 'CRITICAL',
    desc: threat.desc || 'Suspicious unauthorized script or binary detected',
    matchedSnippet: threat.matchedSnippet || '',
    sha256: threat.sha256 || '',
    timestamp: threat.timestamp || new Date().toISOString(),
    status: 'ACTIVE'
  };

  // Prepend to in-memory list
  threats.unshift(threatObj);
  if (threats.length > 200) threats = threats.slice(0, 200);

  console.log(`\n🚨 [THREAT INTERCEPTED] ${threatObj.severity}: ${threatObj.name} at ${threatObj.file}`);

  // 1. Append to alerts.jsonl
  try {
    fs.appendFileSync(ALERTS_LOG, JSON.stringify(threatObj) + '\n', 'utf8');
  } catch (_) {}

  // 2. Save comprehensive incident report JSON
  try {
    const reportPath = path.join(REPORTS_DIR, `incident-${threatObj.id}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(threatObj, null, 2), 'utf8');
  } catch (_) {}

  // 3. Broadcast to all open Web Dashboards via SSE (Triggers instant browser siren & desktop notification)
  broadcastSSE('threat', threatObj);

  // 4. Immediately dispatch alert email to server owner!
  if (serverConfig.ownerEmail) {
    console.log(`📧 Dispatching immediate threat email to owner: ${serverConfig.ownerEmail}...`);
    try {
      const result = await mailer.sendThreatAlert({
        ...threatObj,
        hostname: os.hostname(),
        serverIp: getPrimaryIp()
      });
      if (result.success) {
        console.log(`✅ Alert email successfully delivered to ${serverConfig.ownerEmail}`);
      } else {
        console.warn(`⚠️ Failed to deliver alert email: ${result.error}`);
      }
    } catch (err) {
      console.error('[EMAIL ERROR]', err);
    }
  } else {
    console.warn('[MAILER] Server owner email not set. Configure via Web Dashboard to receive instant alerts.');
  }
}

// Start continuous guard watch daemon if binary is present
let guardProcess = null;
function startGuardWatchDaemon() {
  exec('which guard', (err, stdout) => {
    if (err || !stdout.trim()) {
      console.log('[GUARD ENGINE] Native CLI `guard` not in PATH. Server running built-in Node 24/7 Observer.');
      return;
    }
    const guardBin = stdout.trim();
    console.log(`[GUARD ENGINE] Launching auxiliary watcher: ${guardBin} watch...`);
    guardProcess = spawn(guardBin, ['watch'], { stdio: 'ignore', detached: true });
    guardProcess.unref();
  });
}

// Trigger on-demand server scan
function runServerScan(targetPath = '/') {
  if (scanInProgress) return { success: false, error: 'Scan already in progress' };

  scanInProgress = true;
  currentScanLog = `[${new Date().toLocaleTimeString()}] Starting server forensic audit on ${targetPath}...\n`;
  broadcastSSE('scan_start', { targetPath });

  const guardCmd = `guard scan "${targetPath}" 2>&1 || true`;
  exec('which guard', (err, stdout) => {
    let cmd = guardCmd;
    if (err || !stdout.trim()) {
      cmd = `find "${targetPath}" -type f \\( -name "*.php" -o -name "*.js" -o -name "*.sh" \\) -mtime -3 2>/dev/null | head -n 100`;
    }

    const proc = exec(cmd, { maxBuffer: 10 * 1024 * 1024 });

    proc.stdout.on('data', chunk => {
      currentScanLog += chunk;
      broadcastSSE('scan_log', { chunk });
    });

    proc.on('close', (code) => {
      scanInProgress = false;
      currentScanLog += `\n[${new Date().toLocaleTimeString()}] Audit complete (Exit code ${code}).\n`;
      broadcastSSE('scan_complete', { code, log: currentScanLog });
    });
  });

  return { success: true, message: 'Scan initiated' };
}

// HTTP Server & API Router
const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // Basic Token Authentication if configured
  if (serverConfig.authToken) {
    const authHeader = req.headers['authorization'];
    const queryToken = parsedUrl.searchParams.get('token');
    if (authHeader !== `Bearer ${serverConfig.authToken}` && queryToken !== serverConfig.authToken) {
      if (pathname.startsWith('/api/')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized: Invalid token' }));
      }
    }
  }

  // --- API ROUTES ---

  // 1. Live SSE Stream
  if (pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    res.write(`data: ${JSON.stringify({ type: 'connected', time: new Date() })}\n\n`);
    sseClients.push(res);
    req.on('close', () => {
      sseClients = sseClients.filter(c => c !== res);
    });
    return;
  }

  // Helper: Read JSON Body
  const readJsonBody = (cb) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const json = JSON.parse(body || '{}');
        cb(null, json);
      } catch (err) {
        cb(err);
      }
    });
  };

  // 2. Server Status & Metrics
  if (pathname === '/api/status' && req.method === 'GET') {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const loadAvg = os.loadavg();

    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    return res.end(JSON.stringify({
      hostname: os.hostname(),
      platform: `${os.type()} ${os.release()} (${os.arch()})`,
      serverIp: getPrimaryIp(),
      uptime: os.uptime(),
      cpuCount: os.cpus().length,
      loadAvg: [loadAvg[0].toFixed(2), loadAvg[1].toFixed(2), loadAvg[2].toFixed(2)],
      memory: {
        total: (totalMem / (1024 ** 3)).toFixed(2) + ' GB',
        used: (usedMem / (1024 ** 3)).toFixed(2) + ' GB',
        percent: Math.round((usedMem / totalMem) * 100)
      },
      shieldStatus: 'ACTIVE',
      scanInProgress,
      activeThreatsCount: threats.filter(t => t.status === 'ACTIVE').length,
      totalIncidents: threats.length,
      ownerEmailConfigured: !!serverConfig.ownerEmail,
      ownerEmail: serverConfig.ownerEmail,
      observer: {
        status: serverObserver.status,
        observedFilesCount: serverObserver.observedFilesCount,
        lastObservedFile: serverObserver.lastObservedFile,
        lastObservedTime: serverObserver.lastObservedTime,
        activeWatchersCount: serverObserver.watchers.size
      }
    }));
  }

  // 3. List Threats
  if (pathname === '/api/threats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    return res.end(JSON.stringify(threats));
  }

  // 4. Trigger Scan
  if (pathname === '/api/scan' && req.method === 'POST') {
    readJsonBody((err, data) => {
      const target = data && data.targetPath ? data.targetPath : '/var/www';
      const result = runServerScan(target);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(result));
    });
    return;
  }

  // 5. Neutralize Threat (Quarantine)
  if (pathname === '/api/neutralize' && req.method === 'POST') {
    readJsonBody((err, data) => {
      const threatId = data.threatId;
      const threat = threats.find(t => t.id === threatId);
      if (!threat) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Threat not found' }));
      }

      const filePath = threat.file;
      try {
        if (fs.existsSync(filePath)) {
          const quarantinedPath = filePath + '.quarantined_' + Date.now();
          fs.renameSync(filePath, quarantinedPath);
          threat.status = 'NEUTRALIZED';
          threat.neutralizedAt = new Date().toISOString();
          threat.quarantinedPath = quarantinedPath;
        } else {
          threat.status = 'NOT_FOUND_REMOVED';
        }
        broadcastSSE('threat_neutralized', threat);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Threat neutralized & isolated into quarantine', threat }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // 5b. Permanently Delete Threat File
  if (pathname === '/api/delete-threat' && req.method === 'POST') {
    readJsonBody((err, data) => {
      const threatId = data.threatId;
      const threat = threats.find(t => t.id === threatId);
      if (!threat) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Threat not found' }));
      }

      const filePath = threat.quarantinedPath || threat.file;
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
        threat.status = 'PERMANENTLY_DELETED';
        threat.deletedAt = new Date().toISOString();
        broadcastSSE('threat_deleted', threat);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Infected file permanently deleted', threat }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // 6. Update Settings
  if (pathname === '/api/settings' && req.method === 'POST') {
    readJsonBody((err, newSettings) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
      }
      serverConfig = { ...serverConfig, ...newSettings };
      saveConfig(serverConfig);
      mailer.updateConfig(serverConfig);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Settings updated successfully' }));
    });
    return;
  }

  // 7. Test Email Dispatch
  if (pathname === '/api/test-email' && req.method === 'POST') {
    readJsonBody(async (err, data) => {
      const target = (data && data.email) || serverConfig.ownerEmail;
      if (!target) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'No email address provided' }));
      }
      const result = await mailer.sendTestEmail(target);
      res.writeHead(result.success ? 200 : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    });
    return;
  }

  // --- STATIC FILES FOR WEB DASHBOARD ---
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Access Denied');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.png': 'image/png',
      '.svg': 'image/svg+xml',
      '.json': 'application/json'
    };

    const contentType = mimeTypes[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

// Start services
server.listen(PORT, HOST, () => {
  console.log(`
===========================================================
  🛡️  SECURITY GUARD SERVER EDITION (24/7 ACTIVE OBSERVER)
===========================================================
  🌐 Web View Dashboard : http://${getPrimaryIp()}:${PORT}
  💻 Localhost URL      : http://localhost:${PORT}
  📧 Owner Alert Email  : ${serverConfig.ownerEmail || '(Not configured - set in web view)'}
  👁️  Malware Observer  : Active & Watching Filesystem
===========================================================
`);

  serverObserver.start();
  startGuardWatchDaemon();
});
