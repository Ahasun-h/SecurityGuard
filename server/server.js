/**
 * Security Guard Server Edition - Headless Cyber Defense Daemon & Web Dashboard
 * 
 * Features:
 * - Real-time background server malware & webshell watcher
 * - Immediate email alert dispatching to server owner upon threat interception
 * - Executive Web View Dashboard accessible from any browser
 * - Full on-demand server file system & host persistence scans
 * - 1-Click threat deletion / neutralization directly from the web view
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, exec } = require('child_process');
const Mailer = require('./mailer');

const PORT = parseInt(process.env.PORT || '8888', 10);
const HOST = process.env.HOST || '0.0.0.0';

// Config directories
const CONFIG_DIR = path.join(os.homedir(), '.guard');
const CONFIG_FILE = path.join(CONFIG_DIR, 'server-config.json');
const ALERTS_LOG = path.join(CONFIG_DIR, 'alerts.jsonl');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Ensure config dir exists
if (!fs.existsSync(CONFIG_DIR)) {
  try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); } catch (_) {}
}

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
  watchPaths: ['/var/www', '/home', '/etc/cron.d', '/tmp', os.homedir()]
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
            id: 'alert_' + Math.random().toString(36).substring(2, 9),
            file: item.path || item.file || 'Unknown path',
            name: item.name || item.rule || 'Malware Payload / Dropper',
            severity: item.severity || 'CRITICAL',
            timestamp: item.timestamp || new Date().toISOString(),
            status: 'ACTIVE'
          });
        } catch (_) {}
      }
      // Limit to last 100
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

// Watch alerts.jsonl for real-time background detections
let alertsWatcher = null;
function startAlertsWatcher() {
  if (!fs.existsSync(ALERTS_LOG)) {
    try { fs.writeFileSync(ALERTS_LOG, '', 'utf8'); } catch (_) {}
  }

  let lastSize = 0;
  try { lastSize = fs.statSync(ALERTS_LOG).size; } catch (_) {}

  try {
    if (alertsWatcher) alertsWatcher.close();
    alertsWatcher = fs.watch(ALERTS_LOG, () => {
      try {
        const stat = fs.statSync(ALERTS_LOG);
        if (stat.size > lastSize) {
          const stream = fs.createReadStream(ALERTS_LOG, { start: lastSize, end: stat.size });
          lastSize = stat.size;
          let buffer = '';
          stream.on('data', chunk => buffer += chunk);
          stream.on('end', () => {
            const lines = buffer.trim().split('\n');
            for (const line of lines) {
              if (!line) continue;
              try {
                const parsed = JSON.parse(line);
                handleNewThreat(parsed);
              } catch (_) {}
            }
          });
        }
      } catch (_) {}
    });
    console.log('[WATCHER] Monitoring', ALERTS_LOG, 'for live server threat alerts.');
  } catch (e) {
    console.warn('[WATCHER] Alerts file watch error:', e.message);
  }
}

// Handle an intercepted threat: Log it, broadcast it, and EMAIL the server owner immediately!
async function handleNewThreat(threat) {
  const threatObj = {
    id: 'threat_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
    file: threat.path || threat.file || 'Unknown path',
    name: threat.name || threat.rule || threat.reason || 'Malicious Payload',
    severity: threat.severity || 'CRITICAL',
    timestamp: threat.timestamp || new Date().toISOString(),
    status: 'ACTIVE'
  };

  // Add to threats list
  threats.unshift(threatObj);
  console.log(`\n🚨 [THREAT INTERCEPTED] ${threatObj.severity}: ${threatObj.name} at ${threatObj.file}`);

  // Broadcast to Web Dashboard
  broadcastSSE('threat', threatObj);

  // Immediately dispatch alert email to server owner!
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

// Start continuous guard watch daemon if binary is present
let guardProcess = null;
function startGuardWatchDaemon() {
  exec('which guard', (err, stdout) => {
    if (err || !stdout.trim()) {
      console.log('[GUARD ENGINE] Native `guard` binary not found in PATH. Server will operate in Node watcher mode.');
      return;
    }
    const guardBin = stdout.trim();
    console.log(`[GUARD ENGINE] Launching continuous watcher: ${guardBin} watch...`);
    guardProcess = spawn(guardBin, ['watch'], { stdio: 'ignore', detached: true });
    guardProcess.unref();
  });
}

// Trigger server scan (full disk or specified paths)
function runServerScan(targetPath = '/') {
  if (scanInProgress) return { success: false, error: 'Scan already in progress' };

  scanInProgress = true;
  currentScanLog = `[${new Date().toLocaleTimeString()}] Starting server forensic audit on ${targetPath}...\n`;
  broadcastSSE('scan_start', { targetPath });

  const guardCmd = `guard scan "${targetPath}" 2>&1 || true`;
  exec('which guard', (err, stdout) => {
    let cmd = guardCmd;
    if (err || !stdout.trim()) {
      // Fallback simple node-based scanner if guard binary is not installed
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
      shieldStatus: guardProcess ? 'RUNNING' : 'ACTIVE',
      scanInProgress,
      activeThreatsCount: threats.filter(t => t.status === 'ACTIVE').length,
      totalIncidents: threats.length,
      ownerEmailConfigured: !!serverConfig.ownerEmail,
      ownerEmail: serverConfig.ownerEmail
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

  // 5. Neutralize Threat
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
          // Quarantine by renaming to .quarantined
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
        res.end(JSON.stringify({ success: true, message: 'Threat neutralized & isolated', threat }));
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

  // Security: prevent directory traversal
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
  🛡️  SECURITY GUARD SERVER EDITION
===========================================================
  🌐 Web View Dashboard : http://${getPrimaryIp()}:${PORT}
  💻 Localhost URL      : http://localhost:${PORT}
  📧 Owner Alert Email  : ${serverConfig.ownerEmail || '(Not configured - set in web view)'}
  🛡️ Background Shield  : Continuous Watch Active
===========================================================
`);

  startAlertsWatcher();
  startGuardWatchDaemon();
});
