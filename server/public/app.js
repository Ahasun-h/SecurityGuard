// Security Guard Server Edition - Real-Time Cyber Defense & Web View Client

let threatsData = [];
let eventSource = null;
let soundEnabled = localStorage.getItem('sg_sound_enabled') !== 'false';
let currentForensicThreat = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  fetchStatus();
  fetchThreats();
  setupSSE();
  setupUIHandlers();
  updateSoundUI();

  // Poll host metrics every 10 seconds
  setInterval(fetchStatus, 10000);
});

// Synthesize an urgent warning siren using the browser's Web Audio API (Zero external MP3 files needed)
function playThreatAlarm() {
  if (!soundEnabled) return;
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.type = 'sawtooth';
    const now = ctx.currentTime;
    
    // Siren pitch modulation
    osc.frequency.setValueAtTime(880, now);
    osc.frequency.linearRampToValueAtTime(440, now + 0.25);
    osc.frequency.linearRampToValueAtTime(880, now + 0.5);
    osc.frequency.linearRampToValueAtTime(440, now + 0.75);

    gain.gain.setValueAtTime(0.25, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.85);

    osc.start(now);
    osc.stop(now + 0.85);
  } catch (e) {
    console.warn('Audio alarm playback not allowed yet without user interaction');
  }
}

// Fetch Server Status & Host Metrics
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    document.getElementById('hostBadge').textContent = `HOST: ${data.hostname.toUpperCase()}`;
    document.getElementById('infoPlatform').textContent = data.platform;
    document.getElementById('infoIp').textContent = data.serverIp;
    document.getElementById('infoCpus').textContent = `${data.cpuCount} Cores`;
    document.getElementById('infoUptime').textContent = formatUptime(data.uptime);

    // Active Threats Card
    const cardThreats = document.getElementById('cardThreats');
    const valThreats = document.getElementById('valThreats');
    const subThreats = document.getElementById('subThreats');

    valThreats.textContent = data.activeThreatsCount;
    if (data.activeThreatsCount > 0) {
      cardThreats.className = 'metric-card alert';
      subThreats.textContent = `${data.activeThreatsCount} active threat(s) need immediate action!`;
      subThreats.style.color = '#f87171';
    } else {
      cardThreats.className = 'metric-card clean';
      subThreats.textContent = 'Server filesystem clean';
      subThreats.style.color = 'var(--text-muted)';
    }

    // Memory & Load
    document.getElementById('valMemory').textContent = `${data.memory.used} / ${data.memory.total}`;
    document.getElementById('valLoad').textContent = `Load Avg: ${data.loadAvg.join(', ')}`;

    // Email Status
    const valEmailStatus = document.getElementById('valEmailStatus');
    const valEmailTarget = document.getElementById('valEmailTarget');
    if (data.ownerEmailConfigured) {
      valEmailStatus.textContent = 'ACTIVE';
      valEmailStatus.style.color = 'var(--accent-green)';
      valEmailTarget.textContent = data.ownerEmail;
    } else {
      valEmailStatus.textContent = 'SETUP NEEDED';
      valEmailStatus.style.color = 'var(--accent-amber)';
      valEmailTarget.textContent = 'Click to configure alert email';
    }

    // Observer Telemetry
    if (data.observer) {
      document.getElementById('lblObservedCount').textContent = data.observer.observedFilesCount.toLocaleString();
      if (data.observer.lastObservedFile) {
        document.getElementById('lblLiveTicker').textContent = `Inspected: ${data.observer.lastObservedFile}`;
      }
    }

    document.getElementById('valShield').textContent = data.shieldStatus;
  } catch (err) {
    console.error('Failed fetching status:', err);
  }
}

// Fetch Logged Threats & Incidents
async function fetchThreats() {
  try {
    const res = await fetch('/api/threats');
    threatsData = await res.json();
    renderThreatsTable();
    checkUrgentBanner();
  } catch (err) {
    console.error('Failed fetching threats:', err);
  }
}

// Check if floating banner should be displayed
function checkUrgentBanner() {
  const banner = document.getElementById('urgentBanner');
  const activeThreat = threatsData.find(t => t.status === 'ACTIVE');

  if (activeThreat) {
    document.getElementById('bannerTitle').textContent = `🚨 ${activeThreat.severity}: ${activeThreat.name.toUpperCase()}`;
    document.getElementById('bannerSubtitle').textContent = `Infected file: ${activeThreat.file}. Immediate email alert dispatched.`;
    banner.style.display = 'flex';

    document.getElementById('btnBannerDetails').onclick = () => openForensicReport(activeThreat.id);
    document.getElementById('btnBannerNeutralize').onclick = () => neutralizeThreat(activeThreat.id);
  } else {
    banner.style.display = 'none';
  }
}

// Render Threats Table
function renderThreatsTable() {
  const tbody = document.getElementById('threatsTbody');
  const countLabel = document.getElementById('incidentCountLabel');
  countLabel.textContent = `${threatsData.length} Incident(s) Logged`;

  if (!threatsData.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state">
          ✓ No active threats detected on this server. 24/7 observer is actively watching all file changes.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = threatsData.map(t => {
    const isNeutralized = t.status === 'NEUTRALIZED' || t.status === 'NOT_FOUND_REMOVED' || t.status === 'PERMANENTLY_DELETED';
    const badgeClass = isNeutralized ? 'badge-neutralized' : 'badge-critical';
    let statusText = '⚠️ ACTIVE THREAT';
    if (t.status === 'NEUTRALIZED') statusText = '✓ QUARANTINED';
    if (t.status === 'PERMANENTLY_DELETED') statusText = '🗑️ DELETED';

    return `
      <tr>
        <td><span class="badge ${badgeClass}">${t.severity || 'CRITICAL'}</span></td>
        <td><strong>${escapeHtml(t.name || 'Malware Payload')}</strong></td>
        <td><span class="path-code">${escapeHtml(t.file || '--')}</span></td>
        <td style="font-size:12px; color:var(--text-muted);">${formatDate(t.timestamp)}</td>
        <td><span class="badge ${badgeClass}">${statusText}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="openForensicReport('${t.id}')">
              🔬 Details
            </button>
            ${!isNeutralized ? `
              <button class="btn btn-danger btn-sm" onclick="neutralizeThreat('${t.id}')">
                ⚡ Quarantine
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// Open Threat Forensic Report Modal
function openForensicReport(threatId) {
  const threat = threatsData.find(t => t.id === threatId);
  if (!threat) return;

  currentForensicThreat = threat;
  document.getElementById('repName').textContent = threat.name;
  document.getElementById('repSeverity').textContent = threat.severity || 'CRITICAL';
  document.getElementById('repFile').textContent = threat.file;
  document.getElementById('repHash').textContent = threat.sha256 || 'SHA-256 Calculated on quarantine';
  document.getElementById('repTime').textContent = new Date(threat.timestamp).toLocaleString();
  document.getElementById('repStatus').textContent = threat.status;
  document.getElementById('repSnippet').textContent = threat.matchedSnippet || 'Pattern matched suspicious evaluation or obfuscation';

  const modal = document.getElementById('forensicModal');
  modal.classList.add('active');

  const btnNeutralize = document.getElementById('btnModalNeutralize');
  const btnDelete = document.getElementById('btnModalDelete');

  const isSecured = threat.status === 'NEUTRALIZED' || threat.status === 'PERMANENTLY_DELETED';
  btnNeutralize.disabled = isSecured;
  btnNeutralize.textContent = isSecured ? 'Secured' : '⚡ Neutralize (Quarantine)';
}

// 1-Click Neutralize Threat (Quarantine)
async function neutralizeThreat(threatId) {
  if (!confirm('Neutralize this threat? The infected file will be quarantined immediately.')) return;

  try {
    const res = await fetch('/api/neutralize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threatId })
    });
    const result = await res.json();

    if (result.success) {
      alert('✅ Threat successfully quarantined and isolated!');
      document.getElementById('forensicModal').classList.remove('active');
      fetchThreats();
      fetchStatus();
    } else {
      alert('Error: ' + (result.error || 'Failed to neutralize'));
    }
  } catch (err) {
    alert('Failed to connect to server: ' + err.message);
  }
}

// 1-Click Permanently Delete Infected File
async function deleteThreatFile(threatId) {
  if (!confirm('Permanently DELETE this infected file from the server? This cannot be undone.')) return;

  try {
    const res = await fetch('/api/delete-threat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threatId })
    });
    const result = await res.json();

    if (result.success) {
      alert('🗑️ Infected file permanently deleted from server!');
      document.getElementById('forensicModal').classList.remove('active');
      fetchThreats();
      fetchStatus();
    } else {
      alert('Error: ' + (result.error || 'Failed to delete file'));
    }
  } catch (err) {
    alert('Failed to delete file: ' + err.message);
  }
}

// Live Server-Sent Events (SSE) Stream
function setupSSE() {
  try {
    eventSource = new EventSource('/api/events');

    // 1. Live Threat Intercepted Event
    eventSource.addEventListener('threat', (e) => {
      const threat = JSON.parse(e.data);
      threatsData.unshift(threat);
      renderThreatsTable();
      fetchStatus();
      checkUrgentBanner();

      // Trigger Audible Alarm Siren
      playThreatAlarm();

      // Trigger OS Desktop Notification via Browser Notification API
      if ('Notification' in window && Notification.permission === 'granted') {
        const notif = new Notification(`🚨 CRITICAL THREAT: ${threat.name}`, {
          body: `File: ${threat.file}\nClick to view forensic report and neutralize.`,
          icon: '/assets/icon.png',
          requireInteraction: true
        });
        notif.onclick = () => {
          window.focus();
          openForensicReport(threat.id);
        };
      }
    });

    // 2. Continuous 24/7 File Observation Pulse
    eventSource.addEventListener('observer_pulse', (e) => {
      const data = JSON.parse(e.data);
      document.getElementById('lblObservedCount').textContent = data.totalObserved.toLocaleString();
      document.getElementById('lblLiveTicker').textContent = `Inspected: ${data.file} (${data.latencyMs}ms)`;
    });

    // 3. Scan events
    eventSource.addEventListener('scan_start', (e) => {
      const data = JSON.parse(e.data);
      const consoleCard = document.getElementById('scanConsoleCard');
      const terminal = document.getElementById('scanTerminal');
      consoleCard.style.display = 'block';
      terminal.textContent = `[${new Date().toLocaleTimeString()}] Initiated server scan on ${data.targetPath}...\n`;
      document.getElementById('scanStatusBadge').textContent = 'SCANNING IN PROGRESS...';
      document.getElementById('scanStatusBadge').className = 'badge badge-critical';
    });

    eventSource.addEventListener('scan_log', (e) => {
      const data = JSON.parse(e.data);
      const terminal = document.getElementById('scanTerminal');
      terminal.textContent += data.chunk;
      terminal.scrollTop = terminal.scrollHeight;
    });

    eventSource.addEventListener('scan_complete', (e) => {
      document.getElementById('scanStatusBadge').textContent = 'SCAN COMPLETE';
      document.getElementById('scanStatusBadge').className = 'badge badge-neutralized';
      fetchThreats();
      fetchStatus();
    });
  } catch (err) {
    console.warn('SSE connection failed:', err);
  }
}

// UI Event Handlers
function setupUIHandlers() {
  // Request Notification permission
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }

  // Sound Toggle Button
  document.getElementById('btnSoundToggle').addEventListener('click', () => {
    soundEnabled = !soundEnabled;
    localStorage.setItem('sg_sound_enabled', soundEnabled);
    updateSoundUI();
    if (soundEnabled) playThreatAlarm();
  });

  // Refresh Button
  document.getElementById('btnRefresh').addEventListener('click', () => {
    fetchStatus();
    fetchThreats();
  });

  // Scan Server Now Button
  document.getElementById('btnScanNow').addEventListener('click', async () => {
    const target = prompt('Enter directory path to scan:', '/var/www') || '/var/www';
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetPath: target })
      });
      const data = await res.json();
      if (!data.success) {
        alert(data.error || 'Failed to start scan');
      }
    } catch (e) {
      alert('Error triggering scan: ' + e.message);
    }
  });

  // Forensic Modal Close Buttons
  document.getElementById('btnCloseForensic').addEventListener('click', () => {
    document.getElementById('forensicModal').classList.remove('active');
  });
  document.getElementById('btnModalClose').addEventListener('click', () => {
    document.getElementById('forensicModal').classList.remove('active');
  });

  // Forensic Modal Action Buttons
  document.getElementById('btnModalNeutralize').addEventListener('click', () => {
    if (currentForensicThreat) neutralizeThreat(currentForensicThreat.id);
  });
  document.getElementById('btnModalDelete').addEventListener('click', () => {
    if (currentForensicThreat) deleteThreatFile(currentForensicThreat.id);
  });

  // Urgent Banner Close Button
  document.getElementById('btnBannerClose').addEventListener('click', () => {
    document.getElementById('urgentBanner').style.display = 'none';
  });

  // Email Settings Modal
  const emailModal = document.getElementById('emailModal');
  document.getElementById('btnEmailSettings').addEventListener('click', () => {
    emailModal.classList.add('active');
  });

  document.getElementById('btnCloseModal').addEventListener('click', () => {
    emailModal.classList.remove('active');
  });

  emailModal.addEventListener('click', (e) => {
    if (e.target === emailModal) emailModal.classList.remove('active');
  });

  // Save Settings Form
  document.getElementById('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      ownerEmail: document.getElementById('ownerEmail').value.trim(),
      smtpHost: document.getElementById('smtpHost').value.trim(),
      smtpPort: document.getElementById('smtpPort').value.trim(),
      smtpFrom: document.getElementById('smtpFrom').value.trim(),
      smtpUser: document.getElementById('smtpUser').value.trim(),
      smtpPass: document.getElementById('smtpPass').value
    };

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        alert('Email settings saved successfully! Threat alerts will be delivered immediately.');
        emailModal.classList.remove('active');
        fetchStatus();
      } else {
        alert('Failed saving settings: ' + data.error);
      }
    } catch (err) {
      alert('Network error: ' + err.message);
    }
  });

  // Test Email Button
  document.getElementById('btnTestEmail').addEventListener('click', async () => {
    const email = document.getElementById('ownerEmail').value.trim();
    if (!email) {
      alert('Please enter an email address first.');
      return;
    }
    const btn = document.getElementById('btnTestEmail');
    btn.textContent = 'Sending test...';
    btn.disabled = true;

    try {
      const res = await fetch('/api/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json();
      if (data.success) {
        alert(`✅ Test email delivered successfully to ${email}!`);
      } else {
        alert(`❌ Failed to send test email: ${data.error}`);
      }
    } catch (err) {
      alert('Network error: ' + err.message);
    } finally {
      btn.textContent = '📨 Send Test Email';
      btn.disabled = false;
    }
  });
}

function updateSoundUI() {
  document.getElementById('soundIcon').textContent = soundEnabled ? '🔔' : '🔕';
  document.getElementById('soundLabel').textContent = soundEnabled ? 'Sound: ON' : 'Sound: OFF';
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function formatDate(isoStr) {
  if (!isoStr) return '--';
  const d = new Date(isoStr);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' (' + d.toLocaleDateString() + ')';
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
