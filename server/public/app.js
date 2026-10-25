// Security Guard Server Edition - Web Dashboard Client Logic

let threatsData = [];
let eventSource = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  fetchStatus();
  fetchThreats();
  setupSSE();
  setupUIHandlers();

  // Poll metrics every 10 seconds
  setInterval(fetchStatus, 10000);
});

// Fetch Server Status & Metrics
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
      subThreats.textContent = 'Active malicious infiltration detected!';
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

    // Shield status
    document.getElementById('valShield').textContent = data.shieldStatus;
  } catch (err) {
    console.error('Failed fetching status:', err);
  }
}

// Fetch Threats & Incidents
async function fetchThreats() {
  try {
    const res = await fetch('/api/threats');
    threatsData = await res.json();
    renderThreatsTable();
  } catch (err) {
    console.error('Failed fetching threats:', err);
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
          ✓ No active threats detected on this server. Background shield is actively watching.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = threatsData.map(t => {
    const isNeutralized = t.status === 'NEUTRALIZED' || t.status === 'NOT_FOUND_REMOVED';
    const badgeClass = isNeutralized ? 'badge-neutralized' : 'badge-critical';
    const statusText = isNeutralized ? '✓ NEUTRALIZED' : '⚠️ ACTIVE THREAT';

    return `
      <tr>
        <td><span class="badge ${badgeClass}">${t.severity || 'CRITICAL'}</span></td>
        <td><strong>${escapeHtml(t.name || 'Malware Payload')}</strong></td>
        <td><span class="path-code">${escapeHtml(t.file || '--')}</span></td>
        <td style="font-size:12px; color:var(--text-muted);">${formatDate(t.timestamp)}</td>
        <td><span class="badge ${badgeClass}">${statusText}</span></td>
        <td>
          ${!isNeutralized ? `
            <button class="btn btn-danger" style="padding:4px 10px; font-size:12px;" onclick="neutralizeThreat('${t.id}')">
              ⚡ Neutralize
            </button>
          ` : `
            <span style="font-size:12px; color:var(--accent-green);">Secured</span>
          `}
        </td>
      </tr>
    `;
  }).join('');
}

// 1-Click Neutralize Threat
async function neutralizeThreat(threatId) {
  if (!confirm('Are you sure you want to neutralize and isolate this file?')) return;

  try {
    const res = await fetch('/api/neutralize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threatId })
    });
    const result = await res.json();

    if (result.success) {
      alert('Threat successfully neutralized and quarantined!');
      fetchThreats();
      fetchStatus();
    } else {
      alert('Error: ' + (result.error || 'Failed to neutralize'));
    }
  } catch (err) {
    alert('Failed to connect to server: ' + err.message);
  }
}

// Live Server-Sent Events (SSE)
function setupSSE() {
  try {
    eventSource = new EventSource('/api/events');

    eventSource.addEventListener('threat', (e) => {
      const threat = JSON.parse(e.data);
      threatsData.unshift(threat);
      renderThreatsTable();
      fetchStatus();

      // Browser Desktop Notification if permitted
      if (Notification.permission === 'granted') {
        new Notification(`🚨 Server Alert: ${threat.name}`, {
          body: `Infected path: ${threat.file}`
        });
      }
    });

    eventSource.addEventListener('scan_start', (e) => {
      const data = JSON.parse(e.data);
      const consoleCard = document.getElementById('scanConsoleCard');
      const terminal = document.getElementById('scanTerminal');
      consoleCard.style.display = 'block';
      terminal.textContent = `[${new Date().toLocaleTimeString()}] Initiated server scan on ${data.targetPath}...\n`;
      document.getElementById('scanStatusBadge').textContent = 'SCANNING IN PROGRESS...';
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

// Helpers
function formatUptime(seconds) {
  const d = Math.floor(seconds / (3600 * 24));
  const h = Math.floor((seconds % (3600 * 24)) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function formatDate(isoStr) {
  if (!isoStr) return '--';
  const d = new Date(isoStr);
  return d.toLocaleString();
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
