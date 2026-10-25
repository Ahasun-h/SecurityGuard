/**
 * Security Guard Server - Zero-Dependency SMTP & Webhook Email Dispatcher
 * Sends instant security alerts when malware, webshells, or backdoors are detected.
 */
const tls = require('tls');
const net = require('net');
const https = require('https');

class Mailer {
  constructor(config = {}) {
    this.config = config;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Dispatches a critical security threat alert email to the server owner
   */
  async sendThreatAlert(threatData) {
    const ownerEmail = this.config.ownerEmail;
    if (!ownerEmail) {
      console.warn('[MAILER] No ownerEmail configured. Skipping email alert.');
      return { success: false, error: 'No ownerEmail configured' };
    }

    const hostname = threatData.hostname || require('os').hostname();
    const serverIp = threatData.serverIp || 'Server Host';
    const filePath = threatData.file || threatData.path || 'Unknown path';
    const threatName = threatData.name || threatData.rule || threatData.type || 'Injected Trojan / Malware';
    const severity = (threatData.severity || 'CRITICAL').toUpperCase();
    const timestamp = threatData.timestamp || new Date().toISOString();
    const webViewUrl = this.config.dashboardUrl || `http://${hostname}:8888`;

    const subject = `🚨 [SECURITY ALERT] ${severity} Malware Detected on ${hostname} (${serverIp})`;

    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }
    .container { max-width: 620px; margin: 0 auto; background: #111827; border: 1px solid #ef4444; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(239, 68, 68, 0.2); }
    .header { background: linear-gradient(135deg, #7f1d1d, #991b1b); padding: 24px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; color: #ffffff; letter-spacing: 0.5px; }
    .badge { display: inline-block; background: #dc2626; color: #fff; font-weight: bold; font-size: 12px; padding: 4px 12px; border-radius: 20px; text-transform: uppercase; margin-top: 8px; }
    .content { padding: 28px; }
    .alert-box { background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; padding: 14px 18px; border-radius: 6px; margin-bottom: 24px; }
    .alert-box strong { color: #f87171; font-size: 16px; }
    .details-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    .details-table td { padding: 10px 12px; border-bottom: 1px solid #1f2937; font-size: 14px; }
    .details-table td.label { color: #9ca3af; width: 35%; font-weight: 500; }
    .details-table td.value { color: #f3f4f6; font-family: 'SFMono-Regular', Consolas, monospace; word-break: break-all; }
    .btn-container { text-align: center; margin-top: 28px; }
    .btn { display: inline-block; background: #06b6d4; color: #050b14 !important; font-weight: bold; font-size: 15px; padding: 12px 28px; border-radius: 8px; text-decoration: none; box-shadow: 0 4px 14px rgba(6, 182, 212, 0.4); }
    .footer { background: #0a0e17; padding: 16px; text-align: center; font-size: 12px; color: #6b7280; border-top: 1px solid #1f2937; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 SECURITY GUARD SERVER ALERT</h1>
      <div class="badge">Threat Severity: ${severity}</div>
    </div>
    <div class="content">
      <div class="alert-box">
        <strong>Malware Infiltration Intercepted</strong><br>
        The continuous background shield intercepted suspicious code execution or infected file tampering on your server.
      </div>

      <table class="details-table">
        <tr>
          <td class="label">Server Host:</td>
          <td class="value">${hostname} (${serverIp})</td>
        </tr>
        <tr>
          <td class="label">Detected Threat:</td>
          <td class="value" style="color:#f87171; font-weight:bold;">${threatName}</td>
        </tr>
        <tr>
          <td class="label">Infected Path:</td>
          <td class="value">${filePath}</td>
        </tr>
        <tr>
          <td class="label">Detection Time:</td>
          <td class="value">${timestamp}</td>
        </tr>
      </table>

      <div class="btn-container">
        <a href="${webViewUrl}" class="btn">View Live Forensic Report in Web View &rarr;</a>
      </div>
    </div>
    <div class="footer">
      Security Guard Server Daemon &bull; Automated Cyber Defense Engine &bull; Host: ${hostname}
    </div>
  </div>
</body>
</html>
`;

    const textBody = `
[SECURITY GUARD ALERT] ${severity} Malware Detected on ${hostname} (${serverIp})
========================================================================

Detected Threat : ${threatName}
Infected File   : ${filePath}
Timestamp       : ${timestamp}
Server Hostname : ${hostname} (${serverIp})

View full forensic report and neutralize the threat on your Web Dashboard:
${webViewUrl}

--
Security Guard Server Edition
`;

    return this.sendMail({
      to: ownerEmail,
      subject,
      html: htmlBody,
      text: textBody
    });
  }

  /**
   * Sends a test verification email to confirm email settings are working
   */
  async sendTestEmail(targetEmail) {
    const hostname = require('os').hostname();
    const subject = `✅ Security Guard Server: Email Verification from ${hostname}`;
    const html = `
      <div style="font-family:sans-serif; background:#111827; color:#f3f4f6; padding:24px; border-radius:10px; max-width:500px;">
        <h2 style="color:#10b981; margin-top:0;">🛡️ Security Guard Email Alerts Verified</h2>
        <p>This test confirms that your server <strong>${hostname}</strong> is correctly configured to dispatch instant email alerts upon threat detection.</p>
        <p style="font-size:13px; color:#9ca3af;">Configured Time: ${new Date().toLocaleString()}</p>
      </div>
    `;
    const text = `Security Guard Server: Email notifications verified for ${hostname} at ${new Date().toLocaleString()}`;

    return this.sendMail({
      to: targetEmail || this.config.ownerEmail,
      subject,
      html,
      text
    });
  }

  /**
   * Low-level dispatcher: Supports SMTP (native socket) or Resend / SendGrid API
   */
  async sendMail({ to, subject, html, text }) {
    // 1. If Resend API Key is provided
    if (this.config.resendApiKey) {
      return this._sendViaResend({ to, subject, html, text });
    }

    // 2. If SendGrid API Key is provided
    if (this.config.sendgridApiKey) {
      return this._sendViaSendGrid({ to, subject, html, text });
    }

    // 3. Fallback to native SMTP (Zero dependencies)
    if (this.config.smtpHost && this.config.smtpUser && this.config.smtpPass) {
      return this._sendViaSmtp({ to, subject, html, text });
    }

    console.warn('[MAILER] No email transport configured (no SMTP credentials or Resend/SendGrid API keys).');
    return {
      success: false,
      error: 'No email transport configured. Please configure SMTP in server settings.'
    };
  }

  /**
   * Native SMTP protocol client using Node.js TLS/Net sockets
   */
  _sendViaSmtp({ to, subject, html, text }) {
    return new Promise((resolve) => {
      const host = this.config.smtpHost;
      const port = parseInt(this.config.smtpPort || '465', 10);
      const user = this.config.smtpUser;
      const pass = this.config.smtpPass;
      const from = this.config.smtpFrom || user;
      const secure = port === 465;

      let socket;
      const isDone = false;

      const cleanup = (err, result) => {
        if (socket && !socket.destroyed) {
          try { socket.end(); } catch (_) {}
        }
        if (err) {
          console.error('[SMTP ERROR]', err.message || err);
          resolve({ success: false, error: err.message || String(err) });
        } else {
          resolve({ success: true, ...result });
        }
      };

      try {
        if (secure) {
          socket = tls.connect({ host, port, rejectUnauthorized: false });
        } else {
          socket = net.connect({ host, port });
        }
      } catch (err) {
        return cleanup(err);
      }

      socket.setTimeout(15000);
      socket.setEncoding('utf8');

      let step = 0;
      let buffer = '';

      socket.on('timeout', () => cleanup(new Error('SMTP Connection timed out')));
      socket.on('error', (err) => cleanup(err));

      socket.on('data', (chunk) => {
        buffer += chunk;
        const lines = buffer.split('\r\n');
        buffer = lines.pop(); // keep last incomplete chunk

        for (const line of lines) {
          if (!line) continue;
          const code = parseInt(line.substring(0, 3), 10);
          const isFinal = line.charAt(3) === ' ';

          if (!isFinal) continue; // multi-line response like 250-AUTH

          switch (step) {
            case 0: // Connected, waiting for 220
              if (code === 220) {
                step = 1;
                socket.write(`EHLO localhost\r\n`);
              } else {
                return cleanup(new Error(`Unexpected greeting: ${line}`));
              }
              break;

            case 1: // EHLO response
              if (code === 250) {
                step = 2;
                socket.write(`AUTH LOGIN\r\n`);
              } else {
                return cleanup(new Error(`EHLO failed: ${line}`));
              }
              break;

            case 2: // AUTH LOGIN response (334 VXNlcm5hbWU6)
              if (code === 334) {
                step = 3;
                socket.write(`${Buffer.from(user).toString('base64')}\r\n`);
              } else {
                return cleanup(new Error(`AUTH LOGIN rejected: ${line}`));
              }
              break;

            case 3: // Password prompt (334 UGFzc3dvcmQ6)
              if (code === 334) {
                step = 4;
                socket.write(`${Buffer.from(pass).toString('base64')}\r\n`);
              } else {
                return cleanup(new Error(`Username rejected: ${line}`));
              }
              break;

            case 4: // Auth succeeded (235)
              if (code === 235) {
                step = 5;
                socket.write(`MAIL FROM:<${from}>\r\n`);
              } else {
                return cleanup(new Error(`Authentication failed (wrong password?): ${line}`));
              }
              break;

            case 5: // MAIL FROM ok
              if (code === 250) {
                step = 6;
                socket.write(`RCPT TO:<${to}>\r\n`);
              } else {
                return cleanup(new Error(`MAIL FROM failed: ${line}`));
              }
              break;

            case 6: // RCPT TO ok
              if (code === 250 || code === 251) {
                step = 7;
                socket.write(`DATA\r\n`);
              } else {
                return cleanup(new Error(`Recipient rejected (${to}): ${line}`));
              }
              break;

            case 7: // DATA prompt (354)
              if (code === 354) {
                step = 8;
                const boundary = `----=_Part_${Date.now()}`;
                const rawEmail = [
                  `From: "Security Guard Server" <${from}>`,
                  `To: <${to}>`,
                  `Subject: ${subject}`,
                  `MIME-Version: 1.0`,
                  `Content-Type: multipart/alternative; boundary="${boundary}"`,
                  ``,
                  `--${boundary}`,
                  `Content-Type: text/plain; charset=utf-8`,
                  `Content-Transfer-Encoding: 7bit`,
                  ``,
                  text,
                  ``,
                  `--${boundary}`,
                  `Content-Type: text/html; charset=utf-8`,
                  `Content-Transfer-Encoding: 7bit`,
                  ``,
                  html,
                  ``,
                  `--${boundary}--`,
                  `.`
                ].join('\r\n') + '\r\n';

                socket.write(rawEmail);
              } else {
                return cleanup(new Error(`DATA rejected: ${line}`));
              }
              break;

            case 8: // Email queued (250)
              if (code === 250) {
                step = 9;
                socket.write(`QUIT\r\n`);
                return cleanup(null, { message: 'Email sent successfully via SMTP' });
              } else {
                return cleanup(new Error(`Send message failed: ${line}`));
              }
              break;
          }
        }
      });
    });
  }

  /**
   * Resend API transport
   */
  _sendViaResend({ to, subject, html, text }) {
    return new Promise((resolve) => {
      const payload = JSON.stringify({
        from: this.config.fromEmail || 'Security Guard <onboarding@resend.dev>',
        to: [to],
        subject,
        html,
        text
      });

      const req = https.request({
        hostname: 'api.resend.com',
        path: '/emails',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.resendApiKey}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ success: true, provider: 'resend', response: data });
          } else {
            resolve({ success: false, error: `Resend API Error (${res.statusCode}): ${data}` });
          }
        });
      });

      req.on('error', err => resolve({ success: false, error: err.message }));
      req.write(payload);
      req.end();
    });
  }

  /**
   * SendGrid API transport
   */
  _sendViaSendGrid({ to, subject, html, text }) {
    return new Promise((resolve) => {
      const payload = JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: this.config.fromEmail || 'security@guard.internal', name: 'Security Guard' },
        subject,
        content: [
          { type: 'text/plain', value: text },
          { type: 'text/html', value: html }
        ]
      });

      const req = https.request({
        hostname: 'api.sendgrid.com',
        path: '/v3/mail/send',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.sendgridApiKey}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ success: true, provider: 'sendgrid' });
          } else {
            resolve({ success: false, error: `SendGrid Error (${res.statusCode}): ${data}` });
          }
        });
      });

      req.on('error', err => resolve({ success: false, error: err.message }));
      req.write(payload);
      req.end();
    });
  }
}

module.exports = Mailer;
