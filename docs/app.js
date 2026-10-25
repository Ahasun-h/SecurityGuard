// Security Guard Desktop - Distribution Web Application Logic

document.addEventListener('DOMContentLoaded', () => {
  // 1. Detect User OS
  const userAgent = window.navigator.userAgent.toLowerCase();
  const platform = window.navigator.platform ? window.navigator.platform.toLowerCase() : '';
  
  let detectedOS = 'mac'; // default
  let detectedArch = 'arm64'; // assume Apple Silicon modern mac by default

  if (platform.includes('win') || userAgent.includes('windows')) {
    detectedOS = 'win';
  } else if (platform.includes('linux') || userAgent.includes('linux') || userAgent.includes('x11')) {
    detectedOS = 'linux';
  } else if (platform.includes('mac') || userAgent.includes('macintosh') || userAgent.includes('mac os')) {
    detectedOS = 'mac';
    // Check if arm64 can be determined
    if (navigator.userAgentData) {
      navigator.userAgentData.getHighEntropyValues(['architecture']).then(values => {
        if (values.architecture === 'arm') detectedArch = 'arm64';
        else if (values.architecture === 'x86') detectedArch = 'x64';
        updateHeroDownloadButton(detectedOS, detectedArch);
      }).catch(() => {});
    }
  }

  // Update Hero Button based on detected OS
  function updateHeroDownloadButton(os, arch) {
    const heroBtn = document.getElementById('heroDownloadBtn');
    if (!heroBtn) return;

    if (os === 'mac') {
      heroBtn.innerHTML = `<span>🍏</span> Download for macOS (${arch === 'arm64' ? 'Apple Silicon' : 'Intel'})`;
      heroBtn.href = arch === 'arm64'
        ? 'https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-arm64.dmg'
        : 'https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0.dmg';
    } else if (os === 'win') {
      heroBtn.innerHTML = `<span>🪟</span> Download for Windows (64-bit)`;
      heroBtn.href = 'https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard.Setup.1.0.0.exe';
    } else if (os === 'linux') {
      heroBtn.innerHTML = `<span>🐧</span> Download for Linux (.AppImage)`;
      heroBtn.href = 'https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0.AppImage';
    }

    // Highlight matching download card
    document.querySelectorAll('.download-card').forEach(card => card.classList.remove('highlight'));
    const matchedCard = document.getElementById(`card-${os}`);
    if (matchedCard) {
      matchedCard.classList.add('highlight');
      const badge = matchedCard.querySelector('.os-arch');
      if (badge) badge.innerHTML += ` &bull; <strong style="color:var(--primary);">Recommended for You</strong>`;
    }

    // Activate corresponding install tab
    activateInstallTab(os);
  }

  updateHeroDownloadButton(detectedOS, detectedArch);

  // 2. Interactive Installation Tabs Switcher
  function activateInstallTab(osName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === osName);
    });
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.toggle('active', pane.id === `tab-${osName}`);
    });
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabTarget = btn.getAttribute('data-tab');
      activateInstallTab(tabTarget);
    });
  });

  // 3. One-Click Copy to Clipboard with Feedback
  document.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', async () => {
      const textToCopy = btn.getAttribute('data-copy');
      if (!textToCopy) return;

      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalText = btn.textContent;
        btn.textContent = '✓ Copied!';
        btn.style.background = 'var(--accent-green)';
        btn.style.color = '#ffffff';

        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.background = '';
          btn.style.color = '';
        }, 2000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  });

  // 4. FAQ Accordion Interaction
  document.querySelectorAll('.faq-question').forEach(btn => {
    btn.addEventListener('click', () => {
      const parent = btn.parentElement;
      const wasActive = parent.classList.contains('active');
      
      document.querySelectorAll('.faq-item').forEach(item => item.classList.remove('active'));
      if (!wasActive) {
        parent.classList.add('active');
      }
    });
  });
});
