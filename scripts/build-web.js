const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const RENDERER_DIR = path.join(ROOT_DIR, 'renderer');
const ASSETS_DIR = path.join(ROOT_DIR, 'assets');
const DIST_WEB_DIR = path.join(ROOT_DIR, 'dist', 'web');

console.log('🚀 Building Security Guard for Web...');

// Ensure output directories exist
fs.mkdirSync(DIST_WEB_DIR, { recursive: true });
fs.mkdirSync(path.join(DIST_WEB_DIR, 'assets'), { recursive: true });

// Copy renderer files
const rendererFiles = ['index.html', 'styles.css', 'app.js', 'web-bridge.js'];
rendererFiles.forEach(file => {
  const src = path.join(RENDERER_DIR, file);
  const dest = path.join(DIST_WEB_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`  ✓ Copied renderer/${file} -> dist/web/${file}`);
  }
});

// Copy assets
if (fs.existsSync(ASSETS_DIR)) {
  const assets = fs.readdirSync(ASSETS_DIR);
  assets.forEach(file => {
    const src = path.join(ASSETS_DIR, file);
    const dest = path.join(DIST_WEB_DIR, 'assets', file);
    if (fs.statSync(src).isFile()) {
      fs.copyFileSync(src, dest);
    }
  });
  console.log(`  ✓ Copied ${assets.length} assets -> dist/web/assets/`);
}

// Generate PWA manifest
const manifest = {
  name: "Security Guard - Defense & Intelligence Hub",
  short_name: "Security Guard",
  start_url: "./index.html",
  display: "standalone",
  background_color: "#0f172a",
  theme_color: "#0284c7",
  icons: [
    {
      src: "assets/icon.png",
      sizes: "512x512",
      type: "image/png"
    }
  ]
};
fs.writeFileSync(path.join(DIST_WEB_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log('  ✓ Generated dist/web/manifest.json');

// Generate Service Worker
const swContent = `
const CACHE_NAME = 'security-guard-web-v1';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './web-bridge.js',
  './assets/icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((res) => res || fetch(e.request))
  );
});
`;
fs.writeFileSync(path.join(DIST_WEB_DIR, 'sw.js'), swContent.trim());
console.log('  ✓ Generated dist/web/sw.js');

console.log('\n✨ Security Guard Web build completed successfully!');
console.log(`📦 Web distributable located at: ${DIST_WEB_DIR}`);
