const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

exports.default = async function (context) {
  if (context.electronPlatformName === 'darwin') {
    const appPath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
    const entitlementsPath = path.join(context.packager.projectDir, 'build', 'entitlements.mac.plist');

    console.log(`[afterPack] Checking code signature for: ${appPath}`);

    // If Apple developer identity was used by electron-builder, verify if signature is valid
    let needsAdHocSign = true;
    try {
      execSync(`codesign --verify --deep --strict "${appPath}" 2>/dev/null`);
      needsAdHocSign = false;
      console.log(`[afterPack] Existing code signature is valid.`);
    } catch {
      needsAdHocSign = true;
    }

    if (needsAdHocSign) {
      console.log(`[afterPack] Applying clean ad-hoc signature with entitlements to: ${appPath}`);
      const entFlag = fs.existsSync(entitlementsPath) ? `--entitlements "${entitlementsPath}"` : '';
      try {
        execSync(`codesign --force --deep --sign - ${entFlag} "${appPath}"`, { stdio: 'inherit' });
        console.log(`[afterPack] Successfully re-signed ${appPath}`);
      } catch (err) {
        console.warn(`[afterPack] Warning: Could not apply ad-hoc signature:`, err.message);
      }
    }
  }
};
