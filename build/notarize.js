require('dotenv').config();
const path = require('path');
const { notarize } = require('@electron/notarize');

exports.default = async function (context) {
  const { electronPlatformName, appOutDir } = context;
  if (electronPlatformName !== 'darwin') {
    return;
  }

  // Check if developer credentials exist in environment
  const appleId = process.env.APPLE_ID;
  const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
  const teamId = process.env.APPLE_TEAM_ID;

  if (!appleId || !appleIdPassword || !teamId) {
    console.log('[notarize] ℹ️  Apple Developer credentials not found (APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID).');
    console.log('[notarize] ℹ️  Skipping Apple Notarization. The app will be built with local ad-hoc signatures.');
    console.log('[notarize] ℹ️  To notarize for production, configure these variables in your .env or environment.');
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(appOutDir, `${appName}.app`);

  console.log(`[notarize] 🚀 Submitting ${appPath} to Apple Notary Service for Team ID: ${teamId}...`);

  try {
    await notarize({
      appPath,
      appleId,
      appleIdPassword,
      teamId,
    });
    console.log(`[notarize] ✅ Notarization and stapling complete for ${appName}!`);
  } catch (error) {
    console.warn(`[notarize] ⚠️ Apple Notarization skipped (Developer ID certificate required):`, error.message);
  }
};
