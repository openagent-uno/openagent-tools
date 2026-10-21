import { existsSync } from 'node:fs';

type PathExists = (path: string) => boolean;

/**
 * Resolve the same operator/system Chromium installations the rest of
 * OpenAgent uses before falling back to Playwright's revisioned cache.
 *
 * Release bundles contain Playwright's Node package, but its downloaded
 * browser lives outside node_modules and therefore is not part of the
 * PyInstaller archive.  A host can consequently have a perfectly healthy
 * Chrome (or an explicit OPENAGENT_CHROME_BINARY) while chromium.launch()
 * still fails because one exact ~/.cache/ms-playwright revision is absent.
 */
export function resolveChromiumExecutable(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  pathExists: PathExists = existsSync,
): string | undefined {
  const candidates: Array<string | undefined> = [
    env.OPENAGENT_CHROME_BINARY,
    env.CHROME_PATH,
  ];

  if (platform === 'darwin') {
    candidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
    );
  } else if (platform === 'win32') {
    for (const base of [env.PROGRAMFILES, env['PROGRAMFILES(X86)'], env.LOCALAPPDATA]) {
      if (base) candidates.push(`${base}\\Google\\Chrome\\Application\\chrome.exe`);
    }
  } else {
    candidates.push(
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
    );
  }

  for (const candidate of candidates) {
    const normalized = candidate?.trim();
    if (normalized && pathExists(normalized)) return normalized;
  }
  return undefined;
}

