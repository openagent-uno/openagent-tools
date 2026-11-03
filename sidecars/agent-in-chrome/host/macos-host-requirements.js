// Trusted hosts decide whether to grant these requirements. This module never
// applies a sandbox policy or authorizes a process itself.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function macosAppShimServiceName(bundleIdentifier, profile) {
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]{1,200}$/.test(bundleIdentifier) ||
      !path.isAbsolute(profile) || path.resolve(profile) !== profile || /[\0\r\n]/.test(profile))
    throw new Error('Explicit bundle identifier and canonical absolute profile required');
  // Chromium AppShimController hashes the exact user-data-dir byte string.
  // The service belongs to one profile, rather than a vendor-wide wildcard.
  return bundleIdentifier + '.apps.' + createHash('sha256').update(profile).digest('hex').toUpperCase();
}

export function macosHostRequirements(binary, profile) {
  if (process.platform !== 'darwin' || !path.isAbsolute(binary)) throw new Error('Explicit macOS browser binary required');
  if (path.basename(binary) === 'chrome-headless-shell') {
    macosAppShimServiceName('org.chromium.Chromium',profile); // Validate the profile contract.
    return {schema:1,platform:'darwin',profile,machRegister:[],machRegisterPrefixes:['org.chromium.Chromium.MachPortRendezvousServer.']};
  }
  let bundle = path.dirname(binary);
  while (!bundle.endsWith('.app') && path.dirname(bundle) !== bundle) bundle = path.dirname(bundle);
  if (!bundle.endsWith('.app')) throw new Error('Browser application bundle required');
  const identifier = execFileSync('/usr/libexec/PlistBuddy', ['-c','Print:CFBundleIdentifier',path.join(bundle,'Contents/Info.plist')], {encoding:'utf8'}).trim();
  return {schema:1,platform:'darwin',profile,machRegister:[macosAppShimServiceName(identifier,profile)],machRegisterPrefixes:[identifier+'.MachPortRendezvousServer.']};
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--binary' || args[2] !== '--profile') throw new Error('Use --binary and --profile');
  console.log(JSON.stringify(macosHostRequirements(args[1],args[3])));
}
