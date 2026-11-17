#!/usr/bin/env bash
set -euo pipefail

bundle="${1:?usage: sign-native-macos.sh <bundle-dir>}"
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
test -n "${APPLE_TEAM_ID:-}" || { echo "missing required release input: APPLE_TEAM_ID" >&2; exit 1; }
if [[ -z "${APPLE_NOTARY_PROFILE:-}" ]]; then
  for name in APPLE_ID APPLE_APP_SPECIFIC_PASSWORD; do
    test -n "${!name:-}" || { echo "missing required release secret: $name (or use APPLE_NOTARY_PROFILE)" >&2; exit 1; }
  done
fi
test -d "$bundle" || { echo "bundle does not exist: $bundle" >&2; exit 1; }

temp_base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work_root="$(mktemp -d "$temp_base/openagent-host-tools-sign.XXXXXX")"
keychain="$work_root/sign.keychain-db"
keychain_password="$(openssl rand -hex 24)"
p12="$work_root/sign.p12"
original_keychains=()
while IFS= read -r existing; do
  existing="${existing//\"/}"
  test -n "$existing" && original_keychains+=("$existing")
done < <(security list-keychains -d user)
cleanup() {
  if [[ -f "$keychain" ]] && ((${#original_keychains[@]})); then
    security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1 || true
  fi
  if [[ -f "$keychain" ]]; then
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
  fi
  rm -rf "$work_root"
}
trap cleanup EXIT

if [[ -n "${CSC_NAME:-}" ]]; then
  # Local qualification reuses an existing identity without exporting its key
  # or mutating the user's keychain search list. CI retains its isolated import.
  identity="$CSC_NAME"
else
  for name in CSC_LINK CSC_KEY_PASSWORD; do
    test -n "${!name:-}" || { echo "missing required release secret: $name" >&2; exit 1; }
  done
  security create-keychain -p "$keychain_password" "$keychain"
  security unlock-keychain -p "$keychain_password" "$keychain"
  security set-keychain-settings -lut 3600 "$keychain"
  security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
  printf '%s' "$CSC_LINK" | base64 --decode > "$p12"
  security import "$p12" -k "$keychain" -P "$CSC_KEY_PASSWORD" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain"
  identity="$(security find-identity -v -p codesigning "$keychain" | awk -F'"' '/Developer ID Application/ {print $2; exit}')"
fi
test -n "$identity" || { echo "Developer ID Application identity not found" >&2; exit 1; }

helper="$bundle/openagent-computer-control.app"
test -x "$helper/Contents/MacOS/openagent-computer-control"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$helper/Contents/Info.plist")" = \
  "com.openagent.computer-control"

# Sign nested code first and never use --deep for signing: that would silently
# replace helper identities/entitlements during a parent release.
codesign --force --sign "$identity" --identifier com.openagent.computer-control \
  --options runtime --timestamp "$helper/Contents/MacOS/openagent-computer-control"
codesign --force --sign "$identity" --identifier com.openagent.computer-control \
  --options runtime --timestamp "$helper"

codesign --verify --deep --strict --verbose=2 "$helper"
for target in "$helper"; do
  actual_team="$(codesign -d --verbose=4 "$target" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
  test "$actual_team" = "$APPLE_TEAM_ID" || {
    echo "unexpected TeamIdentifier $actual_team for $target" >&2
    exit 1
  }
done

notary_zip="$work_root/notarize.zip"
ditto -c -k --keepParent "$bundle" "$notary_zip"
if [[ -n "${APPLE_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$notary_zip" --keychain-profile "$APPLE_NOTARY_PROFILE" --wait
else
  xcrun notarytool submit "$notary_zip" \
    --apple-id "$APPLE_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" --wait
fi
xcrun stapler staple "$helper"
xcrun stapler validate "$helper"
spctl --assess --type execute --verbose=4 "$helper"
