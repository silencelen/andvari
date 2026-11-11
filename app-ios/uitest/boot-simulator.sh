#!/usr/bin/env bash
# Creates and boots a fresh iPhone simulator on the newest installed iOS, trusts the test site's CA in it,
# and enrolls its Face ID. Prints the device's UDID on the last line. macOS only.
# Usage: app-ios/uitest/boot-simulator.sh <ca.pem>
set -euo pipefail
CA="${1:?usage: boot-simulator.sh <ca.pem>}"
NAME="andvari-uitest"

xcrun simctl delete "$NAME" > /dev/null 2>&1 || true
read -r RUNTIME DEVICE_TYPE < <(xcrun simctl list -j runtimes devicetypes | python3 -c '
import json, sys
data = json.load(sys.stdin)
runtimes = [r for r in data["runtimes"] if r.get("isAvailable") and r.get("platform", "iOS") == "iOS" and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS")]
runtimes.sort(key=lambda r: [int(p) for p in r["version"].split(".")])
runtime = runtimes[-1]
supported = [d["identifier"] for d in runtime.get("supportedDeviceTypes", []) if d.get("productFamily") == "iPhone"]
# A Face ID phone of the current line when there is one; any iPhone otherwise.
preferred = [d for d in supported if d.endswith(("iPhone-17", "iPhone-17-Pro", "iPhone-16", "iPhone-16-Pro"))]
print(runtime["identifier"], (preferred or supported)[0])
')
echo "runtime: $RUNTIME, device type: $DEVICE_TYPE" >&2
UDID="$(xcrun simctl create "$NAME" "$DEVICE_TYPE" "$RUNTIME")"
xcrun simctl boot "$UDID"
xcrun simctl bootstatus "$UDID" -b >&2
xcrun simctl keychain "$UDID" add-root-cert "$CA"
# The keyboard's one-time swipe-typing lesson covers the keys the tests type on.
for domain in com.apple.keyboard.preferences com.apple.Preferences; do
  xcrun simctl spawn "$UDID" defaults write "$domain" DidShowContinuousPathIntroduction -bool true || true
done
# Features > Face ID > Enrolled. The tests set it again from inside (Biometrics.swift).
xcrun simctl spawn "$UDID" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1 >&2 || true
xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit.enrollmentChanged >&2 || true
echo "$UDID"
