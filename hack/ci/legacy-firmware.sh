#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || $(uname -s) != Linux || $EUID -ne 0 ]]; then
  echo "Usage (Linux): sudo unshare --mount --pid --kill-child --mount-proc --propagation private bash $0 <ipsw-binary> <firmware-directory>" >&2
  exit 2
fi

ipsw_binary=$(realpath "$1")
fixture_root=$(realpath -m "$2")
fixture="$fixture_root/iPad2,1_6.1.3_10B329_Restore.ipsw"
fixture_sha=34baf342d7a6adef2c93f507f707d1bea46b61100c8568d4937bb055638cb67b
mkdir -p "$fixture_root"
run_root=$(mktemp -d "$fixture_root/run.XXXXXX")
mount_point="$run_root/mount"
mkdir "$run_root/tmp" "$run_root/output" "$mount_point"

cleanup() {
  local result=$?
  trap - EXIT
  if mountpoint -q "$mount_point" && ! timeout 30 umount "$mount_point"; then
    echo "Failed to unmount $mount_point; retaining $run_root" >&2
    exit 1
  fi
  if [[ $result -eq 0 ]]; then
    rm -rf --one-file-system -- "$run_root"
  else
    echo "Retaining failed test files at $run_root" >&2
  fi
  exit "$result"
}
trap cleanup EXIT

if [[ ! -f "$fixture" ]]; then
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 600 \
    --output "$fixture.partial" \
    'https://secure-appldnld.apple.com/iOS6.1/091-2397.20130319.EEae9/iPad2,1_6.1.3_10B329_Restore.ipsw'
  printf '%s  %s\n' "$fixture_sha" "$fixture.partial" | sha256sum --check
  mv "$fixture.partial" "$fixture"
else
  printf '%s  %s\n' "$fixture_sha" "$fixture" | sha256sum --check
fi

timeout 300 "$ipsw_binary" info --lookup --json "$fixture" > "$run_root/info.json"
timeout 300 "$ipsw_binary" extract --dtree --lookup --json \
  --output "$run_root/output" "$fixture" > "$run_root/dtree.json"
python3 - "$run_root" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
info = json.loads((root / "info.json").read_text())
assert (info["version"], info["build"]) == ("6.1.3", "10B329"), info
assert any(d["product"] == "iPad2,1" and d["board"] == "K93AP" for d in info["devices"]), info
paths = json.loads((root / "dtree.json").read_text())
assert len(paths) == 1, paths
payload = pathlib.Path(paths[0])
assert payload.name == "DeviceTree.k93ap" and payload.stat().st_size == 73688, payload
PY

timeout 300 env TMPDIR="$run_root/tmp" "$ipsw_binary" mount fs --lookup \
  --detach --mount-point "$mount_point" "$fixture"
loop_device=$(findmnt --noheadings --raw --output SOURCE --mountpoint "$mount_point")
[[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]]
loop_backing_file="/sys/class/block/${loop_device##*/}/loop/backing_file"
IFS= read -r loop_backing < "$loop_backing_file"
[[ "$loop_backing" == "$run_root/tmp/.ipsw-hfsplus-"*.img* ]]
[[ $(findmnt --noheadings --raw --output FSTYPE --mountpoint "$mount_point") == hfsplus ]]
mount_options=$(findmnt --noheadings --raw --output OPTIONS --mountpoint "$mount_point")
[[ ",$mount_options," == *,ro,* ]]
mounted_digest=$(sha256sum < "$mount_point/System/Library/CoreServices/SystemVersion.plist")
timeout 30 umount "$mount_point"
udevadm settle --timeout=10
if [[ -e "$loop_backing_file" ]]; then
  IFS= read -r current_backing < "$loop_backing_file"
  [[ "$current_backing" != "$loop_backing" ]]
fi

timeout 300 env TMPDIR="$run_root/tmp" "$ipsw_binary" extract --files --lookup --json \
  --pattern 'System/Library/CoreServices/SystemVersion\.plist$' \
  --output "$run_root/output" "$fixture" > "$run_root/files.json"
python3 - "$run_root/files.json" "${mounted_digest%% *}" <<'PY'
import hashlib, json, plistlib, sys
with open(sys.argv[1]) as f:
    paths = json.load(f)
assert len(paths) == 1, paths
with open(paths[0], "rb") as f:
    data = f.read()
assert hashlib.sha256(data).hexdigest() == sys.argv[2], "mounted and extracted files differ"
version = plistlib.loads(data)
assert (version["ProductVersion"], version["ProductBuildVersion"]) == ("6.1.3", "10B329"), version
print("Mounted and extracted identical SystemVersion.plist from iOS 6.1.3 (10B329)")
PY
