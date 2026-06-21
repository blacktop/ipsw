#!/usr/bin/env bash
set -euo pipefail

# update.sh — regenerate the embedded crash-log type database from Apple's
# OSAnalytics submissionConfig.plist (the upstream source of the bug_type names
# that `ipsw symbolicate` reports, e.g. 298 -> "Jetsam", 410 -> "AutomationPanic").
#
# How to refresh from a newer OS release:
#
#   1. Pull the plist out of any macOS or iOS IPSW (it lives in OSAnalytics.framework):
#        ipsw extract --files --pattern '.*submissionConfig\.plist$' -o /tmp/osa <IPSW>
#
#   2. Find the extracted plist and regenerate log_type.json + log_type.gz from it:
#        ./pkg/crashlog/data/update.sh "$(find /tmp/osa -name submissionConfig.plist | head -1)"
#
#   3. Rebuild; `go:embed` picks up the new log_type.gz automatically.
#
# iOS and macOS ship an identical type set, so either IPSW works. Output is
# canonical (compact, sorted keys) so re-runs produce clean, minimal diffs.
# Requires python3 (ships with macOS) — reads the binary plist and writes JSON.

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <submissionConfig.plist>" >&2
	exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "error: python3 is required (ships with macOS); install it and re-run" >&2
	exit 1
fi

plist="$1"
dir="$(cd "$(dirname "$0")" && pwd)"

python3 - "$plist" "$dir/log_type.json" "$dir/log_type.gz" <<'PY'
import gzip, json, plistlib, sys

src, json_out, gz_out = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, "rb") as fh:
    data = plistlib.load(fh)

# Validate the plist shape BEFORE writing anything — a wrong/renamed file must not
# overwrite the committed DB with garbage and leave it corrupted.
if "log_types" not in data:
    sys.exit(f"error: {src} has no 'log_types' key — not an OSAnalytics submissionConfig.plist")

# Canonical JSON (compact, sorted keys) + a deterministic gzip header (no embedded
# filename, fixed mtime) keep log_type.json / log_type.gz byte-stable across runs,
# so future refreshes show only the real data changes in the diff.
blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
with open(json_out, "wb") as fh:
    fh.write(blob)
with open(gz_out, "wb") as fh, gzip.GzipFile(filename="", mtime=0, mode="wb", fileobj=fh) as gz:
    gz.write(blob)

print(f"wrote {len(data['log_types'])} log types -> {json_out} (+ .gz)")
PY
