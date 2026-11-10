#!/bin/sh
# Build with a prebuilt ABI-v1 archive matching GOOS/GOARCH; no engine source is needed.
# Dynamic Linux links require GNU ld or LLD with --exclude-libs support.
# Pass static for a complete musl archive and a fully static Linux executable.
set -eu

fail() { printf '%s\n' "$*" >&2; exit 1; }
offline_go() { env GOPROXY=off GOTOOLCHAIN=local go "$@"; }
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail "Usage: sh hack/build-offline-ipa.sh LIBDIR OUTPUT [static]"
link_mode=${3:-dynamic}
case "$link_mode" in dynamic|static) ;; *) fail "The optional link mode must be static" ;; esac
libdir=$1
output=$2
[ -n "$libdir" ] && [ -n "$output" ] || fail "LIBDIR and OUTPUT must be nonempty"
case "$libdir" in /*) ;; *) libdir="$(pwd)/$libdir" ;; esac
case "$output" in /*) ;; *) output="$(pwd)/$output" ;; esac
case "$libdir" in
    *\"*|*\\*|*'
'*) fail "LIBDIR must not contain double quotes, backslashes, or newlines" ;;
esac
repo=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
cd "$repo"
archive="$libdir/libipsw_fp.a"
header=pkg/fairplay/ipsw_fp.h
hidden=pkg/fairplay/ipsw_fp_macos.hidden
[ -f "$archive" ] || fail "LIBDIR must contain the prebuilt libipsw_fp.a"
[ -f "$header" ] || fail "The ABI header is missing"
awk '$1 == "#define" && $2 == "IPSW_FP_ABI_VERSION" && $3 == "UINT32_C(1)" { found=1 }
     END { exit !found }' "$header" || fail "This builder requires the ABI-v1 header"
# The Go wrapper checks the archive's ABI version before any operation.
target_os=$(offline_go env GOOS)
target_arch=$(offline_go env GOARCH)
[ "$(offline_go env CGO_ENABLED)" = 1 ] || fail "This build requires CGO_ENABLED=1"

case "$target_os" in
    darwin)
        [ "$link_mode" = dynamic ] || fail "Static executable mode requires Linux"
        [ -s "$hidden" ] || fail "The macOS implementation-symbol list is missing"
        native_flags="-L \"$libdir\" -Wl,-dead_strip -Wl,-dead_strip_dylibs"
        external_flags="-Wl,-unexported_symbols_list,$hidden"
        deployment=${MACOSX_DEPLOYMENT_TARGET:-26.0}
        set -- env MACOSX_DEPLOYMENT_TARGET="$deployment" \
            CGO_CFLAGS="${CGO_CFLAGS:--O2 -g0} -mmacosx-version-min=$deployment" \
            CGO_CXXFLAGS="${CGO_CXXFLAGS:--O2 -g0} -mmacosx-version-min=$deployment"
        ;;
    linux)
        native_flags="-L \"$libdir\""
        if [ "$link_mode" = static ]; then
            case "$target_arch" in amd64|arm64) ;; *) fail "Static Linux supports amd64 and arm64" ;; esac
            external_flags="-static -Wl,--gc-sections"
        else
            external_flags="-Wl,--gc-sections,--exclude-libs,libipsw_fp.a"
        fi
        set -- env
        ;;
    *) fail "Supported targets are darwin and Linux" ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
    artifact_sha=$(sha256sum "$archive")
else
    artifact_sha=$(shasum -a 256 "$archive")
fi
artifact_sha=${artifact_sha%% *}
[ "${#artifact_sha}" -eq 64 ] || fail "Could not hash the prebuilt archive"
# Key the final linker cache to the archive bytes, including external replacements.
build_id="ipsw-fp-v1-$target_os-$target_arch-$artifact_sha"
version=${IPSW_FP_VERSION:-}
if [ -z "$version" ]; then
    version=$(git describe --tags --match 'v3.*' --always --dirty 2>/dev/null || printf 'dev')
fi
case "$version" in ''|*[!A-Za-z0-9._+-]*) fail "Invalid build version" ;; esac
commit=$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')
case "$commit" in unknown) ;; *[!0-9a-f]*|'') fail "Invalid build commit" ;; esac
link_flags="-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$version -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildCommit=$commit"
if [ "$link_mode" = static ]; then
    build_id="$build_id-static"
    link_flags="$link_flags -linkmode external"
fi
"$@" GOPROXY=off GOTOOLCHAIN=local CGO_LDFLAGS="$native_flags" \
    go build -mod=readonly -trimpath -tags ipsw_fp \
    -ldflags "$link_flags -buildid=$build_id -extldflags '$external_flags'" \
    -o "$output" ./cmd/ipsw
printf 'Built %s (%s/%s; engine SHA-256 %s)\n' "$output" "$target_os" "$target_arch" "$artifact_sha"
