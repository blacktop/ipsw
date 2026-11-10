#!/usr/bin/env python3
"""Build the three offline IPA release assets from reviewed public source."""

import argparse
import contextlib
import gzip
import hashlib
import json
import mmap
import os
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

TARGETS = {
    "macos-arm64": ("darwin", "arm64", "macOS_arm64", None),
    "linux-arm64": ("linux", "arm64", "linux_arm64", "aarch64-linux-musl"),
    "linux-amd64": ("linux", "amd64", "linux_x86_64", "x86_64-linux-musl"),
}
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
CHUNK = 1024 * 1024
REPO = Path(__file__).resolve().parent.parent
BUILD_TIMEOUT = 3600


class PackagingError(Exception):
    pass


class BuildCleanupError(PackagingError):
    pass


def wait_unreaped(process, seconds):
    # Reserve the leader PID until the final group signal, so its ID cannot be reused.
    deadline = time.monotonic() + seconds
    while True:
        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def stop_build_group(process):
    previous_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Darwin may return EPERM when only the unreaped leader remains.
                if not wait_unreaped(process, 0):
                    raise
            if sig == signal.SIGTERM:
                wait_unreaped(process, 5)
        if not wait_unreaped(process, 5):
            raise BuildCleanupError(
                "build group received SIGKILL, but its leader has not exited"
            )
        returncode = process.wait()
        deadline = time.monotonic() + 5
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return returncode
            except PermissionError:
                pass
            if time.monotonic() >= deadline:
                raise BuildCleanupError(
                    f"build leader exited with status {returncode}, but its process group still exists"
                )
            time.sleep(0.05)
    except OSError as error:
        raise BuildCleanupError(
            f"could not finish owned build group cleanup: {error}"
        ) from error
    finally:
        signal.signal(signal.SIGINT, previous_sigint)


def run_build(command, repo, build_env):
    process = subprocess.Popen(
        command, cwd=repo, env=build_env, stdout=sys.stderr, start_new_session=True
    )
    try:
        finished = wait_unreaped(process, BUILD_TIMEOUT)
    except BaseException:
        returncode = stop_build_group(process)
        print(
            f"Build interrupted; process exited with status {returncode}",
            file=sys.stderr,
        )
        raise
    if not finished:
        returncode = stop_build_group(process)
        raise PackagingError(
            f"build timed out after {BUILD_TIMEOUT} seconds; process exited with status {returncode}"
        )
    returncode = process.wait()
    if returncode:
        raise subprocess.CalledProcessError(returncode, command)


@contextlib.contextmanager
def staging_directory():
    stage = Path(tempfile.mkdtemp(prefix="ipsw-offline-ipa-"))
    cleanup = True
    try:
        yield stage
    except BuildCleanupError:
        cleanup = False
        print(
            f"Retained staging directory because build cleanup is incomplete: {stage}",
            file=sys.stderr,
        )
        raise
    finally:
        if cleanup:
            shutil.rmtree(stage)


def regular(path, limit=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (limit is not None and info.st_size > limit):
        raise PackagingError(f"expected a regular file of permitted size: {path}")
    return info


def digest_file(path):
    regular(path)
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checked_input(value, base, label, limit=None):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise PackagingError(f"{label} must contain exactly path and sha256")
    name, expected = value["path"], value["sha256"]
    if not isinstance(name, str) or not name or "\x00" in name:
        raise PackagingError(f"{label} path must be nonempty text")
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise PackagingError(f"{label} sha256 must be 64 lowercase hexadecimal digits")
    path = Path(os.path.abspath(base / name))
    regular(path, limit)
    if digest_file(path) != expected:
        raise PackagingError(f"SHA-256 mismatch for {label}")
    return path, expected


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackagingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_manifest(path):
    regular(path, 64 * 1024)
    manifest = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys
    )
    if not isinstance(manifest, dict) or set(manifest) != {"archives"}:
        raise PackagingError("manifest must contain exactly archives")
    archives = manifest["archives"]
    if not isinstance(archives, dict) or set(archives) != set(TARGETS):
        raise PackagingError("archives must name exactly " + ", ".join(TARGETS))
    checked = {}
    for target in TARGETS:
        checked[target] = checked_input(archives[target], path.parent, target)
        if checked[target][0].name != "libipsw_fp.a":
            raise PackagingError(f"{target} path must name libipsw_fp.a")
    return checked


def git_output(repo, *args):
    return (
        subprocess.check_output(
            ["git", "-c", "core.fsmonitor=false", *args], cwd=repo, timeout=30
        )
        .decode("utf-8", errors="strict")
        .strip()
    )


def check_source(repo, commit):
    if git_output(repo, "rev-parse", "--verify", "HEAD") != commit:
        raise PackagingError("HEAD does not equal the expected public Go commit")
    if git_output(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        raise PackagingError(
            "source has tracked or untracked changes; commit the reviewed public source first"
        )


def verify_executable(path, target, private_paths):
    size = regular(path).st_size
    with path.open("rb") as source:
        header = source.read(64)
        if target == "macos-arm64":
            if len(header) < 16 or struct.unpack_from("<II4xI", header) != (
                0xFEEDFACF,
                0x0100000C,
                2,
            ):
                raise PackagingError("macOS output is not an arm64 Mach-O executable")
        else:
            machine = 183 if target == "linux-arm64" else 62
            if (
                len(header) != 64
                or header[:6] != b"\x7fELF\x02\x01"
                or struct.unpack_from("<H", header, 18)[0] != machine
            ):
                raise PackagingError(
                    f"{target} output is not the expected ELF executable"
                )
            offset = struct.unpack_from("<Q", header, 32)[0]
            entry_size, count = struct.unpack_from("<HH", header, 54)
            if (
                struct.unpack_from("<H", header, 16)[0] not in (2, 3)
                or entry_size != 56
                or count > 4096
                or offset + count * entry_size > size
            ):
                raise PackagingError(f"{target} has invalid ELF program headers")
            source.seek(offset)
            for _ in range(count):
                if struct.unpack_from("<I", source.read(entry_size))[0] in (2, 3):
                    raise PackagingError(f"{target} is not fully static")
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if any(data.find(os.fsencode(item)) != -1 for item in private_paths):
                raise PackagingError(f"{target} executable contains an input path")


def write_archive(path, files):
    expected = {}
    with (
        path.open("xb") as raw,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive,
    ):
        for name, value in files.items():
            metadata = tarfile.TarInfo(name)
            metadata.mode = 0o755 if name == "ipsw" else 0o644
            metadata.mtime = metadata.uid = metadata.gid = 0
            metadata.uname = metadata.gname = ""
            metadata.size = regular(value).st_size
            expected[name] = metadata.tobuf(tarfile.USTAR_FORMAT), digest_file(value)
            with value.open("rb") as source:
                archive.addfile(metadata, source)
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != list(files):
            raise PackagingError("archive member list did not verify")
        for member in members:
            header, digest = expected[member.name]
            if member.pax_headers or member.tobuf(tarfile.USTAR_FORMAT) != header:
                raise PackagingError("archive metadata did not verify")
            with archive.extractfile(member) as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                    raise PackagingError(
                        f"archive content hash did not verify: {member.name}"
                    )


def guide_readme(path):
    regular(path, 16 * CHUNK)
    content = path.read_bytes()
    _, delimiter, body = content.partition(b"\n---\n")
    if not content.startswith(b"---\n") or not delimiter:
        raise PackagingError("offline IPA guide must start with delimited frontmatter")
    if any(line.startswith(b":::") for line in body.splitlines()):
        raise PackagingError("offline IPA guide ships as README.md; remove admonitions")
    return body.lstrip(b"\n")


def build_asset(args, files, target, archive_input, private_paths):
    goos, goarch, suffix, zig_target = TARGETS[target]
    archive, archive_sha = archive_input
    binary = files["ipsw"]
    if digest_file(archive) != archive_sha:
        raise PackagingError(f"{target} archive changed after preflight")
    build_env = os.environ.copy()
    build_env.update(
        GOOS=goos,
        GOARCH=goarch,
        CGO_ENABLED="1",
        IPSW_FP_VERSION=args.version,
        CC=f"zig cc -target {zig_target}" if zig_target else "clang",
        CXX=f"zig cc -target {zig_target}" if zig_target else "clang++",
    )
    command = ["sh", "hack/build-offline-ipa.sh", str(archive.parent), str(binary)]
    if zig_target:
        command.append("static")
    run_build(command, REPO, build_env)
    if digest_file(archive) != archive_sha:
        raise PackagingError("a manifest input changed during the build")
    verify_executable(binary, target, (*private_paths, archive, archive.parent))
    asset = binary.parent / f"ipsw_{args.version}_{suffix}_offline_ipa.tar.gz"
    write_archive(asset, files)
    binary.unlink()
    return asset, digest_file(asset)


def publish(assets, output):
    output.mkdir(mode=0o755)
    for source, expected in assets:
        destination = output / source.name
        with source.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, CHUNK)
        if digest_file(destination) != expected:
            raise PackagingError(
                f"published asset hash did not verify: {destination.name}"
            )


def package(args):
    # os.waitid, which supervises the build, reached macOS in Python 3.13.
    if sys.version_info < (3, 13):
        raise PackagingError("run this packager with Python 3.13 or newer")
    if not VERSION.fullmatch(args.version):
        raise PackagingError(
            "version must start with an alphanumeric and contain only letters, digits, . _ + - (maximum 128 characters)"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", args.public_commit):
        raise PackagingError(
            "public commit must be a full 40-character lowercase Git SHA"
        )
    repo = REPO
    manifest = Path(os.path.abspath(args.manifest))
    output = Path(os.path.abspath(args.output))
    if os.path.lexists(output):
        raise PackagingError("output already exists; choose a new directory")
    if not output.parent.is_dir():
        raise PackagingError("output parent directory must already exist")
    archives = read_manifest(manifest)
    check_source(repo, args.public_commit)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise PackagingError("run this packager natively on macOS arm64")
    for tool in ("go", "clang", "clang++", "zig"):
        if shutil.which(tool) is None:
            raise PackagingError(f"required tool is unavailable: {tool}")
    readme_text = guide_readme(repo / "www/docs/guides/offline-ipa.md")
    license_file = repo / "LICENSE"
    regular(license_file, 16 * CHUNK)
    # Stage outside the checkout so the final clean-source check sees no build output.
    with staging_directory() as stage:
        files = {
            "ipsw": stage / "ipsw",
            "README.md": stage / "README.md",
            "LICENSE": license_file,
        }
        files["README.md"].write_bytes(readme_text)
        private_paths = (repo, manifest)
        assets = [
            build_asset(args, files, target, archives[target], private_paths)
            for target in TARGETS
        ]
        check_source(repo, args.public_commit)
        checksums = stage / f"ipsw_{args.version}_offline_ipa_checksums.txt"
        checksums.write_text(
            "".join(f"{digest}  {asset.name}\n" for asset, digest in assets),
            encoding="ascii",
        )
        assets.append((checksums, digest_file(checksums)))
        publish(assets, output)
        print(output)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Manifest schema: {"archives": {"macos-arm64": {"path": ".../libipsw_fp.a", "sha256": "..."}, "linux-arm64": {...}, "linux-amd64": {...}}}. Relative paths are based on the manifest directory.',
    )
    parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="explicit JSON manifest of public release inputs",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="release version used in asset names and ipsw version output",
    )
    parser.add_argument(
        "--public-commit",
        required=True,
        help="reviewed public Go commit, full lowercase SHA",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new output directory under an existing parent",
    )
    args = parser.parse_args()
    try:
        package(args)
    except (
        PackagingError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        parser.exit(1, f"error: {error}\n")
    except KeyboardInterrupt:
        parser.exit(130, "error: interrupted\n")


if __name__ == "__main__":
    main()
