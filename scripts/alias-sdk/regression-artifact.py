#!/usr/bin/env python3
"""Create/verify build-only CI delivery. This is not release qualification."""

import argparse
import hashlib
import json
import pathlib
import re
import tarfile
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_payload(payload, platform, source):
    if platform == "typescript":
        with tarfile.open(payload, "r:gz") as archive:
            names = set()
            for member in archive.getmembers():
                parts = pathlib.PurePosixPath(member.name).parts
                require(
                    parts and parts[0] == "package" and ".." not in parts
                    and "node_modules" not in parts
                    and member.name.rstrip("/") == str(pathlib.PurePosixPath(member.name))
                    and "\\" not in member.name and not member.name.startswith("/")
                    and (member.isfile() or member.isdir()) and member.name not in names,
                    "Unsafe or duplicate npm archive entry",
                )
                names.add(member.name)
            require(archive.extractfile("package/VERSION").read().decode().strip() == source,
                    "npm payload source mismatch")
            package = json.load(archive.extractfile("package/package.json"))
            require(package["name"] == "@bitwarden/sdk-internal"
                    and package["license"] == "GPL-3.0-only", "Expected the OSS SDK package")
            require(isinstance(package["version"], str) and package["version"],
                    "Expected a package version")
            return package["version"]
    with zipfile.ZipFile(payload) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate AAR entry")
        for name in names:
            parts = pathlib.PurePosixPath(name).parts
            require(parts and not name.startswith("/") and ".." not in parts
                    and name.rstrip("/") == str(pathlib.PurePosixPath(name))
                    and "\\" not in name, "Unsafe AAR entry")
        for name in ["classes.jar"] + [
            f"jni/{abi}/libbitwarden_uniffi.so"
            for abi in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        ]:
            require(archive.getinfo(name).file_size > 0, f"Missing AAR content: {name}")
    return None


def identity(directory, platform, source):
    require(re.fullmatch(r"[0-9a-f]{40}", source), "Expected an immutable source SHA")
    name = "sdk.tgz" if platform == "typescript" else "sdk.aar"
    payload = directory / name
    require(payload.is_file() and not payload.is_symlink(), "Missing regular payload")
    version = inspect_payload(payload, platform, source)
    return {
        "schemaVersion": 1,
        "purpose": "regression-build-only",
        "securityQualified": False,
        "platform": platform,
        "sourceCommit": source,
        "packageVersion": version,
        "file": name,
        "bytes": payload.stat().st_size,
        "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
    }


def verify(directory, platform, source):
    manifest = directory / "BUILD-ONLY.json"
    require(manifest.is_file() and not manifest.is_symlink(), "Missing regular manifest")
    observed = json.loads(manifest.read_text())
    expected = identity(directory, platform, source)
    # Comparing canonical JSON also rejects bools substituted for integer fields.
    require(json.dumps(observed, sort_keys=True) == json.dumps(expected, sort_keys=True),
            "Build manifest, checksum, or source mismatch")
    require({p.name for p in directory.iterdir()} == {"BUILD-ONLY.json", expected["file"]},
            "Unexpected build delivery content")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "verify", "extract"))
    parser.add_argument("platform", choices=("typescript", "android"))
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("source")
    parser.add_argument("destination", type=pathlib.Path, nargs="?")
    args = parser.parse_args()
    if args.operation == "create":
        manifest = identity(args.directory, args.platform, args.source)
        require(not (args.directory / "BUILD-ONLY.json").exists(), "Manifest already exists")
        (args.directory / "BUILD-ONLY.json").write_text(json.dumps(manifest, indent=2) + "\n")
    manifest = verify(args.directory, args.platform, args.source)
    if args.operation == "extract":
        require(args.platform == "typescript" and args.destination is not None,
                "Extraction requires an npm destination")
        args.destination.mkdir(parents=True, exist_ok=False)
        with tarfile.open(args.directory / manifest["file"], "r:gz") as archive:
            # inspect_payload has rejected all links and non-package paths.
            archive.extractall(args.destination, filter="data")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
