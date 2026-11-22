#!/usr/bin/env python3
"""
Build Artifact Verifier
-----------------------
A simple DevSecOps tool that proves build artifacts were not tampered with
between the build stage and the deploy stage.

Workflow:
  1. generate : hash every file in an artifact directory (SHA-256), write a
                manifest, and sign the manifest with HMAC-SHA256.
  2. verify   : re-hash the directory and compare against the manifest.
                Reports modified, missing, and unexpected files, and checks
                the manifest signature.

The signing key is read from the ARTIFACT_SIGNING_KEY environment variable
(never pass keys on the command line or commit them to the repo).

Usage:
  export ARTIFACT_SIGNING_KEY="a-long-random-secret"
  python build_artifact_verifier.py generate ./dist -o manifest.json
  python build_artifact_verifier.py verify   ./dist -m manifest.json

Exit codes: 0 = verified, 1 = verification failed, 2 = usage/config error.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_VERSION = 1
CHUNK_SIZE = 1024 * 1024  # 1 MiB


# --------------------------------------------------------------------------
# Hashing and signing helpers
# --------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_hashes(root: Path, exclude: set) -> dict:
    """Map relative POSIX path -> SHA-256 for every file under root."""
    hashes = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in exclude:
            continue
        hashes[rel] = sha256_file(path)
    return hashes


def get_key() -> bytes:
    key = os.environ.get("ARTIFACT_SIGNING_KEY")
    if not key:
        raise SystemExit(
            "error: set the ARTIFACT_SIGNING_KEY environment variable first"
        )
    return key.encode("utf-8")


def sign(payload: dict, key: bytes) -> str:
    """HMAC-SHA256 over a canonical JSON encoding of the payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_generate(args) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    key = get_key()
    out_path = Path(args.output)
    exclude = set()
    try:  # don't hash the manifest itself if it lives inside the directory
        exclude.add(out_path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        pass

    payload = {
        "version": MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "files": collect_hashes(root, exclude),
    }
    manifest = {"payload": payload, "signature": sign(payload, key)}
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Manifest written to {out_path} ({len(payload['files'])} files)")
    return 0


def cmd_verify(args) -> int:
    root = Path(args.directory)
    manifest_path = Path(args.manifest)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    if not manifest_path.is_file():
        print(f"error: manifest {manifest_path} not found", file=sys.stderr)
        return 2

    key = get_key()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload = manifest["payload"]
        signature = manifest["signature"]
        expected = payload["files"]
    except (json.JSONDecodeError, KeyError, TypeError):
        print("error: manifest is malformed", file=sys.stderr)
        return 2

    problems = []

    # 1. Manifest integrity (constant-time comparison)
    if not hmac.compare_digest(signature, sign(payload, key)):
        problems.append("INVALID SIGNATURE: manifest was altered or key is wrong")

    # 2. Artifact integrity
    exclude = set()
    try:
        exclude.add(manifest_path.resolve().relative_to(root.resolve()).as_posix())
    except ValueError:
        pass
    actual = collect_hashes(root, exclude)

    for name in sorted(expected.keys() - actual.keys()):
        problems.append(f"MISSING:    {name}")
    for name in sorted(actual.keys() - expected.keys()):
        problems.append(f"UNEXPECTED: {name}")
    for name in sorted(expected.keys() & actual.keys()):
        if not hmac.compare_digest(expected[name], actual[name]):
            problems.append(f"MODIFIED:   {name}")

    if problems:
        print("VERIFICATION FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"VERIFIED: {len(actual)} files match the signed manifest")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and verify signed manifests for build artifacts."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="hash artifacts and sign a manifest")
    gen.add_argument("directory", help="artifact directory, e.g. ./dist")
    gen.add_argument("-o", "--output", default="manifest.json")
    gen.set_defaults(func=cmd_generate)

    ver = sub.add_parser("verify", help="verify artifacts against a manifest")
    ver.add_argument("directory", help="artifact directory, e.g. ./dist")
    ver.add_argument("-m", "--manifest", default="manifest.json")
    ver.set_defaults(func=cmd_verify)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
