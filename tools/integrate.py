#!/usr/bin/env python3
"""Check or apply the native keystore2 extension to its pinned AOSP checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COPIES = {
    "src/attestation_shim.rs": "keystore2/src/attestation_shim.rs",
    "src/attest_ext.cpp": "keystore2/ukeystore/attest_ext.cpp",
    "config/ukeystore-attest-targets.conf": "keystore2/ukeystore/ukeystore-attest-targets.conf",
    "config/ukeystore-profile.json": "keystore2/ukeystore/ukeystore-profile.json",
}


def git(tree, *args):
    return subprocess.check_output(["git", "-C", str(tree), *args], text=True).strip()


def verify_preimages(tree, base):
    for row in base["preimages"]:
        path = tree / row["path"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked source: " + row["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("Source hash mismatch: " + row["path"])


def verify_checkout(tree, base):
    if git(tree, "rev-parse", "--show-toplevel") != str(tree):
        raise ValueError("Expected the system/security repository root")
    if git(tree, "rev-parse", "HEAD") != base["commit"]:
        raise ValueError("system/security is not at the pinned public AOSP commit")
    if git(tree, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("The AOSP checkout must be clean")
    verify_preimages(tree, base)
    for relative in COPIES.values():
        path = tree / relative
        if path.exists() or path.is_symlink():
            raise ValueError("Refusing to overwrite: " + relative)
        for parent in path.parents:
            if parent == tree:
                break
            if parent.is_symlink():
                raise ValueError("Symlinked destination directory")


def integrate(tree, apply=False):
    tree = tree.resolve(strict=True)
    base = json.loads((ROOT / "aosp-base.json").read_text())
    verify_checkout(tree, base)
    patch = (ROOT / "patches/keystore2.patch").read_bytes()
    subprocess.run(["git", "-C", str(tree), "apply", "--check", "--whitespace=nowarn", "-"],
                   input=patch, check=True)
    if apply:
        subprocess.run(["git", "-C", str(tree), "apply", "--whitespace=nowarn", "-"],
                       input=patch, check=True)
        for source, relative in COPIES.items():
            target = tree / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)
    return {"applied": apply, "aosp_commit": base["commit"], "build_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-security", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(integrate(args.system_security, args.apply), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit("STOP: " + str(error))
