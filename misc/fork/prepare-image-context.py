"""Create a public, hash-addressed downstream build context; no credentials.

Uses pinned official runtime digests and exact Fork changes instead of rebuilding
unchanged Nginx/ModSecurity. Full feature acceptance is still required. The local LKG adaptation is included with explicit file hashes.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import re
import runpy
import os
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(output, wheelhouse, lkg):
    source = Path(__file__).resolve().parents[2]
    if (source / "src/VERSION").read_text().strip() != "1.6.17":
        raise RuntimeError("Update the pinned runtime baseline and regression plan before changing upstream versions")
    if output.exists():
        raise RuntimeError("Refuse overwriting an existing build snapshot")
    output.mkdir(mode=0o755, parents=True)
    shutil.copy2(source / "misc/fork/Dockerfile", output / "Dockerfile")
    for name in ("build-publish.py", "load-upstream-bases.py", "upstream-bases.lock.json"):
        shutil.copy2(source / "misc/fork" / name, output / name)
    shutil.copy2(source / "misc/fork/requirements-aliyun-overlay.txt", output / "requirements-aliyun-overlay.txt")
    shutil.copy2(source / "src/common/utils/alidns.py", output / "alidns.py")
    shutil.copytree(source / "src/common/core/letsencrypt", output / "letsencrypt", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (output / "lkg").mkdir()
    for name in ("guard.py", "start.py", "patch_api.py", "lkg_guard.lua"):
        path = lkg / name
        if path.is_symlink():
            raise RuntimeError("Refuse symlinked LKG source")
        shutil.copy2(path, output / "lkg" / name)
    allowed = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", (output / "requirements-aliyun-overlay.txt").read_text()))
    for artifact in wheelhouse.iterdir():
        if artifact.is_symlink() or not artifact.is_file() or digest(artifact) not in allowed:
            raise RuntimeError("Wheelhouse contains an artifact outside the hash lock")
    shutil.copytree(wheelhouse, output / "wheelhouse")
    # The separately installed plugin must be traceable to the same candidate.
    # It is hashed in the source manifest, without adding it to Worker layers.
    runpy.run_path(str(source / "misc/fork/package-dnsmanager.py"))["package"](output / "artifacts")
    hashes = {}
    for path in sorted(output.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("Build context cannot contain symlinks")
        if path.is_file():
            hashes[path.relative_to(output).as_posix()] = digest(path)
    tree = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=source, text=True).strip())
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip())
    manifest = {
        "upstream_version": "1.6.17",
        "git_head": revision,
        "dirty": dirty,
        "source_revision_label": f"uncommitted-{tree}" if dirty else revision,
        "source_tree_sha256": tree,
        "source_date_epoch": epoch,
        "files": hashes,
        "lkg_source": str(lkg.resolve()),
        "build_mode": "pinned-official-runtimes-with-fork-changes",
        "release_eligible": not dirty,
    }
    (output / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    # Git checkout times and local umasks must not change COPY inputs.
    for path in (output, *output.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (epoch, epoch))
    print(json.dumps({"context": str(output), "source_tree_sha256": tree, "dirty": dirty, "release_eligible": not dirty}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--lkg-source", type=Path, default=Path(__file__).resolve().parent / "lkg")
    args = parser.parse_args()
    prepare(args.output, args.wheelhouse, args.lkg_source)
