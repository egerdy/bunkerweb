"""Preserve exact cached upstream runtimes in an explicit registry namespace.

Exports only identities pinned in an earlier candidate manifest. A changed
registry manifest representation is allowed; its config digest (including all
runtime settings and filesystem diff IDs) must match the original save archive.
Existing mirror tags are read and verified, never overwritten.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--candidate-manifest", required=True, type=Path)
parser.add_argument("--crane", required=True, type=Path)
parser.add_argument("--auth-directory", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--image-prefix", required=True)
parser.add_argument("--insecure", action="store_true")
args = parser.parse_args()
import runpy

runpy.run_path(str(Path(__file__).with_name("build-publish.py")))["validate_image_prefix"](args.image_prefix)
environment = os.environ | {"DOCKER_CONFIG": str(args.auth_directory), "GOMAXPROCS": "2", "GOMEMLIMIT": "192MiB"}
version = subprocess.check_output([str(args.crane), "version"], text=True).strip()
assert version == "0.22.1", "Use the verified crane version"
args.output.mkdir(parents=True, mode=0o700, exist_ok=True)
bases = json.loads(args.candidate_manifest.read_text())["bases"]
records = []


def crane(*command, check=True):
    return subprocess.run([str(args.crane), *(["--insecure"] if args.insecure else []), *command], env=environment, capture_output=True, text=True, check=check)


for base in bases:
    reference = base.get("upstream_reference", base.get("original_reference"))
    digest = reference.rsplit("@", 1)[1]
    component = base["argument"].removeprefix("BASE_").lower()
    original = json.loads(subprocess.check_output(["docker", "image", "inspect", reference]))[0]
    assert original["Id"] == digest or reference in original.get("RepoDigests", []), "Unexpected upstream identity"
    archive_path = args.output / f"upstream-{component}.tar"
    if not archive_path.exists():
        subprocess.run(["docker", "image", "save", "--output", str(archive_path), base["local_alias"]], check=True)
    with tarfile.open(archive_path) as archive:
        index = json.load(archive.extractfile("manifest.json"))
        assert len(index) == 1, "Expected exactly one upstream image"
        config_bytes = archive.extractfile(index[0]["Config"]).read()
    config = json.loads(config_bytes)
    assert config["rootfs"]["diff_ids"] == original["RootFS"]["Layers"], "Upstream filesystem changed"
    assert all(original["Config"].get(key) == value for key, value in config["config"].items()), "Upstream runtime config changed"
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    target = f"{args.image_prefix}/bunkerweb-upstream-{component}:1.6.17-{digest[7:19]}"
    existing = crane("digest", target, check=False)
    if existing.returncode:
        assert any(word in existing.stderr for word in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN", "404")), "Registry check failed; do not assume absence"
        # Repeating after a partial push first checks the existing manifest.
        crane("push", str(archive_path), target)
    mirrored_digest = crane("digest", target).stdout.strip()
    manifest = json.loads(crane("manifest", target + "@" + mirrored_digest).stdout)
    assert manifest["config"]["digest"] == config_digest, "Mirror does not preserve the original config"
    records.append(
        {
            "argument": base["argument"],
            "upstream_reference": reference,
            "mirror_reference": target.rsplit(":", 1)[0] + "@" + mirrored_digest,
            "config_digest": config_digest,
            "rootfs_diff_ids": config["rootfs"]["diff_ids"],
            "local_archive": str(archive_path),
        }
    )
    (args.output / "upstream-bases.lock.json").write_text(json.dumps({"crane_version": version, "bases": records}, indent=2) + "\n")
    print(json.dumps({"component": component, "mirror": records[-1]["mirror_reference"], "config_preserved": True}), flush=True)
