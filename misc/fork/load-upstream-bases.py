"""Restore pinned runtime bases without changing Docker daemon configuration."""

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import io
from pathlib import Path


def exported_config(path):
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile("manifest.json"))
        assert len(index) == 1, "Expected one base image"
        raw = archive.extractfile(index[0]["Config"]).read()
        return "sha256:" + hashlib.sha256(raw).hexdigest(), json.loads(raw)


def restore(lock_path, crane_path, auth, output, insecure=False):
    lock = json.loads(lock_path.read_text())
    assert hashlib.sha256(crane_path.read_bytes()).hexdigest() == lock["crane_binary_sha256"], "Unverified registry client"
    environment = os.environ | {"DOCKER_CONFIG": str(auth), "GOMAXPROCS": "2", "GOMEMLIMIT": "192MiB"}
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    records = []
    for base in lock["bases"]:
        component = base["argument"].removeprefix("BASE_").lower()
        alias = f"bunkerweb-pinned-{component}:config-{base['config_digest'][7:19]}"
        existing = subprocess.run(["docker", "image", "inspect", alias], capture_output=True)
        verification = output / f"{component}-verify.tar"
        if existing.returncode:
            downloaded = output / f"{component}-download.tar"
            subprocess.run(
                [str(crane_path), *(["--insecure"] if insecure else []), "pull", "--format=tarball", base["mirror_reference"], str(downloaded)],
                env=environment,
                check=True,
            )
            actual, config = exported_config(downloaded)
            assert actual == base["config_digest"] and config["rootfs"]["diff_ids"] == base["rootfs_diff_ids"], "Mirror content mismatch"
            imported = output / f"{component}-import.tar"
            # Only our private alias is imported; registry or upstream tags in
            # the archive cannot replace other applications' local image tags.
            with tarfile.open(downloaded) as source, tarfile.open(imported, "w") as destination:
                for member in source:
                    if member.name == "manifest.json":
                        index = json.load(source.extractfile(member))
                        index[0]["RepoTags"] = [alias]
                        content = json.dumps(index).encode()
                        member.size = len(content)
                        destination.addfile(member, io.BytesIO(content))
                    else:
                        destination.addfile(member, source.extractfile(member) if member.isfile() else None)
            subprocess.run(["docker", "image", "load", "--input", str(imported)], check=True)
        # Independently read Docker's imported image, not just a local marker.
        subprocess.run(["docker", "image", "save", "--output", str(verification), alias], check=True)
        actual, config = exported_config(verification)
        assert actual == base["config_digest"] and config["rootfs"]["diff_ids"] == base["rootfs_diff_ids"], "Imported base identity mismatch"
        image = json.loads(subprocess.check_output(["docker", "image", "inspect", alias]))[0]
        records.append({**base, "local_alias": alias, "image_id": image["Id"], "config_verified": True})
        print(json.dumps({"base_restored": component, "mirror": base["mirror_reference"], "config_verified": True}), flush=True)
    (output / "restored-bases.json").write_text(json.dumps(records, indent=2) + "\n")
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--auth-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--insecure", action="store_true", help="Explicitly allow HTTP registry transport")
    args = parser.parse_args()
    restore(args.lock, args.crane, args.auth_directory, args.output, args.insecure)
