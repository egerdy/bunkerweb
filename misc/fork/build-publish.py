"""Build and publish pinned Fork components to an explicitly selected registry.

Source snapshots and dependency hashes are verified before publishing. Registry
credentials and output stay outside the source checkout. TLS is the default.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path


def validate_image_prefix(value):
    if (
        not isinstance(value, str)
        or len(value) > 255
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*", value)
    ):
        raise ValueError("Use a registry/namespace image prefix without credentials, scheme or tag")
    return value


def publish(context, auth, output, tag, candidate, crane, image_prefix, insecure=False):
    image_prefix = validate_image_prefix(image_prefix)
    manifest = json.loads((context / "source-manifest.json").read_text())
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != manifest["files"].get("build-publish.py"):
        raise RuntimeError("Run the snapshotted publisher from this verified build context")
    if manifest["dirty"] and not candidate:
        raise RuntimeError("Dirty source is not release eligible; explicitly select candidate mode")
    if manifest["dirty"] and "-snapshot-" not in tag:
        raise RuntimeError("Dirty candidates require a -snapshot- tag")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", tag) or tag == "latest":
        raise RuntimeError("Use an explicit version tag")
    for name, expected in manifest["files"].items():
        file = context / name
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Build snapshot failed its hash check")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = os.environ | {"DOCKER_CONFIG": str(auth)}
    lock_path = context / "upstream-bases.lock.json"
    lock = json.loads(lock_path.read_text())
    configured = dict(re.findall(r"^ARG (BASE_[A-Z]+)=(\S+)$", (context / "Dockerfile").read_text(), re.MULTILINE))
    if configured != {item["argument"]: item["mirror_reference"] for item in lock["bases"]}:
        raise RuntimeError("Dockerfile bases do not match the pinned runtime lock")
    spec = importlib.util.spec_from_file_location("pinned_base_loader", context / "load-upstream-bases.py")
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    bases = loader.restore(lock_path, crane, auth, output / "bases", insecure=insecure)
    (output / "base-identities.json").write_text(json.dumps(bases, indent=2) + "\n")
    targets = (("ui", "bunkerweb-ui"), ("scheduler", "bunkerweb-scheduler"), ("worker", "bunkerweb"))
    for component, repository in targets:
        if (output / f"{component}-metadata.json").exists():
            raise RuntimeError("Build metadata exists; reconcile the previous push before rebuilding")
        reference = f"{image_prefix}/{repository}:{tag}"
        existing = subprocess.run([str(crane), *(["--insecure"] if insecure else []), "digest", reference], env=environment, capture_output=True, text=True)
        if existing.returncode == 0:
            raise RuntimeError("Target tag already exists; never overwrite a published candidate or release")
        if not any(word in existing.stderr for word in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN", "404")):
            raise RuntimeError("Unable to prove target tag absent; refusing publication")
    results = []
    for component, repository in targets:
        reference = f"{image_prefix}/{repository}:{tag}"
        metadata = output / f"{component}-metadata.json"
        if metadata.exists():
            raise RuntimeError("Build metadata exists; reconcile the previous push before rebuilding")
        command = [
            "docker",
            "buildx",
            "build",
            "--pull=false",
            "--platform",
            "linux/amd64",
            "--provenance=false",
            "--sbom=false",
            "--target",
            component,
            "--metadata-file",
            str(metadata),
            "--build-arg",
            f"SOURCE_REVISION={manifest['source_revision_label']}",
            "--build-arg",
            f"SOURCE_TREE_SHA256={manifest['source_tree_sha256']}",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={manifest['source_date_epoch']}",
            "--output",
            f"type=image,name={reference},push=true" + (",registry.insecure=true" if insecure else ""),
            str(context),
        ]
        for base in bases:
            command[3:3] = ["--build-arg", f"{base['argument']}={base['local_alias']}"]
        subprocess.run(command, env=environment, check=True)
        for base in bases:
            actual = json.loads(subprocess.check_output(["docker", "image", "inspect", base["local_alias"]], env=environment, text=True))[0]
            if actual["Id"] != base["image_id"]:
                raise RuntimeError("Upstream alias changed during the build")
        data = json.loads(metadata.read_text())
        results.append({"component": component, "image": reference, "digest": data["containerimage.digest"]})
        (output / "release-manifest.json").write_text(
            json.dumps(
                {"source": manifest, "bases": bases, "publisher_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "images": results}, indent=2
            )
            + "\n"
        )
    print(json.dumps({"images": results, "release_eligible": manifest["release_eligible"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context", type=Path)
    parser.add_argument("--auth-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--image-prefix", required=True, type=validate_image_prefix, help="Registry/namespace, e.g. ghcr.io/your-org")
    parser.add_argument("--insecure", action="store_true", help="Explicitly allow HTTP registry transport")
    args = parser.parse_args()
    publish(args.context, args.auth_directory, args.output, args.tag, args.candidate, args.crane, args.image_prefix, args.insecure)
