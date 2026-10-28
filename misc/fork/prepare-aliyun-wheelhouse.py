"""Fetch hash-locked CPython 3.14 / musllinux x86_64 compatibility artifacts.

This prepares public dependency files only. It does not build, push or deploy an
image. The original sdist is kept when no compatible wheel exists, so pip can
still verify the upstream source hash rather than trusting a locally built wheel.
"""

import argparse
import hashlib
import re
from pathlib import Path

import requests


def artifact_rank(artifact):
    name = artifact["filename"]
    if artifact["packagetype"] == "bdist_wheel":
        if name.endswith(("-py3-none-any.whl", "-py2.py3-none-any.whl")):
            return 0
        if name.endswith("-cp314-cp314-musllinux_1_2_x86_64.whl"):
            return 1
        return 10
    return 2 if artifact["packagetype"] == "sdist" else 10


def prepare(requirements, destination):
    destination.mkdir(parents=True, exist_ok=True)
    text = requirements.read_text()
    blocks = re.split(r"(?=^[A-Za-z0-9][A-Za-z0-9_-]*==)", text, flags=re.MULTILINE)
    session = requests.Session()
    for block in blocks:
        match = re.match(r"([A-Za-z0-9_-]+)==([^\s\\]+)", block)
        if not match:
            continue
        name, version = match.groups()
        allowed = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", block))
        response = session.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=(10, 30))
        response.raise_for_status()
        candidates = sorted(response.json()["urls"], key=artifact_rank)
        artifact = next((item for item in candidates if artifact_rank(item) < 10 and item["digests"]["sha256"] in allowed), None)
        if artifact is None:
            raise RuntimeError(f"No hash-locked artifact for {name}=={version}")
        filename = artifact["filename"]
        if Path(filename).name != filename:
            raise RuntimeError("Invalid artifact filename")
        target = destination / filename
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() in allowed:
            print(f"verified {filename}", flush=True)
            continue
        url = artifact["url"]
        if not url.startswith("https://files.pythonhosted.org/"):
            raise RuntimeError("Unexpected artifact host")
        downloaded = session.get(url, timeout=(10, 60))
        downloaded.raise_for_status()
        if hashlib.sha256(downloaded.content).hexdigest() not in allowed:
            raise RuntimeError(f"Hash mismatch for {filename}")
        target.write_bytes(downloaded.content)
        print(f"downloaded {filename}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    prepare(Path(__file__).with_name("requirements-aliyun-overlay.txt"), args.destination)
