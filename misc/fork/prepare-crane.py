"""Install the pinned Linux/amd64 registry client into a private tools directory."""

import argparse
import hashlib
import io
import json
import os
import tarfile
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("destination", type=Path)
parser.add_argument("--archive", type=Path, help="Optional offline official release archive")
args = parser.parse_args()
expected = "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0"
binary_expected = "8e75c326adb43b053cfd78b9b987663f8f4fe4557f4d3915905643f25c730992"
url = "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz"
data = args.archive.read_bytes() if args.archive else urllib.request.urlopen(url, timeout=45).read(32 * 1024 * 1024)
assert hashlib.sha256(data).hexdigest() == expected, "Registry tool archive checksum mismatch"
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    member = archive.getmember("crane")
    assert member.isfile()
    binary = archive.extractfile(member).read()
assert hashlib.sha256(binary).hexdigest() == binary_expected, "Registry client binary checksum mismatch"
args.destination.mkdir(parents=True, mode=0o700, exist_ok=True)
target = args.destination / "crane-v0.22.1"
temporary = args.destination / ".crane-v0.22.1.pending"
temporary.write_bytes(binary)
temporary.chmod(0o700)
os.replace(temporary, target)
print(json.dumps({"installed": str(target), "version": "0.22.1", "archive_sha256": expected, "binary_sha256": binary_expected}))
