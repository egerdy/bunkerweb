"""Build a deterministic DNS plugin ZIP, excluding state and secret files."""

import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


def package(destination):
    root = Path(__file__).resolve().parents[2] / "misc/plugins/dnsmanager"
    metadata = json.loads((root / "plugin.json").read_text())
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"dnsmanager-{metadata['version']}.zip"
    allowed = {".json", ".py", ".html", ".js", ".css"}
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError("Plugin packages must not contain symlinks")
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            relative = path.relative_to(root)
            if str(relative) == "README.md":
                continue
            if path.suffix not in allowed or (str(relative) != "plugin.json" and not str(relative).startswith("ui/")):
                raise ValueError(f"Unexpected file in plugin source: {relative}")
            member = ZipInfo(relative.as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            member.external_attr = 0o100644 << 16
            member.compress_type = ZIP_DEFLATED
            archive.writestr(member, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".zip.sha256").write_text(f"{digest}  {output.name}\n")
    print(json.dumps({"file": str(output), "sha256": digest, "version": metadata["version"]}))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python misc/fork/package-dnsmanager.py OUTPUT_DIRECTORY")
    package(Path(sys.argv[1]))
