"""Public build tools require an explicit registry namespace and secure transport."""

import importlib.util
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fork_publish", ROOT / "misc/fork/build-publish.py")
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


class PublisherTests(unittest.TestCase):
    def test_image_prefix_requires_namespace_without_credentials_or_scheme(self):
        for value in ("ghcr.io/example", "registry.example.com:5443/project", "registry.example.com/org/subgroup"):
            self.assertEqual(PUBLISHER.validate_image_prefix(value), value)
        for value in (
            "",
            "https://registry.example.com/project",
            "user:password@registry.example.com/project",
            "registry.example.com",
            "registry.example.com/project:tag",
            "registry.example.com/project;echo",
            "registry.example.com/../project",
        ):
            with self.assertRaises(ValueError):
                PUBLISHER.validate_image_prefix(value)

    def test_existing_tag_check_uses_selected_namespace_and_tls_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publisher = Path(PUBLISHER.__file__)
            manifest = {"files": {"build-publish.py": hashlib.sha256(publisher.read_bytes()).hexdigest()}, "dirty": False}
            (root / "build-publish.py").write_bytes(publisher.read_bytes())
            (root / "source-manifest.json").write_text(json.dumps(manifest))
            (root / "upstream-bases.lock.json").write_text(json.dumps({"bases": []}))
            (root / "Dockerfile").write_text("")
            with patch.object(PUBLISHER.importlib.util, "spec_from_file_location"), patch.object(
                PUBLISHER.importlib.util, "module_from_spec", return_value=Mock(restore=Mock(return_value=[]))
            ), patch.object(PUBLISHER.subprocess, "run", return_value=Mock(returncode=0)) as command:
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    PUBLISHER.publish(root, root / "auth", root / "output", "1.6.17-fork.1", False, root / "crane", "registry.example.com/test")
                args = command.call_args.args[0]
                self.assertNotIn("--insecure", args)
                self.assertEqual(args[-1], "registry.example.com/test/bunkerweb-ui:1.6.17-fork.1")
