import importlib
import os
from pathlib import Path
import pkgutil
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from unittest.mock import patch
from urllib.parse import urlsplit, unquote

import clever_link
from clever_link.platform import resource_path

ROOT = Path(__file__).resolve().parents[1]


class References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ("src", "href") and value:
                self.paths.append(value)


class PathTests(unittest.TestCase):
    def test_import_every_module(self):
        for mod in pkgutil.walk_packages(clever_link.__path__, "clever_link."):
            importlib.import_module(mod.name)

    def test_ui_references_exist(self):
        for html in (ROOT / "clever_link/ui").glob("*.html"):
            parser = References()
            parser.feed(html.read_text(encoding="utf-8"))
            for value in parser.paths:
                url = urlsplit(value)
                if not url.scheme and url.path:
                    self.assertTrue((html.parent / unquote(url.path)).is_file(), value)

    def test_runtime_files_independent_of_cwd(self):
        with tempfile.TemporaryDirectory() as elsewhere:
            env = dict(os.environ, PYTHONPATH=str(ROOT))
            code = """
from pathlib import Path
from clever_link.config import CONFIG_PATH
from clever_link.profiles import PROFILE_FILE
from clever_link.connection.ssh_session import KNOWN_HOSTS_FILE
from clever_link.connection.mount_control import MOUNT_STATE_FILE
from clever_link.platform.resource_path import app_dir, resource_path
for file in [CONFIG_PATH, PROFILE_FILE, KNOWN_HOSTS_FILE, MOUNT_STATE_FILE]:
    assert Path(file).parent == Path(app_dir()), file
assert Path(resource_path('clever_link/ui/index.html')).is_file()
from clever_link.app import Api
assert Api().get_profiles() == []
"""
            # Empty private data avoids loading any real profiles or keyring secrets.
            env["CLEVER_LINK_DATA_DIR"] = elsewhere
            result = subprocess.run([sys.executable, "-B", "-c", code], cwd=elsewhere,
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_frozen_paths(self):
        with patch.object(sys, "_MEIPASS", str(ROOT), create=True):
            self.assertTrue(Path(resource_path.resource_path("clever_link/ui/terminal.html")).is_file())
        with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(ROOT / "Clever Link.exe")):
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(Path(resource_path.app_dir()), ROOT)

    def test_spec_paths_without_building(self):
        def analysis(scripts, **kwargs):
            self.assertTrue(all(Path(p).is_file() for p in scripts))
            self.assertTrue(all(Path(p).exists() for p, _ in kwargs["datas"]))
            self.assertEqual(kwargs["pathex"], [str(ROOT)])
            return type("Analysis", (), dict(pure=[], scripts=[], binaries=[], datas=[]))()

        def exe(*args, **kwargs):
            self.assertTrue(Path(kwargs["icon"]).is_file())
            return object()

        namespace = dict(SPECPATH=str(ROOT / "packaging"), Analysis=analysis,
                         PYZ=lambda *a: None, EXE=exe, COLLECT=lambda *a, **k: None)
        with patch.dict(os.environ, {}, clear=True):
            exec(compile((ROOT / "packaging/clever_link.spec").read_text(encoding="utf-8"), "spec", "exec"), namespace)


if __name__ == "__main__":
    unittest.main()
