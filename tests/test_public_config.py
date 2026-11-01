import ast
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from clever_link import config as app_config


class PublicConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config_path = Path(self.temp.name) / "config.json"

    def settings(self):
        with patch.object(app_config, "CONFIG_PATH", self.config_path):
            with patch.dict(os.environ, {}, clear=True):
                return app_config.load_settings()

    def test_missing_settings_are_empty(self):
        self.assertEqual(self.settings(), {"sheet_csv_url": "", "default_password": ""})

    def test_local_settings(self):
        self.config_path.write_text(json.dumps({"sheet_csv_url": "https://example.invalid/data.csv"}), encoding="utf-8")
        self.assertEqual(self.settings()["sheet_csv_url"], "https://example.invalid/data.csv")

    def test_environment_overrides_file(self):
        self.config_path.write_text('{"default_password":"fake-local"}', encoding="utf-8")
        with patch.object(app_config, "CONFIG_PATH", self.config_path):
            with patch.dict(os.environ, {"CLEVER_LINK_DEFAULT_PASSWORD": "fake-env"}, clear=True):
                self.assertEqual(app_config.load_settings()["default_password"], "fake-env")

    def test_invalid_settings_rejected(self):
        for text in ("{", "[]", '{"default_password":123}'):
            self.config_path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                self.settings()

    def test_sheet_without_url_does_not_call_network(self):
        sheet = importlib.import_module("clever_link.sheets.sheet_sync")
        with patch.object(sheet, "SHEET_CSV_URL", ""), patch.object(sheet.urllib.request, "urlopen") as request:
            with self.assertRaisesRegex(ValueError, "config.json"):
                sheet.fetch_sheet_rows()
            request.assert_not_called()

    def test_all_python_sources_parse(self):
        for file in (Path(__file__).resolve().parents[1] / "clever_link").rglob("*.py"):
            ast.parse(file.read_text(encoding="utf-8-sig"), filename=str(file))


if __name__ == "__main__":
    unittest.main()
