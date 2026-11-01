"""Private local settings; environment variables take precedence."""

import json
import os
from pathlib import Path
from clever_link.platform.resource_path import app_dir

BASE_DIR = Path(app_dir())
CONFIG_PATH = BASE_DIR / "config.json"


def load_settings():
    settings = {}
    if CONFIG_PATH.exists():
        try:
            settings = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            raise ValueError("config.json could not be read; check its JSON format.") from exc
        if not isinstance(settings, dict):
            raise ValueError("config.json must contain a JSON object.")
    result = {}
    for key, env_name in (("sheet_csv_url", "CLEVER_LINK_SHEET_CSV_URL"),
                          ("default_password", "CLEVER_LINK_DEFAULT_PASSWORD")):
        value = os.environ.get(env_name, settings.get(key, ""))
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string.")
        result[key] = value
    return result


_settings = load_settings()
SHEET_CSV_URL = _settings["sheet_csv_url"]
DEFAULT_PASSWORD = _settings["default_password"]
