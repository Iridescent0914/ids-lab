"""Verify packaged LightIDS resource paths without opening the GUI."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_ROOT = PROJECT_ROOT / "dist" / "LightIDS"
INTERNAL_ROOT = DIST_ROOT / "_internal"

sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    sys.frozen = True
    sys._MEIPASS = str(INTERNAL_ROOT)
    sys.executable = str(DIST_ROOT / "LightIDS.exe")

    from app.main import bootstrap, resource_root, runtime_root

    config, _database = bootstrap(resource_root())

    print(f"resource_root={resource_root()}")
    print(f"runtime_root={runtime_root()}")
    print(f"rules={config.default_rules_path}")
    print(f"rules_exists={config.default_rules_path.exists()}")

    if not config.default_rules_path.exists():
        raise FileNotFoundError(config.default_rules_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
