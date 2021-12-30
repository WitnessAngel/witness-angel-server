#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import pathlib
import sys

executable_is_frozen = getattr(sys, "frozen", False)

if not executable_is_frozen:
    # Ensure application code is importable
    root_dir = pathlib.Path(__file__).resolve().parents[0]
    assert (root_dir / "manage.py").exists(), root_dir / "manage.py"
    sys.path.append(str(root_dir / "src"))


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "watrustee.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
