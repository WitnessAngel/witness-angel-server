#!/usr/bin/env python
"""Special version of django management command launcher, for embedding in PyInstaller-generated executable file."""

import os
import sys

def main():
    print("WITNESS ANGEL ESCROW PROD RUNNER STARTED")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "waescrow.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
