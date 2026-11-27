#!/usr/bin/env python3
"""Companion: measure-only stress metrics (wraps lab_stress_populate --measure-only)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("lab_stress_populate.py")


def main() -> int:
    cmd = [sys.executable, str(SCRIPT), "--measure-only", *sys.argv[1:]]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
