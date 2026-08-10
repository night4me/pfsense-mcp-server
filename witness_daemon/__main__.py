"""Enables `python -m witness_daemon` (Python's standard package
entrypoint convention) -- confirmed missing during real-hardware Phase 2
verification (2026-08-10): without this file, `python -m witness_daemon`
fails outright ("'witness_daemon' is a package and cannot be directly
executed"), even though every reference in this package's own docs
(`README.md`, `main.py`'s own docstring, the reference systemd unit)
already assumed it worked. `python -m witness_daemon.main` remains an
equally valid alternative -- this file makes the shorter, more
conventional form work too."""

from __future__ import annotations

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
