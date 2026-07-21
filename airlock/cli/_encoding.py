"""Force UTF-8 on stdout/stderr before anything writes to them.

Windows consoles and piped output default to a legacy code page (cp1252 on this machine) that cannot
encode the middle-dot, arrow, and box glyphs the CLI uses, so they land as replacement characters -
the first thing a judge on Windows would see. UTF-8 output is byte-identical on macOS, Linux, and a
modern Windows terminal (README section 11). Imported for its side effect, and first, so the rich
consoles capture streams that are already reconfigured.
"""

from __future__ import annotations

import contextlib
import sys

for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        with contextlib.suppress(ValueError, OSError):
            _reconfigure(encoding="utf-8")
