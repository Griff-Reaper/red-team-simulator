# utils.py
"""
Shared utilities for the Red Team Simulator.

Keeps cross-cutting helpers (LLM-judge JSON parsing, lightweight logging) in one
place so the testing engines stay focused on orchestration.
"""

import json
import logging
import os
import sys
from typing import Optional


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so box-drawing/emoji output never crashes.

    Without this, any non-interactive run on Windows (CI logs, piped output, a
    redirect to a file) uses cp1252 and raises UnicodeEncodeError on the first
    '→' or emoji the TUI prints. ``errors='replace'`` is a final safety net.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


_force_utf8_streams()


def _configure_logger() -> logging.Logger:
    """Configure the shared 'redteam' logger once, driven by the environment.

    Level precedence: REDTEAM_LOG_LEVEL > (DEBUG if REDTEAM_DEBUG else WARNING).
    Diagnostics go to stderr so they never corrupt piped/redirected TUI output
    or generated JSON on stdout.
    """
    logger = logging.getLogger("redteam")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        )
        logger.addHandler(handler)
        logger.propagate = False

    level_name = os.getenv("REDTEAM_LOG_LEVEL") or (
        "DEBUG" if os.getenv("REDTEAM_DEBUG") else "WARNING"
    )
    logger.setLevel(getattr(logging, level_name.upper(), logging.WARNING))
    return logger


logger = _configure_logger()


def extract_json_object(text: str) -> Optional[dict]:
    """Robustly extract the first JSON object from an LLM response.

    LLM judges are instructed to return raw JSON, but in practice they wrap it in
    ```json fences, add a preamble ("Here is the evaluation:"), or append trailing
    prose. This scanner ignores all of that: it finds the first balanced ``{...}``
    object, respecting braces inside string literals and escape sequences.

    Returns the parsed dict, or ``None`` if no valid JSON object is found.
    """
    if not text:
        return None

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    # Malformed first object — bail rather than guess further.
                    return None

    return None


def log(message: str, level: str = "INFO") -> None:
    """Emit a diagnostic through the shared 'redteam' logger.

    Interactive UI output stays on ``print``; this is for diagnostics. Levels
    map to stdlib logging (default threshold WARNING, so INFO is hidden unless
    REDTEAM_DEBUG / REDTEAM_LOG_LEVEL lowers it; ERROR always shows).
    """
    logger.log(getattr(logging, level.upper(), logging.INFO), message)
