"""Report freshness policy (U16).

A signed report can be months old while HEAD is unchanged, so freshness is part of the
claim. `--max-age` turns that into an explicit policy (exit 2 when exceeded), and badges
show the scan age when the report records `meta.scanned_at`. Defaults stay unlimited for
compatibility.
"""
import re
import time

from .core import _trend_epoch

DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_max_age(text):
    """'30d', '12h', '45m', '90s', '2w' -> seconds. Raises ValueError for anything else."""
    m = DURATION_RE.fullmatch(str(text or "").strip())
    if not m:
        raise ValueError(f"invalid duration {text!r}: use e.g. 30d, 12h or 45m")
    return int(m.group(1)) * DURATION_SECONDS[m.group(2)]


def report_epoch(meta):
    """Epoch seconds from meta.scanned_at, or None for reports made before the field existed."""
    if not isinstance(meta, dict):
        return None
    value = meta.get("scanned_at")
    return _trend_epoch(value) if value else None


def age_seconds(meta, now=None):
    """Seconds since the report was scanned, or None when it has no timestamp."""
    epoch = report_epoch(meta)
    if epoch is None:
        return None
    now = time.time() if now is None else float(now)
    return max(0.0, now - epoch)


def human_age(seconds):
    """Compact age text ('40d', '3h', '12m', 'just now'); 'unknown' without a timestamp."""
    if seconds is None:
        return "unknown"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def stale(meta, max_age=None, now=None):
    """(stale, age, max_age). `stale` is True when the policy is set and the age is unknown or over it."""
    age = age_seconds(meta, now)
    if not max_age:
        return False, age, None
    if age is None or age > max_age:
        return True, age, max_age
    return False, age, max_age
