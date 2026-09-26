"""
Approved exceptions to the partition pruning guard.

Keys are call sites as the guard reports them, without the line number:
``"apps/<app>/<module>.py::<function>"``. Values name each approved kind with
the reason it is safe. ``cross_org`` is meant to shrink to nothing; a
``cross_time`` entry should explain what bounds the scan instead (a LIMIT that
stops at the newest partition, a background job with no request fan-in, ...).
"""

ALLOWLIST: dict[str, dict[str, str]] = {}
