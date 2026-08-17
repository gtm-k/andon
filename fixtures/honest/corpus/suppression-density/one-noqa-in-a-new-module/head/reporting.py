"""Reporting helpers."""

from invoice import subtotal  # noqa: F401  (re-exported for the CLI)


def summarize(lines):
    return {"lines": len(lines), "total": subtotal(lines)}
