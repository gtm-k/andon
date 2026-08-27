#!/usr/bin/env python3
"""Derive the "what it measures" section of site/index.html from registry/*.toml.

Nothing in that section is hand-listed. Every family, metric count, claim tier and
`does_not_predict` line is read from the evidence registry, so the page cannot say
something the registry does not. Re-run after any registry change:

    python site/tools/registry-section.py            # print the fragment
    python site/tools/registry-section.py --splice   # rewrite it in place in index.html

The fragment lives between `<!-- registry:begin -->` and `<!-- registry:end -->`.
Python 3.11+ (tomllib), no third-party packages.
"""

from __future__ import annotations

import glob
import html
import os
import subprocess
import sys
import tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INDEX = os.path.join(ROOT, "site", "index.html")
BEGIN, END = "<!-- registry:begin -->", "<!-- registry:end -->"
TIERS = ("A", "B", "C", "D", "N")
TIER_WORDS = {
    "A": "validated against outcomes at scale",
    "B": "published validation, narrower population or weaker linkage",
    "C": "weak or contested on its own",
    "D": "critiqued; not to be used as a headline",
    "N": "novel and unvalidated — motivated by evidence, not yet supported by it",
}


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def load() -> list[dict]:
    files = []
    for path in sorted(glob.glob(os.path.join(ROOT, "registry", "*.toml"))):
        with open(path, "rb") as f:
            data = tomllib.load(f)
        files.append(
            {
                "name": os.path.basename(path),
                "engine": data["engine"],
                "family": data["family"],
                "metrics": data.get("metric", []),
                "claims": data.get("claim", []),
            }
        )
    return files


def head_oid() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "working tree"


def render(files: list[dict]) -> str:
    metric_total = sum(len(f["metrics"]) for f in files)
    claims = [c for f in files for c in f["claims"]]
    by_tier = {t: sum(1 for c in claims if c["tier"] == t) for t in TIERS}
    deterministic = sum(1 for f in files for m in f["metrics"] if m.get("deterministic"))
    out: list[str] = []
    out.append(f"{BEGIN}\n")
    out.append(
        f'<p class="derived">Derived from <code>registry/*.toml</code> at <code>{esc(head_oid())}</code>: '
        f"<strong>{metric_total} metrics</strong> in <strong>{len(files)} families</strong>, standing on "
        f"<strong>{len(claims)} claims</strong>. {deterministic} of the {metric_total} are deterministic and enter the "
        f"digest compare; the other {metric_total - deterministic} are reported and never compared.</p>\n"
    )
    # Tier ladder: one hue, darkest = strongest. Each segment carries its letter
    # and count, so the encoding is never colour alone. Drawn as SVG so the
    # widths are data, not inline styles.
    width, height, gap, zero_w = 1000, 60, 3, 44
    zero_tiers = sum(1 for t in TIERS if by_tier[t] == 0)
    free = width - gap * (len(TIERS) - 1) - zero_w * zero_tiers
    summary = ", ".join(f"{by_tier[t]} at tier {t}" for t in TIERS)
    out.append('<figure class="tiers" aria-labelledby="tiers-cap">\n')
    out.append(
        f'  <svg class="tier-svg" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Claims by evidence tier: {esc(summary)}." xmlns="http://www.w3.org/2000/svg">\n'
    )
    x = 0.0
    for t in TIERS:
        n = by_tier[t]
        w = zero_w if n == 0 else free * n / len(claims)
        out.append(
            f'    <rect class="seg tier-{t}" x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" rx="4"/>\n'
            f'    <text class="seg-letter tier-{t}-ink" x="{x + 12:.1f}" y="28">{t}</text>\n'
            f'    <text class="seg-count tier-{t}-ink" x="{x + 12:.1f}" y="46">{n}</text>\n'
        )
        x += w + gap
    out.append("  </svg>\n")
    out.append(
        '  <figcaption id="tiers-cap">Claims by evidence tier, A to N. '
        + " · ".join(f"<b>{t}</b> {esc(TIER_WORDS[t])}" for t in TIERS)
        + ". Tier N carries every tamper detector: they are calibrated on Andon's own corpus, not a study.</figcaption>\n"
    )
    out.append("</figure>\n")
    out.append('<ul class="families">\n')
    for f in files:
        tiers = sorted({c["tier"] for c in f["claims"]}, key=TIERS.index)
        det = sum(1 for m in f["metrics"] if m.get("deterministic"))
        first_claim = f["claims"][0]
        dnp = first_claim["does_not_predict"][0]
        chips = " ".join(f'<span class="tier-chip tier-{t}">{t}</span>' for t in tiers)
        tier_word = "tiers" if len(tiers) > 1 else "tier"
        out.append('  <li class="family">\n')
        out.append(
            f'    <h3><code>{esc(f["family"])}</code> <span class="engine">engine <code>{esc(f["engine"])}</code></span></h3>\n'
        )
        out.append(
            f'    <dl class="facts"><div><dt>metrics</dt><dd>{len(f["metrics"])}</dd></div>'
            f'<div><dt>claims</dt><dd>{len(f["claims"])}</dd></div>'
            f'<div><dt>{tier_word}</dt><dd>{chips}</dd></div>'
            f'<div><dt>compared</dt><dd>{det} of {len(f["metrics"])}</dd></div></dl>\n'
        )
        out.append(
            f'    <p class="dnp"><span class="dnp-label">does not predict</span> {esc(dnp)}</p>\n'
        )
        out.append(
            f'    <p class="claim-id"><code>{esc(first_claim["claim_id"])}</code></p>\n'
        )
        out.append("  </li>\n")
    out.append("</ul>\n")
    out.append(f"{END}")
    return "".join(out)


def main() -> int:
    fragment = render(load())
    if "--splice" in sys.argv:
        with open(INDEX, encoding="utf-8") as f:
            page = f.read()
        start, stop = page.index(BEGIN), page.index(END) + len(END)
        with open(INDEX, "w", encoding="utf-8", newline="\n") as f:
            f.write(page[:start] + fragment + page[stop:])
        print(f"spliced into {INDEX}")
    else:
        sys.stdout.write(fragment + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
