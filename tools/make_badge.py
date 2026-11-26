#!/usr/bin/env python3
"""Turn a repobeagle --json report into README badge files.

  python3 tools/make_badge.py beagle.json --endpoint badge.json --svg badge.svg --link URL

The endpoint JSON renders with shields.io:
  https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/repobeagle/badge.json
The SVG is a tiny self-hosted fallback for people who do not want shields.io.
Colors follow the verdict: GREEN brightgreen, YELLOW yellow, RED red.
Stdlib only.
"""
import argparse
import json
import sys

COLORS = {"GREEN": "brightgreen", "YELLOW": "yellow", "RED": "red"}
HEXES = {"GREEN": "#4c1", "YELLOW": "#dfb317", "RED": "#cb2431"}
FALLBACK = ("lightgrey", "#9f9f9f")
CHAR_W = 6.5          # approx Verdana 11px advance width per char
PAD = 10              # horizontal padding per side, one side


def _text_w(s):
    return round(len(s) * CHAR_W) + PAD


def _color(verdict):
    return COLORS.get(verdict, FALLBACK[0]), HEXES.get(verdict, FALLBACK[1])


def endpoint_json(verdict, label, link, privacy=None, privacy_only=False, scope=None, partial=False):
    color, _ = _color(verdict)
    d = {"schemaVersion": 1, "label": label, "message": f"{verdict} (partial)" if partial else verdict, "color": color}
    if partial:
        d["complete"] = False
    if link:
        d["link"] = link
    if privacy_only:
        d["privacy_only"] = True      # verdict covers privacy/telemetry findings only
    if privacy:
        d["privacy"] = privacy
    if scope:
        d["scope"] = {"mode": "changed", "since": scope.get("since"),
                      "changed_files": scope.get("changed_files")}   # diff verdict, not a full-repo one
    return json.dumps(d, indent=2) + "\n"


def privacy_counts(report):
    """Counts from the report's privacy_summary; extra keys are ignored by shields.io but useful to API consumers."""
    summary = report.get("privacy_summary") or {}
    out = {}
    for group, vals in summary.items():
        n = sum(len(v) for v in vals.values()) if isinstance(vals, dict) else len(vals)
        if n:
            out[group] = n
    return out


def svg(verdict, label, partial=False):
    """Flat-style two-cell badge (label + verdict), no external deps."""
    if partial:
        verdict = f"{verdict} (partial)"
    color_name, hexcolor = _color(verdict)
    lw, vw = _text_w(label), _text_w(verdict)
    total = lw + vw
    mid = lw + vw / 2
    # Reason: text sits at the center of each cell, baseline y=14 for 11px type.
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {verdict}">'.format(
            w=total, label=label, verdict=verdict),
        "<title>{label}: {verdict}</title>".format(label=label, verdict=verdict),
        '<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'.format(w=total),
        '<g clip-path="url(#r)">',
        '<rect width="{lw}" height="20" fill="#555"/>'.format(lw=lw),
        '<rect x="{lw}" width="{vw}" height="20" fill="{hex}"/>'.format(lw=lw, vw=vw, hex=hexcolor),
        "</g>",
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">',
        '<text x="{x}" y="14" fill="#010101" fill-opacity=".3">{label}</text>'.format(x=lw // 2 + 1, label=label),
        '<text x="{x}" y="14">{label}</text>'.format(x=lw // 2, label=label),
        '<text x="{x}" y="14" fill="#010101" fill-opacity=".3">{verdict}</text>'.format(x=mid + 1, verdict=verdict),
        '<text x="{x}" y="14">{verdict}</text>'.format(x=mid, verdict=verdict),
        "</g>",
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


def main():
    ap = argparse.ArgumentParser(description="repobeagle report -> badge files")
    ap.add_argument("report", help="repobeagle --json output")
    ap.add_argument("--endpoint", help="write shields.io endpoint JSON here")
    ap.add_argument("--svg", help="write a self-hosted SVG badge here")
    ap.add_argument("--label", default="repobeagle")
    ap.add_argument("--link", default="", help="URL opened when the badge is clicked")
    a = ap.parse_args()
    try:
        with open(a.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as ex:
        print(f"make_badge: cannot read report {a.report}: {ex}", file=sys.stderr)
        return 1
    verdict = report.get("verdict")
    if verdict not in COLORS:
        print(f"make_badge: unexpected verdict {verdict!r} in {a.report}", file=sys.stderr)
        return 1
    partial = (report.get("meta") or {}).get("complete") is False
    out = False
    privacy = privacy_counts(report)
    privacy_only = (report.get("meta") or {}).get("privacy_mode") == "only"
    scope = (report.get("meta") or {}).get("scope")
    if a.endpoint:
        with open(a.endpoint, "w", encoding="utf-8") as fh:
            fh.write(endpoint_json(verdict, a.label, a.link, privacy, privacy_only, scope, partial))
        out = True
    if a.svg:
        with open(a.svg, "w", encoding="utf-8") as fh:
            fh.write(svg(verdict, a.label, partial))
        out = True
    if not out:
        print(verdict)  # no files requested: print the verdict for scripts
    return 0


if __name__ == "__main__":
    sys.exit(main())
