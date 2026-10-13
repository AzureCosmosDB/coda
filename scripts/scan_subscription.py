"""Scan a subscription's Cosmos accounts with CODA (breadth-first, the customer "one-shot" entry).

Thin CLI over :func:`coda_core.scan.scan` — the same core the MCP server will call. Scope is just a
filter: no filter scans the whole subscription; ``--resource-groups`` / ``--accounts`` narrow it; use
``scripts/diagnose.py`` to drill into a single account in depth.

  uv run python scripts/scan_subscription.py                          # whole subscription
  uv run python scripts/scan_subscription.py --resource-groups rg1,rg2
  uv run python scripts/scan_subscription.py --concurrency 12 --timeout 90 --out-dir docs/evidence/fleet-scan

Output (per-account JSON + summary) is written to ``--out-dir`` and contains real account/db/container
names — keep it local (it is gitignored under docs/evidence/fleet-scan/).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser

from azure.identity import DefaultAzureCredential

from coda_core.feedback import feedback_block, new_issue_url
from coda_core.redact import redact_scan
from coda_core.scan import scan, shallow_scan
from coda_core.selfupdate import auto_update, run_update_command

DEFAULT_SUBSCRIPTION = os.environ.get("CODA_SUBSCRIPTION")


def _csv(value: str | None) -> list[str] | None:
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def main() -> None:
    # `--update` must work standalone (before argparse enforces required args).
    if "--update" in sys.argv[1:]:
        sys.exit(run_update_command())
    p = argparse.ArgumentParser(description="Scan a subscription's Cosmos accounts with CODA.")
    p.add_argument("--subscription", default=DEFAULT_SUBSCRIPTION,
                   required=DEFAULT_SUBSCRIPTION is None,
                   help="Azure subscription id (or set CODA_SUBSCRIPTION).")
    p.add_argument("--resource-groups", default=None, help="Comma-separated RG allow-list.")
    p.add_argument("--accounts", default=None, help="Comma-separated account allow-list.")
    p.add_argument("--limit", type=int, default=None, help="Cap accounts scanned (sampling).")
    p.add_argument("--mode", choices=["production", "eval"], default="production")
    p.add_argument("--shallow", action="store_true",
                   help="Tier-1 shallow scan: fast account-level health grid (429 rate + peak "
                        "saturation), NO Log Analytics, seconds not minutes. Omit for the full "
                        "per-account deep scan.")
    p.add_argument("--concurrency", type=int, default=8, help="Accounts diagnosed in parallel.")
    p.add_argument("--timeout", type=float, default=120.0, help="Per-account timeout (seconds).")
    p.add_argument("--out-dir", default="docs/evidence/fleet-scan")
    p.add_argument("--redact", action="store_true",
                   help="Also write scan-summary-redacted.json (hashed names, aggregate signal only) — "
                        "the file safe to share back for feedback.")
    p.add_argument("--open-feedback", action="store_true",
                   help="With --redact, open the pre-filled feedback issue in your browser.")
    p.add_argument("--update", action="store_true",
                   help="Update CODA to the latest preview version and exit (git pull + uv sync).")
    p.add_argument("--no-update", action="store_true",
                   help="Skip the automatic update check for this run.")
    args = p.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Keep the preview current (see scripts/diagnose.py); `--update` is handled up front. Auto-update
    # + re-exec on run unless --no-update. No-op outside the preview clone; fail-open when offline.
    if not args.no_update:
        auto_update()

    cred = DefaultAzureCredential()
    os.makedirs(os.path.join(args.out_dir, "accounts"), exist_ok=True)

    if args.shallow:
        def _sprog(done: int, total: int, acct) -> None:
            tag = f" [{acct.severity}]" if acct.severity in ("high", "medium") else ""
            print(f"  [{done}/{total}] {acct.resource_group}/{acct.account}: {acct.status}{tag}",
                  flush=True)
        scope_s = args.resource_groups or args.accounts or "whole subscription"
        print(f"[scan] shallow (Tier-1) scope={scope_s}")
        result = shallow_scan(cred, args.subscription, resource_groups=_csv(args.resource_groups),
                              accounts=_csv(args.accounts), limit=args.limit, progress=_sprog)
        agg = result.aggregate()
        base = os.path.join(args.out_dir, "scan-shallow-summary")
        with open(f"{base}.json", "w", encoding="utf-8") as fh:
            json.dump(agg, fh, indent=2)
        md = _render_shallow_md(agg)
        with open(f"{base}.md", "w", encoding="utf-8") as fh:
            fh.write(md)
        print("\n" + md)
        print(f"\n[scan] wrote {base}.json / .md")
        if args.redact:
            print("[scan] note: --redact is a no-op for --shallow (aggregate account-level signal only).")
        return

    def _progress(done: int, total: int, acct) -> None:
        flag = {"timeout": " [TIMEOUT]", "error": " [ERROR]"}.get(acct.status, "")
        extra = (f", {acct.actionable} findings, {acct.abstained} abstained"
                 if acct.status == "ok" else "")
        print(f"  [{done}/{total}] {acct.resource_group}/{acct.account}{extra}"
              f"{' [LA-missing]' if acct.la_missing else ''}{flag}", flush=True)
        if acct.report is not None:  # persist the full per-account report for drill-in
            path = os.path.join(args.out_dir, "accounts",
                                f"{acct.resource_group}__{acct.account}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(acct.report, fh, indent=2)

    scope = args.resource_groups or args.accounts or "whole subscription"
    print(f"[scan] scope={scope} mode={args.mode} concurrency={args.concurrency}")
    result = scan(
        cred, args.subscription, resource_groups=_csv(args.resource_groups),
        accounts=_csv(args.accounts), mode=args.mode, concurrency=args.concurrency,
        per_account_timeout=args.timeout, limit=args.limit, progress=_progress,
    )
    agg = result.aggregate()

    base = os.path.join(args.out_dir, "scan-summary")
    with open(f"{base}.json", "w", encoding="utf-8") as fh:
        json.dump(agg, fh, indent=2)
    redacted = None
    if args.redact:
        redacted = redact_scan(agg)
        with open(f"{base}-redacted.json", "w", encoding="utf-8") as fh:
            json.dump(redacted, fh, indent=2)
    md = _render_md(agg)
    with open(f"{base}.md", "w", encoding="utf-8") as fh:
        fh.write(md)
    print("\n" + md)
    extra = " (+ scan-summary-redacted.json to share)" if args.redact else ""
    print(f"\n[scan] wrote {base}.json / .md{extra}  (+ per-account reports in {args.out_dir}/accounts/)")
    if args.redact and redacted is not None:
        print(feedback_block(redacted, f"{base}-redacted.json"))
        if args.open_feedback:
            webbrowser.open(new_issue_url())


def _render_shallow_md(s: dict) -> str:
    lines = [
        "# CODA shallow subscription scan (Tier-1)", "",
        f"- **Generated:** {s['generated_at']} · mode: {s['mode']}",
        f"- **Accounts scanned:** {s['accounts_scanned']} (errored/timeout: {s['accounts_errored']})",
        f"- **Problem accounts:** {s['problem_accounts']} "
        f"(high: {s['by_severity']['high']}, medium: {s['by_severity']['medium']})",
        "- **Status mix:** " + (", ".join(f"{k}: {v}" for k, v in s["by_status"].items()) or "none"),
        f"- **Elapsed:** {s['elapsed_s']}s", "",
        "## Problem accounts", "",
        "| Severity | Resource group | Account | Status | Throttle % | Peak sat % | Signal |",
        "|---|---|---|---|--:|--:|---|",
    ]
    for a in s["problems"]:
        lines.append(f"| {a['severity']} | {a['resource_group']} | {a['account']} | {a['status']} | "
                     f"{a['throttle_pct']} | {a['peak_saturation_pct']} | {a['reason']} |")
    if not s["problems"]:
        lines.append("| — | — | — | no throttling or saturation detected | — | — | — |")
    return "\n".join(lines)


def _render_md(s: dict) -> str:
    lines = [
        "# CODA fleet scan summary", "",
        f"- **Generated:** {s['generated_at']} · mode: {s['mode']}",
        f"- **Accounts scanned:** {s['accounts_scanned']} "
        f"(errored: {s['accounts_errored']}, timed out: {s['accounts_timed_out']})",
        f"- **Accounts with findings:** {s['accounts_with_findings']} · "
        f"without Log Analytics: {s['accounts_la_missing']}",
        f"- **Total actionable findings:** {s['total_actionable_findings']} · "
        f"abstained: {s['total_abstained']}",
        f"- **Total recoverable capacity:** {s['total_recoverable_ru']:,} RU/s",
        f"- **Elapsed:** {s['elapsed_s']}s", "",
        "## Findings by detector", "",
        "| Detector | Count | By severity |", "|---|--:|---|",
    ]
    for det, info in s["findings_by_detection"].items():
        sev = ", ".join(f"{k}:{v}" for k, v in info["by_severity"].items())
        lines.append(f"| {det} | {info['count']} | {sev} |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
