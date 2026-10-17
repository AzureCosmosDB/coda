"""Run the CODA diagnostic pipeline end-to-end against an account and persist artifacts.

Defaults to **production** mode — the right choice for a real, steadily-used workload: honest long
windows ending *now* + the resource-age guard. (On a young/quiet account expect mostly abstentions —
that is the sufficiency framework working, not a failure.)

Advanced / testing & forensics (opt in with ``--mode``):
  * eval — a recent window with the age guard disabled, used to exercise the wiring on freshly
    generated telemetry (our validation path). Combine with ``--window-end`` / ``--eval-hours`` to
    pin analysis to a past window (e.g. post-incident forensics, or fixtures whose load ran earlier).
  * both — run production and eval.

Usage:
  uv run python scripts/diagnose.py --resource-group <resource-group> \
      --account <account> --out-dir ./coda-out
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime

from azure.identity import DefaultAzureCredential

from coda_core.feedback import feedback_block, new_issue_url
from coda_core.pipeline import default_eval_window, render_markdown, run_diagnostics
from coda_core.providers.arm import ArmProvider
from coda_core.selfupdate import auto_update, run_update_command
from coda_core.providers.azure_monitor import AzureMonitorMetricsProvider
from coda_core.providers.cost_management import CostManagementProvider
from coda_core.providers.log_analytics import LogAnalyticsProvider
from coda_core.providers.retail_prices import RetailPricesProvider
from coda_core.redact import redact_report
from coda_core.scan import shallow_scan_account

DEFAULT_SUBSCRIPTION = os.environ.get("CODA_SUBSCRIPTION")


def main() -> None:
    # `--update` (update CODA and exit) must work standalone, before argparse enforces the required
    # diagnosis args — so handle it here, up front.
    if "--update" in sys.argv[1:]:
        sys.exit(run_update_command())
    parser = argparse.ArgumentParser(description="Run CODA diagnostics for one account.")
    parser.add_argument("--subscription", default=DEFAULT_SUBSCRIPTION,
                        required=DEFAULT_SUBSCRIPTION is None,
                        help="Azure subscription id (or set CODA_SUBSCRIPTION).")
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument(
        "--mode", choices=["production", "eval", "both"], default="production",
        help="Analysis mode. Default 'production' (now-anchored long windows + age guard) suits a "
             "steadily-used workload. 'eval'/'both' are for testing & forensics — see --window-end.")
    parser.add_argument("--eval-hours", type=int, default=None,
                        help="[eval only] Eval-window size in hours (default 24). Sized to the signal "
                             "duration: a short window avoids diluting a sustained burst's p99.")
    parser.add_argument("--window-end", default=None,
                        help="[eval only] ISO-8601 end anchor (default: automatic). Pin "
                             "to a past window for forensics or fixtures whose load ran earlier "
                             "(e.g. 2026-06-22T03:00:00Z). Five-minute logs require aligned boundaries.")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--redact", action="store_true",
                        help="Also write a PII-safe *-redacted.json (hashed names, no query text / "
                             "UserAgent / prose) — the only file safe to share back for feedback.")
    parser.add_argument("--open-feedback", action="store_true",
                        help="With --redact, open the pre-filled feedback issue in your browser.")
    parser.add_argument("--update", action="store_true",
                        help="Update CODA to the latest preview version and exit (git pull + uv sync).")
    parser.add_argument("--no-update", action="store_true",
                        help="Skip the automatic update check for this run.")
    parser.add_argument("--shallow", action="store_true",
                        help="Tier-1 shallow health signal for this account (account-level metrics "
                             "only — 429 rate + peak saturation, no Log Analytics, ~1s) instead of "
                             "the full deep diagnosis.")
    parser.add_argument("--unit-concurrency", type=int, default=None,
                        help="Max database/container diagnosis workers for this account "
                             "(default 4 or CODA_DIAGNOSE_UNIT_CONCURRENCY).")
    args = parser.parse_args()

    # Windows consoles default to cp1252 and choke on the report's unicode (—, ≈). Force utf-8.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Keep the preview current: auto-update + re-exec on run unless disabled. (`--update` is handled
    # up front, before argparse.) No-op outside the preview clone; fail-open when offline.
    if not args.no_update:
        auto_update()

    cred = DefaultAzureCredential()
    if args.shallow:
        row = shallow_scan_account(cred, args.subscription, args.resource_group, args.account).as_row()
        if row.get("error"):
            print(f"[diagnose] shallow: {args.account}: ERROR {row['error']}")
        else:
            print(f"[diagnose] shallow (Tier-1) health for {args.account}:")
            print(f"  status={row['status']} · severity={row['severity']} · "
                  f"throttle={row['throttle_pct']}% · peak_saturation={row['peak_saturation_pct']}% · "
                  f"requests={row['total_requests']:,}")
            print(f"  {row['reason']}")
        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
            path = os.path.join(args.out_dir, "diagnose-shallow.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(row, fh, indent=2)
            print(f"[diagnose] wrote {path}")
        return
    arm = ArmProvider(cred, args.subscription)
    metrics = AzureMonitorMetricsProvider(cred)
    la = LogAnalyticsProvider(cred)
    cost = CostManagementProvider(cred, args.subscription)
    retail_prices = RetailPricesProvider()

    modes = ["production", "eval"] if args.mode == "both" else [args.mode]
    # Build the eval window when a size and/or an explicit end anchor is given. `now` is the END anchor,
    # so --window-end pins analysis to when the load-gen produced the telemetry.
    window_end = datetime.fromisoformat(args.window_end) if args.window_end else None
    eval_window = (default_eval_window(now=window_end, hours=args.eval_hours or 24)
                   if (args.eval_hours or window_end) else None)
    for mode in modes:
        report = run_diagnostics(metrics, arm, args.resource_group, args.account, mode=mode,
                                 eval_window=eval_window, la=la, cost=cost,
                                 retail_prices=retail_prices,
                                 unit_concurrency=args.unit_concurrency)
        md = render_markdown(report)
        # Persist BEFORE printing so a console-encoding hiccup can't lose the artifact.
        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
            base = os.path.join(args.out_dir, f"diagnose-{mode}")
            with open(f"{base}.json", "w", encoding="utf-8") as fh:
                json.dump(report.as_dict(), fh, indent=2)
            with open(f"{base}.md", "w", encoding="utf-8") as fh:
                fh.write(md)
            if args.redact:
                # PII-safe research artifact (hashed names, no query text / UserAgent / prose) — the
                # ONLY file safe to share back for analysis. Review it before sending.
                redacted = redact_report(report.as_dict())
                redacted_path = f"{base}-redacted.json"
                with open(redacted_path, "w", encoding="utf-8") as fh:
                    json.dump(redacted, fh, indent=2)
        print(f"\n{'=' * 80}\nMODE: {mode}\n{'=' * 80}")
        print(md)
        if args.out_dir:
            extra = " (+ -redacted.json to share)" if args.redact else ""
            print(f"\n[diagnose] wrote {os.path.join(args.out_dir, f'diagnose-{mode}')}.json / .md{extra}")
            if args.redact:
                print(feedback_block(redacted, redacted_path))
                if args.open_feedback:
                    webbrowser.open(new_issue_url())


if __name__ == "__main__":
    main()
