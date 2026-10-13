import argparse
import json
import sys

from . import __version__
from .core import analyze, load, load_dangerous_list


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="confirmskip",
        description=(
            "Flag side-effecting agent tool calls that lack a prior user confirmation "
            "(JSONL conversation / tool-call traces)."
        ),
    )
    p.add_argument("traces", nargs="+", help="JSONL trace files")
    p.add_argument(
        "--lookback",
        type=int,
        default=8,
        help="how many prior events may contain the confirmation (default 8)",
    )
    p.add_argument(
        "--dangerous-file",
        help="optional text file of dangerous tool name patterns (one per line)",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="high",
        help="exit 1 when a finding at this severity or worse exists (default high)",
    )
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)

    dangerous = None
    if a.dangerous_file:
        try:
            dangerous = load_dangerous_list(a.dangerous_file)
        except OSError as e:
            print(f"confirmskip: {a.dangerous_file}: {e}", file=sys.stderr)
            return 2
        if not dangerous:
            print(f"confirmskip: {a.dangerous_file}: no tool names found", file=sys.stderr)
            return 2

    reports, worst = {}, 0
    rank = {"medium": 1, "high": 2}
    for path in a.traces:
        try:
            events = load(path)
            r = analyze(events, lookback=a.lookback, dangerous=dangerous)
        except (OSError, ValueError) as e:
            print(f"confirmskip: {path}: {e}", file=sys.stderr)
            return 2
        reports[path] = r
        for f in r["findings"]:
            worst = max(worst, rank.get(f["severity"], 0))

    if a.json:
        print(json.dumps(reports, indent=2))
    else:
        for path, r in reports.items():
            print(
                f"{path}: {r['events']} events, {r['tool_calls']} tool calls, "
                f"{r['dangerous_calls']} dangerous, {len(r['findings'])} findings"
            )
            for f in r["findings"]:
                print(
                    f"  [{f['severity'].upper():6}] {f['kind']:12} line {f['line']}: {f['message']}"
                )

    if a.fail_on != "none" and worst >= rank[a.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
