# confirmskip

Flag AI agent tool calls that do something hard to undo **without a prior user confirmation**.

Offline, stdlib-only Python. No network, no dependencies beyond the standard library.

Agents sometimes send email, push code, deploy, delete data, or run shell commands because the model "thought it was helpful," not because a human said yes. Existing trace checkers catch loops, result bleed, ghost narration, and ignored failures. **confirmskip** targets a different failure mode: a side-effecting tool ran with no confirming user turn in the recent window.

## What's novel

- Treats **user confirmation** as a first-class event (phrase match *or* explicit `approval` / `type: approval` markers).
- Maintains a default catalog of **dangerous** tools (email, messaging, git push/merge, deploy, payments, destructive shell) with severity that escalates when shell args look destructive (`rm -rf`, `terraform destroy`, …).
- Configurable lookback window and custom dangerous-tool lists for CI policies.
- Distinct from sandclock, tokpack, hushdiff, runseal, toolflow, hedgescope, diffintent, promptfence, aegispath, rippleguard, shardroom, claimcite, stubtruth, callstorm, toolorphan, seedguard, ngramleak, refage, failthrough, resultbleed, stopskew, ghostact, mcpwarden, cronherd, retryamp, envgap, orderflake, permscope, and loopsnare.

## Demo

```bash
$ python -m confirmskip examples/unsafe.jsonl
examples/unsafe.jsonl: 7 events, 3 tool calls, 3 dangerous, 3 findings
  [HIGH  ] confirmskip  line 3: send_email matches dangerous rule 'send_email' with no user confirmation in the prior 8 events
  [HIGH  ] confirmskip  line 6: deploy matches dangerous rule 'deploy' with no user confirmation in the prior 8 events
  [HIGH  ] confirmskip  line 7: shell matches dangerous rule 'shell' with no user confirmation in the prior 8 events

$ python -m confirmskip examples/safe.jsonl
examples/safe.jsonl: 5 events, 1 tool calls, 1 dangerous, 0 findings
```

## Trace format

JSONL, one event per line. Mix conversation turns and tool calls:

```json
{"role": "user", "content": "Yes, go ahead and send it."}
{"role": "assistant", "tool_calls": [{"name": "send_email", "arguments": {"to": "a@b.c"}}]}
{"type": "tool_call", "tool": "deploy", "args": {"env": "prod"}}
{"role": "user", "approval": true}
```

Confirmation phrases include yes / ok / confirm / proceed / go ahead / approved / LGTM / please send / and similar. Explicit `{"approval": true}` or `{"type": "approval"}` also counts.

## Install

```bash
pip install git+https://github.com/rashedhasan090/confirmskip
# or from a checkout:
pip install -e .
python -m confirmskip examples/unsafe.jsonl
```

Requires Python 3.9+.

## Options

| Flag | Meaning |
|------|---------|
| `--lookback N` | Prior events that may hold the confirmation (default 8) |
| `--dangerous-file PATH` | One dangerous tool-name pattern per line (`#` comments ok) |
| `--json` | Machine-readable report |
| `--fail-on {none,medium,high}` | CI exit code gate (default: fail on `high`) |

## Tests

```bash
python -m unittest discover -s tests
```

## License

MIT
