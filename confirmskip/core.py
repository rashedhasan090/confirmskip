"""Detect side-effecting agent tool calls that lack a prior user confirmation.

Trace format (JSONL, one event per line). Supported shapes:

  Conversation turns:
    {"role": "user"|"assistant"|"system"|"tool", "content": "...", ...}

  Tool calls (any of):
    {"role": "assistant", "tool_calls": [{"name"|"tool": "...", "arguments"|"args": ...}, ...]}
    {"tool": "send_email", "args": {...}, "role": "assistant"}   # compact tool-call line
    {"type": "tool_call", "tool": "...", "args": {...}}

  Explicit approvals (optional, treated as confirmations):
    {"role": "user", "approval": true, ...}
    {"type": "approval", ...}

A confirmation is a recent user turn whose text matches confirmation patterns
(yes, confirm, proceed, go ahead, approved, ...) or an explicit approval event,
within ``lookback`` conversation events before the dangerous tool call.
"""
from __future__ import annotations

import json
import re
from typing import Any

# Default dangerous tools (side-effecting / hard to reverse). Matching is
# case-insensitive substring on the tool name (underscores/hyphens normalized).
DEFAULT_DANGEROUS = (
    "send_email",
    "send_message",
    "send_sms",
    "slack_post",
    "slack_send",
    "post_message",
    "create_pr",
    "merge_pr",
    "git_push",
    "force_push",
    "delete_file",
    "rm_rf",
    "drop_table",
    "transfer_money",
    "send_payment",
    "purchase",
    "buy",
    "deploy",
    "kubectl_apply",
    "kubectl_delete",
    "terraform_apply",
    "destroy",
    "revoke",
    "public_tweet",
    "post_tweet",
    "publish",
    "shell",  # broad; often used for irreversible ops
    "bash",
    "run_terminal",
    "execute",
)

# Phrases that count as user confirmation (word-boundary aware where useful).
_CONFIRM_PATTERNS = [
    r"\byes\b",
    r"\byep\b",
    r"\byeah\b",
    r"\byup\b",
    r"\bok\b",
    r"\bokay\b",
    r"\bsure\b",
    r"\bconfirm(ed|ation)?\b",
    r"\bapproved?\b",
    r"\bproceed\b",
    r"\bgo\s+ahead\b",
    r"\bdo\s+it\b",
    r"\bsend\s+it\b",
    r"\bship\s+it\b",
    r"\blgtm\b",
    r"\blooks\s+good\b",
    r"\bplease\s+(do|send|post|publish|deploy|merge|push|delete)\b",
    r"\bi\s+approve\b",
    r"\byou\s+(may|can|should)\s+(send|post|publish|deploy|merge|push|delete)\b",
]
_CONFIRM_RE = re.compile("|".join(_CONFIRM_PATTERNS), re.IGNORECASE)

# Soft danger: shell-like tools are medium unless args look destructive.
_SHELL_TOOLS = {"shell", "bash", "run_terminal", "execute", "run_command", "terminal"}
_DESTRUCTIVE_SHELL = re.compile(
    r"\b(rm\s+-rf|git\s+push\s+--force|drop\s+table|mkfs|dd\s+if=|"
    r"kubectl\s+delete|terraform\s+destroy|git\s+reset\s+--hard)\b",
    re.IGNORECASE,
)


def _norm_name(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", (name or "").strip().lower())


def _content_text(ev: dict) -> str:
    c = ev.get("content")
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        parts = []
        for block in c:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text") or block.get("content") or ""))
        return " ".join(parts)
    return str(c)


def _is_approval(ev: dict) -> bool:
    if ev.get("approval") is True or ev.get("type") == "approval":
        return True
    if (ev.get("role") or "").lower() != "user":
        return False
    text = _content_text(ev)
    if not text.strip():
        return False
    # Short affirmative replies, or any match of confirmation patterns.
    if _CONFIRM_RE.search(text):
        return True
    return False


def _extract_tool_calls(ev: dict) -> list[dict]:
    """Return list of {name, args} from one event."""
    out: list[dict] = []
    role = (ev.get("role") or "").lower()
    # Skip pure tool *results*.
    if role == "tool" and "tool_calls" not in ev:
        return out

    tcs = ev.get("tool_calls")
    if isinstance(tcs, list):
        for tc in tcs:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else None
            name = (
                tc.get("name")
                or tc.get("tool")
                or (fn.get("name") if fn else None)
            )
            args = tc.get("args", tc.get("arguments"))
            if args is None and fn:
                args = fn.get("arguments")
            if name:
                out.append({"name": str(name), "args": args})
        return out

    # Compact tool-call line: {"tool": "...", "args": {...}} or type=tool_call
    if "tool" in ev and (
        ev.get("type") == "tool_call"
        or role in ("", "assistant", "tool_call")
        or ("args" in ev or "arguments" in ev)
    ):
        name = ev.get("tool") or ev.get("name")
        if name:
            out.append({
                "name": str(name),
                "args": ev.get("args", ev.get("arguments")),
            })
    return out


def _args_text(args: Any) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, sort_keys=True, default=str)
    except TypeError:
        return str(args)


def _match_dangerous(tool_name: str, dangerous: tuple[str, ...] | list[str]) -> str | None:
    """Return the matched dangerous pattern, or None."""
    n = _norm_name(tool_name)
    for d in dangerous:
        dn = _norm_name(d)
        if not dn:
            continue
        if n == dn or dn in n or n.endswith("_" + dn) or n.startswith(dn + "_"):
            return d
    return None


def _severity(tool_name: str, args: Any, matched: str) -> str:
    n = _norm_name(tool_name)
    if n in _SHELL_TOOLS or _norm_name(matched) in _SHELL_TOOLS:
        text = _args_text(args)
        if _DESTRUCTIVE_SHELL.search(text):
            return "high"
        return "medium"
    return "high"


def load(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"line {n}: invalid JSON: {e}") from e
            if not isinstance(ev, dict):
                continue
            ev["_line"] = n
            events.append(ev)
    return events


def analyze(
    events: list[dict],
    *,
    lookback: int = 8,
    dangerous: tuple[str, ...] | list[str] | None = None,
) -> dict:
    """Scan events; return findings for dangerous tools without prior confirmation."""
    dang = tuple(dangerous) if dangerous is not None else DEFAULT_DANGEROUS
    findings: list[dict] = []
    # Track recent confirmation line numbers (absolute indices into events).
    confirm_idxs: list[int] = []

    tool_call_count = 0
    dangerous_count = 0

    for i, ev in enumerate(events):
        if _is_approval(ev):
            confirm_idxs.append(i)

        calls = _extract_tool_calls(ev)
        if not calls:
            continue

        for call in calls:
            tool_call_count += 1
            matched = _match_dangerous(call["name"], dang)
            if not matched:
                continue
            dangerous_count += 1
            # Any confirmation in the lookback window of prior events?
            window_start = max(0, i - lookback)
            recent = [c for c in confirm_idxs if window_start <= c < i]
            if recent:
                continue
            sev = _severity(call["name"], call["args"], matched)
            findings.append({
                "kind": "confirmskip",
                "severity": sev,
                "tool": call["name"],
                "matched_rule": matched,
                "line": ev["_line"],
                "lookback": lookback,
                "message": (
                    f"{call['name']} matches dangerous rule '{matched}' "
                    f"with no user confirmation in the prior {lookback} events"
                ),
            })

    return {
        "events": len(events),
        "tool_calls": tool_call_count,
        "dangerous_calls": dangerous_count,
        "findings": findings,
    }


def load_dangerous_list(path: str) -> list[str]:
    """Load dangerous tool names from a text file (one name per line, # comments)."""
    names: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.append(line.split()[0])
    return names
