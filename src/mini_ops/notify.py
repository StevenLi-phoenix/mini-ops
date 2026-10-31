"""Notifications: DSH's lsy-event-ingest (``host`` source) -> bus -> WeChat. Durable outbox.

The ``host-alerts`` subscription on the DSH side is a plain WeChat note (no model), deduped by
``key``, with its own hourly cap. We keep a second, smaller cap here so a bad hour becomes a digest,
not a flood; and an outbox so a DSH restart (they are frequent) loses nothing.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from mini_ops.actions import ActionResult
from mini_ops.config import NotifyConfig
from mini_ops.gate import Incident
from mini_ops.text import clip, sanitize
from mini_ops.triage import Post, Verdict, http_post

log = logging.getLogger("mini_ops.notify")

MAX_TRIES = 8


def _oneline(parts: list[str], limit: int) -> str:
    return clip(" ｜ ".join(p for p in parts if p), limit)


def render_alert(
    inc: Incident, verdict: Verdict | None, result: ActionResult | None, note: str = ""
) -> tuple[str, str]:
    """``(title, text)`` for an immediate notification.

    DSH's ``host-alerts`` note shows only ``subject`` and ``title`` (whitespace collapsed, 300
    characters) -- the ``text`` field never reaches the phone. So the title carries the whole
    message in one line; ``text`` keeps the long form for the journal and the API.
    """
    head = verdict.summary if verdict and verdict.summary else inc.headline
    action = result.line() if result is not None else ""
    if result is None and verdict and verdict.rejected_action:
        action = f"未执行：模型提议的动作 {sanitize(verdict.rejected_action, 40)} 不在允许清单里"
    title = _oneline(
        [
            sanitize(head, 70),
            f"诊断：{sanitize(verdict.diagnosis, 110)}" if verdict and verdict.diagnosis else note,
            sanitize(action, 80),
            f"建议：{sanitize(verdict.advice, 60)}" if verdict and verdict.advice else "",
            note if verdict and verdict.diagnosis else "",
        ],
        290,
    )
    lines: list[str] = [f"【运维】{inc.service}：{sanitize(head, 120)}"]
    if verdict and verdict.diagnosis:
        lines.append(f"诊断：{verdict.diagnosis}")
    elif note:
        lines.append(note)
    if inc.evidence:
        lines.append("证据：")
        lines += [f"- {sanitize(e, 160)}" for e in inc.evidence[:3]]
    if action:
        lines.append(action)
    if verdict and verdict.advice:
        lines.append(f"建议：{verdict.advice}")
    if note and verdict and verdict.diagnosis:
        lines.append(note)
    return title, clip("\n".join(lines), 1800)


def render_digest(items: dict[str, Any], stats: dict[str, Any], now: float) -> tuple[str, str]:
    """One-line title for the phone (see ``render_alert``), long form in ``text``."""
    total = sum(i["count"] for i in items.values())
    ordered = sorted(items.values(), key=lambda i: -i["count"])
    short = [f"{i['service']} {sanitize(i['summary'], 28)}×{i['count']}" for i in ordered[:5]]
    more = f"…另 {len(ordered) - 5} 类" if len(ordered) > 5 else ""
    title = _oneline(
        [f"摘要：{len(items)} 类问题已抑制/静音（共 {total} 次）：" + "；".join(short) + more], 290
    )
    lines = []
    for i in ordered[:12]:
        last = time.strftime("%m-%d %H:%M", time.localtime(i["last"]))
        lines.append(
            f"- {i['service']}：{sanitize(i['summary'], 100)} ×{i['count']}（{i['why']}，最后 {last}）"
        )
    if len(ordered) > 12:
        lines.append(f"…还有 {len(ordered) - 12} 类")
    if stats.get("actions"):
        lines.append("本期动作：" + "；".join(stats["actions"][:5]))
    if stats.get("llm"):
        lines.append(stats["llm"])
    return title, clip("\n".join(lines), 1800)


class Notifier:
    def __init__(
        self,
        cfg: NotifyConfig,
        state: dict[str, Any],
        *,
        post: Post = http_post,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg, self.state, self.post, self.clock = cfg, state, post, clock

    def room(self, now: float | None = None) -> bool:
        """Hourly and daily caps: the WeChat reply window is shared with every other sender."""
        now = self.clock() if now is None else now
        self.state["sent"] = [t for t in self.state["sent"] if now - t < 86400]
        hour = sum(1 for t in self.state["sent"] if now - t < 3600)
        return hour < self.cfg.max_per_hour and len(self.state["sent"]) < self.cfg.max_per_day

    def enqueue(
        self, suffix: str, key: str, subject: str, title: str, text: str, *, capped: bool = True
    ) -> bool:
        """Queue one event. ``False`` = over the hourly cap (the caller folds it into the digest)."""
        now = self.clock()
        if capped and not self.room(now):
            return False
        if any(o["key"] == key for o in self.state["outbox"]):
            return True
        self.state["sent"].append(now)
        self.state["outbox"].append(
            {
                "kind": f"{self.cfg.kind_prefix}.{suffix}",
                "key": clip(key, 190),
                "subject": clip(subject, 190),
                "title": clip(title, 290),
                "text": clip(text, 7900),
                "tries": 0,
                "next_try": 0.0,
            }
        )
        return True

    def flush(self) -> tuple[int, int]:
        """Deliver what is due. Returns ``(delivered, failed_attempts)``."""
        now = self.clock()
        try:
            token = self.cfg.token_file.read_text(encoding="utf-8").strip()
        except OSError as e:
            if self.state["outbox"]:
                log.error(
                    "notify token unreadable (%s); %d queued", e.strerror, len(self.state["outbox"])
                )
            return 0, 0
        delivered = failed = 0
        keep = []
        for o in self.state["outbox"]:
            if o["next_try"] > now:
                keep.append(o)
                continue
            body = {k: o[k] for k in ("kind", "key", "subject", "title", "text")}
            status, resp = self.post(
                self.cfg.url,
                {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json.dumps(body, ensure_ascii=False).encode(),
                self.cfg.timeout_s,
            )
            if 200 <= status < 300:
                delivered += 1
                outcome = ""
                try:
                    outcome = json.loads(resp).get("outcome", "")
                except ValueError:
                    pass
                log.info("notified %s key=%s outcome=%s", o["kind"], o["key"], outcome)
                if outcome in ("unmatched", "suppressed"):
                    log.error(
                        "DSH did not route %s (outcome=%s): check the host-alerts subscription",
                        o["kind"],
                        outcome,
                    )
                continue
            failed += 1
            o["tries"] += 1
            if status in (400, 401, 403, 413, 422) or o["tries"] >= MAX_TRIES:
                log.error(
                    "dropping notification %s after %s (HTTP %s): %s",
                    o["key"],
                    o["tries"],
                    status,
                    resp[:120],
                )
                continue
            o["next_try"] = now + min(300 * 2 ** (o["tries"] - 1), 3600)
            log.warning("notify failed (HTTP %s), retry in %ds", status, o["next_try"] - now)
            keep.append(o)
        self.state["outbox"] = keep
        return delivered, failed
