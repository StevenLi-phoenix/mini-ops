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


def render_alert(
    inc: Incident, verdict: Verdict | None, result: ActionResult | None, note: str = ""
) -> tuple[str, str]:
    """(title, text) for an immediate notification."""
    head = verdict.summary if verdict and verdict.summary else inc.headline
    title = clip(f"【运维】{inc.service}：{sanitize(head, 120)}", 200)
    lines: list[str] = []
    if verdict and verdict.diagnosis:
        lines.append(f"诊断：{verdict.diagnosis}")
    elif note:
        lines.append(note)
    if inc.evidence:
        lines.append("证据：")
        lines += [f"- {sanitize(e, 160)}" for e in inc.evidence[:3]]
    if result is not None:
        lines.append(result.line())
    elif verdict and verdict.rejected_action:
        lines.append(
            f"未执行：模型提议的动作 {sanitize(verdict.rejected_action, 40)} 不在允许清单里"
        )
    if verdict and verdict.advice:
        lines.append(f"建议：{verdict.advice}")
    if note and verdict and verdict.diagnosis:
        lines.append(note)
    return title, clip("\n".join(lines), 1800)


def render_digest(items: dict[str, Any], stats: dict[str, Any], now: float) -> tuple[str, str]:
    total = sum(i["count"] for i in items.values())
    title = f"【运维】摘要：{len(items)} 类问题已抑制/静音（共 {total} 次）"
    ordered = sorted(items.values(), key=lambda i: -i["count"])
    lines = []
    for i in ordered[:12]:
        last = time.strftime("%m-%d %H:%M", time.localtime(i["last"]))
        lines.append(
            f"- {i['service']}：{sanitize(i['summary'], 100)} ×{i['count']}"
            f"（{i['why']}，最后 {last}）"
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
        now = self.clock() if now is None else now
        self.state["sent"] = [t for t in self.state["sent"] if now - t < 3600]
        return len(self.state["sent"]) < self.cfg.max_per_hour

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
