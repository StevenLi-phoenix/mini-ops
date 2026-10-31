"""Durable state: one JSON file, written atomically, only when something changed."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("mini_ops.store")


def _default() -> dict[str, Any]:
    return {
        "version": 1,
        "baselined": False,
        "sigs": {},  # signature -> {first,last_seen,hist,last_emit,base,service,sample}
        "verdicts": {},  # signature -> {verdict,until,summary}
        "jobs": {},  # service id -> {runs,pid,down_since,last_report,runs_hist,last_exit}
        "health": {},  # service id -> {fails,last_report}
        "offsets": {},  # path -> {inode,offset}
        "actions": [],  # [{ts,action,target,outcome}]
        "budget": {},  # "YYYY-MM-DD" -> {calls,usd}
        "sent": [],  # timestamps of immediate notifications
        "digest": {},  # signature -> held item waiting for the next digest
        "outbox": [],  # notifications waiting to be delivered (durable, retried)
        "backlog": [],  # incidents waiting for a triage slot
        "digest_last": 0,
        "tailscale": {"last_report": 0},
        "freeze": {},
    }


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = _default()
        self._saved = ""
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as e:
            bad = self.path.with_suffix(".corrupt")
            log.error("state %s unreadable (%s); moved to %s and starting fresh", self.path, e, bad)
            try:
                os.replace(self.path, bad)
            except OSError:
                pass
            return
        if isinstance(raw, dict):
            self.data.update(raw)  # new keys keep their defaults

    def save(self) -> bool:
        blob = json.dumps(self.data, sort_keys=True)
        if blob == self._saved:
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(blob)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._saved = blob
        return True
