"""The tick: observe -> gate -> (freeze | cached verdict | LLM triage) -> action -> notify."""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ams.escalations import EscalationJournal
from ams.events import Severity

from mini_ops import actions as actions_mod
from mini_ops import freeze as freeze_mod
from mini_ops import triage as triage_mod
from mini_ops.actions import ActionRequest, ActionResult, Executor
from mini_ops.config import Config, ServiceConfig
from mini_ops.gate import HealthGate, Incident, JobGate, LogGate
from mini_ops.notify import Notifier, render_alert, render_digest
from mini_ops.observe import health, launchd, logs
from mini_ops.observe.launchd import JobState
from mini_ops.runner import Runner
from mini_ops.runner import run as default_run
from mini_ops.store import Store
from mini_ops.text import clip, sanitize, signature
from mini_ops.triage import Triage

log = logging.getLogger("mini_ops.engine")

MAX_TRIAGE_PER_TICK = 3
BACKLOG_CAP = 50
TAILSCALE_EVERY_S = 300
EVIDENCE_LINES = 3
TRACE_LINES = 14  # a Traceback needs its tail to be diagnosable
_TRACE = ("Traceback", "ERROR: Exception")


@dataclass
class Env:
    """Everything the engine touches outside itself, so tests can replace it."""

    runner: Runner = default_run
    read_job: Callable[[str, Runner], JobState] = launchd.read_job
    http_probe: Callable[..., health.Probe] = health.http
    socket_probe: Callable[[Path], health.Probe] = health.unix_socket
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.time


@dataclass
class TickReport:
    incidents: int = 0
    triaged: int = 0
    suppressed: int = 0
    alerts: int = 0
    actions: list[ActionResult] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        triage: Triage,
        notifier: Notifier,
        env: Env | None = None,
        journal: EscalationJournal | None = None,
    ) -> None:
        self.cfg, self.store, self.triage, self.notifier = cfg, store, triage, notifier
        self.journal = journal
        self.env = env or Env()
        d = store.data
        self.logs = LogGate(d["sigs"], cfg.gate)
        self.jobs = JobGate(d["jobs"], cfg.gate)
        self.health = HealthGate(d["health"], cfg.gate)
        self.executor = Executor(cfg, d["actions"], runner=self.env.runner, sleep=self.env.sleep)
        self._ticks = 0
        self._ts_last = 0.0

    # ---- observation --------------------------------------------------------------------
    def _log_incidents(self, svc: ServiceConfig, now: float, seed: bool) -> list[Incident]:
        out: list[Incident] = []
        seen: set[str] = set()
        for path in svc.logs:
            entry = self.store.data["offsets"].setdefault(str(path), {})
            lines, skipped = logs.read_new(path, entry, seed=seed)
            if skipped:
                log.warning("%s: skipped %d bytes of a log flood", path.name, skipped)
            hits = list(logs.noteworthy(svc, lines))
            for ln, sev in hits:
                sig = signature(svc.id, ln)
                if seed:
                    self.logs.seed(svc.id, sig, ln, now)
                    continue
                opened = self.logs.observe(svc.id, sig, ln, now)
                held = self.store.data["digest"].get(sig)
                if held and opened is None:
                    held["count"] += 1
                    held["last"] = now
                if opened is None or sig in seen:
                    continue
                seen.add(sig)
                idx = lines.index(ln)
                span = TRACE_LINES if ln.lstrip().startswith(_TRACE) else EVIDENCE_LINES
                ctx = tuple(lines[idx : idx + span])
                out.append(
                    Incident(
                        "log",
                        svc.id,
                        sig,
                        clip(sanitize(ln, 160), 160),
                        opened[0],
                        evidence=ctx,
                        count=opened[1],
                        facts={"severity": Severity(sev).name},
                        ts=now,
                    )
                )
        return out

    def _observe(self, now: float, seed: bool) -> tuple[list[Incident], dict[str, dict]]:
        incidents: list[Incident] = []
        status: dict[str, dict] = {}
        for svc in self.cfg.services:
            info: dict[str, Any] = {}
            if svc.launchd:
                job = self.env.read_job(svc.launchd, self.env.runner)
                info["job"] = dataclasses.asdict(job)
                if not seed:
                    incidents += self.jobs.check(svc, job, now)
                    self._note_recovery(svc, job, now)
            if svc.health_url or svc.health_socket:
                pr = (
                    self.env.http_probe(svc.health_url, accept=svc.health_accept)
                    if svc.health_url
                    else self.env.socket_probe(svc.health_socket)
                )  # type: ignore[arg-type]
                info["health"] = {"ok": pr.ok, "detail": pr.detail}
                if not seed:
                    inc = self.health.check(svc, pr.ok, pr.detail, now)
                    if inc:
                        incidents.append(inc)
            if svc.logs:
                incidents += self._log_incidents(svc, now, seed)
            if "advertise_tailscale" in svc.actions and not seed:
                inc = self._tailscale(svc, now)
                if inc:
                    incidents.append(inc)
            status[svc.id] = info
        return incidents, status

    def _tailscale(self, svc: ServiceConfig, now: float) -> Incident | None:
        if now - self._ts_last < TAILSCALE_EVERY_S:
            return None
        self._ts_last = now
        missing = actions_mod.missing_services(self.cfg, self.env.runner)
        st = self.store.data["tailscale"]
        if not missing:
            st.pop("last_report", None)
            return None
        last = st.get("last_report")
        if last is not None and now - last < self.cfg.gate.job_repeat_s:
            return None
        st["last_report"] = now
        return Incident(
            "tailscale",
            svc.id,
            f"{svc.id}|tailscale",
            f"Tailscale Service 未被本机 advertise：{', '.join(missing)}",
            "MISSING",
            facts={"missing": missing},
            ts=now,
        )

    def _note_recovery(self, svc: ServiceConfig, job: JobState, now: float) -> None:
        st = self.store.data["jobs"].get(svc.id, {})
        if svc.expect == "running" and job.running and st.pop("alerted", None):
            self._hold(
                f"{svc.id}|recovered", svc.id, f"{svc.id} 已恢复运行（pid {job.pid}）", "恢复", now
            )

    # ---- decisions ----------------------------------------------------------------------
    def _journal(self, decision: str, inc: Incident, **extra: Any) -> None:
        """One JSON line per decision -- the audit trail (and what an operator session reads)."""
        if self.journal is not None:
            self.journal.append(
                {
                    "decision": decision,
                    "service": inc.service,
                    "kind": inc.kind,
                    "reason": inc.reason,
                    "signature": inc.signature,
                    "headline": inc.headline,
                    "count": inc.count,
                    **extra,
                }
            )

    def _hold(self, sig: str, service: str, summary: str, why: str, now: float) -> None:
        d = self.store.data["digest"]
        item = d.get(sig)
        if item:
            item.update(count=item["count"] + 1, last=now, why=why)
        else:
            d[sig] = {
                "service": service,
                "summary": summary,
                "count": 1,
                "first": now,
                "last": now,
                "why": why,
            }

    def _context(self, inc: Incident, svc: ServiceConfig | None, now: float) -> dict[str, Any]:
        recent = [
            f"{h['action']}→{h['outcome']}"
            for h in self.store.data["actions"]
            if h["target"] == inc.service and now - h["ts"] < 86400
        ][-5:]
        ctx: dict[str, Any] = {"最近24小时对该服务执行过的动作": recent or "无"}
        if svc and "soft_restart_kaorou" in svc.actions:
            idle, why = actions_mod.kaorou_idle(self.cfg, self.env.runner)
            ctx["烤肉当前是否空闲(无烧录)"] = idle
            if not idle:
                ctx["烤肉忙碌原因"] = why
        return ctx

    def handle(
        self,
        inc: Incident,
        freezes: dict[str, freeze_mod.Freeze],
        now: float,
        report: TickReport,
        *,
        may_triage: bool = True,
    ) -> bool:
        """Returns False when the incident must wait for a triage slot."""
        data = self.store.data
        fz = freeze_mod.lookup(freezes, inc.service)
        if fz is not None and fz.mute:
            self._hold(inc.signature, inc.service, inc.headline, f"静音（{fz.reason}）", now)
            self._journal("muted", inc, freeze=fz.reason)
            report.suppressed += 1
            return True
        cached = data["verdicts"].get(inc.signature) if inc.is_log else None
        if cached and cached["until"] > now:
            self._hold(
                inc.signature, inc.service, cached["summary"] or inc.headline, "LLM 判定为噪音", now
            )
            self._journal("cached-suppress", inc)
            report.suppressed += 1
            return True
        ok, why = triage_mod.budget_left(data["budget"], self.cfg.llm, now)
        if not ok:
            return self._fallback(inc, f"LLM 不可用：{why}", now, report)
        if not may_triage:
            return False
        svc = self.cfg.service(inc.service)
        res = self.triage.run(inc, svc, self._context(inc, svc, now))
        if res.raw_path or res.usd:  # a call was made: it counts against the cap, success or not
            triage_mod.record_spend(data["budget"], now, res.usd)
        report.triaged += 1
        if res.verdict is None:
            return self._fallback(inc, f"LLM 不可用：{res.error}", now, report)
        v = res.verdict
        log.info("verdict %s/%s %s: %s", inc.service, inc.kind, v.verdict, v.summary)
        if v.verdict == "suppress":
            if inc.is_log:
                data["verdicts"][inc.signature] = {
                    "until": now + self.cfg.gate.suppress_ttl_s,
                    "summary": v.summary,
                }
            self._hold(inc.signature, inc.service, v.summary or inc.headline, "LLM 判定为噪音", now)
            self._journal(
                "suppress", inc, summary=v.summary, diagnosis=v.diagnosis, raw=res.raw_path
            )
            report.suppressed += 1
            return True
        result: ActionResult | None = None
        if v.action:
            result = self.executor.execute(ActionRequest(v.action, inc.service, {}), freezes, now)
            report.actions.append(result)
        if inc.kind in ("job_down", "job_flap"):
            data["jobs"].setdefault(inc.service, {})["alerted"] = True
        self._journal(
            "act",
            inc,
            summary=v.summary,
            diagnosis=v.diagnosis,
            advice=v.advice,
            action=(result.line() if result else v.rejected_action or None),
            raw=res.raw_path,
        )
        self._alert(inc, v, result, "", now, report)
        return True

    def _fallback(self, inc: Incident, note: str, now: float, report: TickReport) -> bool:
        """No model: job/health incidents still reach the owner (raw); log lines wait for the digest."""
        self._journal("fallback", inc, note=note)
        if inc.is_log:
            self._hold(inc.signature, inc.service, inc.headline, "未经 LLM 判断", now)
            report.suppressed += 1
            return True
        if inc.kind in ("job_down", "job_flap"):
            self.store.data["jobs"].setdefault(inc.service, {})["alerted"] = True
        self._alert(inc, None, None, note, now, report)
        return True

    def _alert(
        self,
        inc: Incident,
        v: Any,
        result: ActionResult | None,
        note: str,
        now: float,
        report: TickReport,
    ) -> None:
        title, text = render_alert(inc, v, result, note)
        digest = hashlib.sha1(inc.signature.encode()).hexdigest()[:10]  # noqa: S324 - not security
        key = f"ops-{digest}-{time.strftime('%Y%m%d%H%M', time.localtime(now))}"
        if self.notifier.enqueue("alert", key, f"运维·{inc.service}", title, text):
            report.alerts += 1
        else:
            self._hold(
                inc.signature,
                inc.service,
                f"{inc.headline}（通知超过每小时上限，改入摘要）",
                "限流",
                now,
            )

    # ---- digest -------------------------------------------------------------------------
    def maybe_digest(self, now: float, *, force: bool = False) -> bool:
        d = self.store.data
        tm = time.localtime(now)
        slot = time.strftime("%Y%m%d%H", tm)
        due = force or (tm.tm_hour in self.cfg.digest_hours and d["digest_last"] != slot)
        if not due or not d["digest"]:
            return False
        recent = [h for h in d["actions"] if h["ts"] > now - 86400 and h["outcome"] != "refused"]
        spent = d["budget"].get(time.strftime("%Y-%m-%d", tm), {"calls": 0, "usd": 0.0})
        stats = {
            "actions": [f"{h['target']} {h['action']}→{h['outcome']}" for h in recent],
            "llm": f"今日 LLM {spent['calls']} 次，约 ${spent['usd']:.4f}",
        }
        title, text = render_digest(d["digest"], stats, now)
        if self.notifier.enqueue(
            "digest", f"ops-digest-{slot}", "digest", title, text, capped=False
        ):
            d["digest"] = {}
            d["digest_last"] = slot
            return True
        return False

    # ---- the loop body ------------------------------------------------------------------
    def tick(self) -> TickReport:
        now = self.env.clock()
        report = TickReport()
        data = self.store.data
        seed = not data["baselined"]
        freezes = freeze_mod.load(self.cfg.config_dir / "freeze.json", now)
        incidents, status = self._observe(now, seed)
        if seed:
            data["baselined"] = True
            n = len(data["sigs"])
            self._hold(
                "baseline",
                "mini-ops",
                f"首次启动：把 {n} 类既有日志告警记为基线，不再逐条通知",
                "基线",
                now,
            )
            log.info("baseline seeded: %d causes", n)
        pending = [Incident(**{**b, "evidence": tuple(b["evidence"])}) for b in data["backlog"]]
        data["backlog"] = []
        for inc in pending + incidents:
            report.incidents += 1
            done = self.handle(
                inc, freezes, now, report, may_triage=report.triaged < MAX_TRIAGE_PER_TICK
            )
            if not done and len(data["backlog"]) < BACKLOG_CAP:
                data["backlog"].append(dataclasses.asdict(inc))
        self.maybe_digest(now)
        self.notifier.flush()
        self._ticks += 1
        if self._ticks % 120 == 0:
            self.logs.prune(now)
        data["status"] = {
            "ts": now,
            "services": status,
            "backlog": len(data["backlog"]),
            "outbox": len(data["outbox"]),
            "freeze": sorted(freezes),
        }
        self.store.save()
        return report
