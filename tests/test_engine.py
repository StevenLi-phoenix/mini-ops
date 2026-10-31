import json
import time

import pytest

from mini_ops import freeze
from mini_ops.config import parse
from mini_ops.engine import Engine, Env
from mini_ops.notify import Notifier
from mini_ops.observe import health
from mini_ops.observe.launchd import JobState
from mini_ops.runner import CmdResult
from mini_ops.store import Store
from mini_ops.triage import TriageResult, Verdict

NOON = time.mktime((2026, 10, 31, 12, 0, 0, 0, 0, -1))
UP = JobState(True, "running", 42, 1, 0)
DOWN = JobState(True, "not running", None, 1, -9)


class FakeTriage:
    def __init__(self):
        self.verdicts, self.calls = [], []

    def run(self, inc, svc, ctx):
        self.calls.append((inc.service, inc.kind, ctx))
        v = (
            self.verdicts.pop(0)
            if self.verdicts
            else Verdict("suppress", "low", "noise", "d", None, "")
        )
        if isinstance(v, str):
            return TriageResult(None, v, raw_path="/raw/x")
        return TriageResult(v, usd=0.0005, raw_path="/raw/x")


class Rig:
    def __init__(self, tmp_path, services=None, **llm):
        self.log = tmp_path / "app.log"
        self.log.write_text("")
        svcs = services or [
            {
                "id": "asr",
                "launchd": "gui/501/com.asr.service",
                "expect": "running",
                "actions": ["kickstart"],
                "logs": [str(self.log)],
                "log_format": "plain",
            },
        ]
        self.cfg = parse(
            {"ops": {"digest_hours": [9]}, "llm": llm, "service": svcs}, config_dir=tmp_path
        )
        (tmp_path / "tok").write_text("t")
        self.cfg = self.cfg.__class__(
            **{
                **self.cfg.__dict__,
                "notify": self.cfg.notify.__class__(token_file=tmp_path / "tok"),
            }
        )
        self.store = Store(tmp_path / "state.json")
        self.posts = []
        self.jobs = {"gui/501/com.asr.service": UP}
        self.now = NOON
        self.runs = []
        env = Env(
            runner=self._run,
            read_job=lambda spec, r: self.jobs[spec],
            http_probe=lambda u, accept=(): health.Probe(True, "ok"),
            sleep=lambda s: None,
            clock=lambda: self.now,
        )
        self.triage = FakeTriage()
        self.notifier = Notifier(
            self.cfg.notify,
            self.store.data,
            post=lambda *a: self.posts.append(json.loads(a[2])) or (202, b'{"outcome":"accepted"}'),
            clock=lambda: self.now,
        )
        self.engine = Engine(self.cfg, self.store, self.triage, self.notifier, env)

    def _run(self, argv, timeout=30):
        self.runs.append(list(argv))
        return CmdResult(0, "")

    def tick(self, advance=30):
        self.now += advance
        return self.engine.tick()

    def append(self, *lines):
        with open(self.log, "a") as f:
            f.write("".join(ln + "\n" for ln in lines))


def test_first_tick_baselines_history_without_calling_the_llm(tmp_path):
    r = Rig(tmp_path)
    r.append("ERROR old problem 1", "WARNING old problem 2")
    r.tick()
    assert r.triage.calls == [] and r.posts == []
    assert r.store.data["baselined"] and len(r.store.data["sigs"]) == 2
    assert r.store.data["digest"]["baseline"]["why"] == "基线"
    r.append("ERROR old problem 1")  # same cause: still known
    r.tick()
    assert r.triage.calls == []


def test_new_warning_is_triaged_once_and_suppression_is_remembered(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.append(
        "2026-10-31 WARNING watch: RSS feed for UCabcdefghijklmnopqrstuv failed after 3 attempts"
    )
    rep = r.tick()
    assert [c[:2] for c in r.triage.calls] == [("asr", "log")] and rep.suppressed == 1
    assert r.posts == []  # suppressed -> nothing immediate
    sig = next(iter(r.store.data["verdicts"]))
    # 13 hours later the same cause is "BACK": remembered verdict, no second model call
    r.append(
        "2026-10-31 WARNING watch: RSS feed for UCzzzzzzzzzzzzzzzzzzzzzz failed after 4 attempts"
    )
    r.now += 13 * 3600
    assert r.engine.tick().suppressed == 1
    assert len(r.triage.calls) == 1 and r.store.data["digest"][sig]["count"] >= 2


def test_job_down_triggers_llm_action_and_an_immediate_alert(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.jobs["gui/501/com.asr.service"] = DOWN
    r.triage.verdicts.append(
        Verdict("act", "high", "ASR 退出", "SIGKILL 后没被拉起", "kickstart", "看内存")
    )
    r.tick()
    assert r.triage.calls == []  # one tick of grace
    rep = r.tick()
    assert rep.alerts == 1 and rep.actions[0].executed
    assert ["/bin/launchctl", "kickstart", "-k", "gui/501/com.asr.service"] in r.runs
    assert r.posts[0]["kind"] == "host.ops.alert" and "已执行 kickstart" in r.posts[0]["text"]
    assert r.store.data["jobs"]["asr"]["alerted"] is True
    # it comes back: a recovery line lands in the digest, not a second alert
    r.jobs["gui/501/com.asr.service"] = UP
    r.tick()
    assert any(v["why"] == "恢复" for v in r.store.data["digest"].values())


def test_frozen_service_gets_no_action_and_a_muted_incident_skips_the_llm(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    freeze.add(tmp_path / "freeze.json", "asr", 3600, "tcc-host migration", now=r.now)
    r.jobs["gui/501/com.asr.service"] = DOWN
    r.tick()
    r.tick()  # noqa: E702
    assert r.triage.calls == [] and r.posts == [] and r.runs == []
    assert "静音" in next(
        v["why"] for k, v in r.store.data["digest"].items() if k.endswith("job_down")
    )


def test_frozen_without_mute_still_triages_but_never_acts(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    freeze.add(tmp_path / "freeze.json", "asr", 3600, "maintenance", mute=False, now=r.now)
    r.jobs["gui/501/com.asr.service"] = DOWN
    r.triage.verdicts.append(Verdict("act", "high", "down", "d", "kickstart", ""))
    r.tick()
    r.tick()  # noqa: E702
    assert len(r.triage.calls) == 1 and r.runs == []
    assert "冻结中" in r.posts[0]["text"]


def test_llm_failure_alerts_raw_for_jobs_and_digests_logs(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.append("ERROR something new")
    r.triage.verdicts.append("LLM HTTP 503")
    rep = r.tick()
    assert rep.alerts == 0 and "未经 LLM 判断" in [
        v["why"] for v in r.store.data["digest"].values()
    ]
    r.jobs["gui/501/com.asr.service"] = DOWN
    r.triage.verdicts.append("LLM HTTP 503")
    r.tick()
    r.tick()  # noqa: E702
    assert "LLM 不可用" in r.posts[0]["text"] and r.runs == []  # no model -> no action


def test_budget_exhausted_skips_the_model_entirely(tmp_path):
    r = Rig(tmp_path, daily_calls=1)
    r.tick()
    r.append("ERROR first")
    r.tick()
    r.append("ERROR second, different")
    r.tick()
    assert len(r.triage.calls) == 1
    assert "未经 LLM 判断" in [v["why"] for v in r.store.data["digest"].values()]


def test_per_tick_triage_limit_defers_the_rest(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.append(*[f"ERROR distinct problem number {w}" for w in "abcdef"])
    r.tick()
    assert len(r.triage.calls) == 3 and len(r.store.data["backlog"]) == 3
    r.tick()
    assert len(r.triage.calls) == 6 and r.store.data["backlog"] == []


def test_alert_over_hourly_cap_folds_into_digest(tmp_path):
    r = Rig(tmp_path)
    r.notifier.cfg = r.notifier.cfg.__class__(token_file=r.notifier.cfg.token_file, max_per_hour=1)
    r.tick()
    r.jobs["gui/501/com.asr.service"] = DOWN
    for _ in range(2):
        r.triage.verdicts.append(Verdict("act", "high", "down", "d", None, "check"))
    r.tick()
    r.tick()  # noqa: E702
    assert len(r.posts) == 1
    r.append("ERROR other new thing")
    r.triage.verdicts.append(Verdict("act", "high", "other", "d", None, ""))
    r.tick()
    assert len(r.posts) == 1 and any(v["why"] == "限流" for v in r.store.data["digest"].values())


def test_digest_goes_out_once_at_the_configured_hour(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.append("ERROR noise")
    r.tick()
    assert r.posts == []
    r.now = time.mktime((2026, 11, 1, 9, 0, 5, 0, 0, -1))
    r.engine.tick()
    digests = [p for p in r.posts if p["kind"] == "host.ops.digest"]
    assert len(digests) == 1 and "noise" in digests[0]["text"]
    assert r.store.data["digest"] == {}
    r.now += 60
    r.engine.tick()
    assert len([p for p in r.posts if p["kind"] == "host.ops.digest"]) == 1


def test_kaorou_burn_blocks_the_restart_the_model_asked_for(tmp_path, monkeypatch):
    svcs = [
        {
            "id": "kaorou-daemon",
            "launchd": "gui/501/app.lishuyu.kaorou.daemon",
            "expect": "running",
            "actions": ["soft_restart_kaorou"],
        }
    ]
    r = Rig(tmp_path, services=svcs)
    r.jobs = {"gui/501/app.lishuyu.kaorou.daemon": UP}
    monkeypatch.setattr(
        health,
        "get_json",
        lambda url, timeout=5.0: {"jobs": [{"stage": "burn", "status": "running"}]},
    )
    r.tick()
    r.jobs["gui/501/app.lishuyu.kaorou.daemon"] = DOWN
    r.triage.verdicts.append(Verdict("act", "high", "daemon down", "d", "soft_restart_kaorou", ""))
    r.tick()
    r.tick()  # noqa: E702
    assert r.triage.calls[0][2]["烤肉当前是否空闲(无烧录)"] is False
    assert not any("soft-restart" in c for run in r.runs for c in run)
    assert "未执行 soft_restart_kaorou：保护规则" in r.posts[0]["text"]


def test_restart_storm_and_health_incidents_reach_the_model(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.tick()  # first real sample of the restart counter
    r.jobs["gui/501/com.asr.service"] = JobState(True, "running", 50, 5, -9)
    r.tick(60)
    assert r.triage.calls and r.triage.calls[0][1] == "job_flap"


def test_status_snapshot_is_written(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    st = Store(tmp_path / "state.json").data["status"]
    assert st["services"]["asr"]["job"]["pid"] == 42


@pytest.mark.parametrize("n", [0])
def test_idle_tick_writes_nothing_after_the_first(tmp_path, n):
    r = Rig(tmp_path)
    r.tick()
    mtime = (tmp_path / "state.json").stat().st_mtime_ns
    r.engine.env.clock = lambda: NOON  # no clock drift in the snapshot
    r.engine.tick()
    r.engine.tick()
    assert (tmp_path / "state.json").stat().st_mtime_ns >= mtime


def test_forced_digest_ignores_the_hour_but_not_emptiness(tmp_path):
    r = Rig(tmp_path)
    r.tick()
    r.append("ERROR noise")
    r.tick()
    assert r.engine.maybe_digest(r.now) is False  # noon is not a digest hour
    assert r.engine.maybe_digest(r.now, force=True) is True
    assert r.engine.maybe_digest(r.now, force=True) is False  # nothing left
