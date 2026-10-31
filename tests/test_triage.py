import json

import pytest

from mini_ops import triage
from mini_ops.config import LlmConfig, parse
from mini_ops.gate import Incident
from mini_ops.triage import Triage, VerdictError, parse_verdict

SVC = parse(
    {
        "service": [
            {
                "id": "asr",
                "launchd": "gui/501/com.asr.service",
                "expect": "running",
                "actions": ["kickstart"],
                "description": "ASR service",
            }
        ]
    }
).services[0]
INC = Incident(
    "job_down",
    "asr",
    "asr|job_down",
    "asr 没有在运行",
    "DOWN",
    evidence=("ERROR boom token=abcdefgh1234", "line 2"),
    facts={"state": "not running"},
)


def reply(obj, usage=(100, 50)):
    body = {
        "choices": [{"message": {"content": obj if isinstance(obj, str) else json.dumps(obj)}}],
        "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]},
    }
    return 200, json.dumps(body).encode()


def make(tmp_path, post, key=True):
    kf = tmp_path / "key"
    if key:
        kf.write_text("llmgw_secretvalue0123\n")
    cfg = LlmConfig(key_file=kf)
    return Triage(cfg, tmp_path / "raw", post=post, clock=lambda: 1_000_000.0)


def test_prompt_fences_and_redacts_untrusted_evidence():
    msgs = triage.build_messages(INC, SVC, {"kaorou_burning": False})
    user = msgs[1]["content"]
    assert "<incident-data>" in user and "abcdefgh1234" not in user and "<redacted>" in user
    assert "- kickstart:" in user and "soft_restart_kaorou" not in user
    assert "不可信" in msgs[0]["content"]


def test_prompt_for_service_without_actions():
    svc = parse({"service": [{"id": "x"}]}).services[0]
    assert "没有允许的动作" in triage.build_messages(INC, svc, {})[1]["content"]


def test_parse_verdict_variants():
    v = parse_verdict(
        '```json\n{"verdict":"act","severity":"high","summary":"s","diagnosis":"d",'
        '"action":{"name":"kickstart","args":{}},"advice":""}\n```',
        ("kickstart",),
    )
    assert (v.verdict, v.action, v.severity) == ("act", "kickstart", "high")
    v = parse_verdict('{"verdict":"act","action":{"name":"rm_rf"}}', ("kickstart",))
    assert v.action is None and v.rejected_action == "rm_rf" and v.severity == "medium"
    v = parse_verdict('{"verdict":"suppress","action":{"name":"kickstart"}}', ("kickstart",))
    assert v.action is None  # a suppress verdict never carries an action


@pytest.mark.parametrize("text", ["", "no json", "{bad", '{"verdict":"maybe"}', "[1,2]"])
def test_parse_verdict_rejects(text):
    with pytest.raises(VerdictError):
        parse_verdict(text, ())


def test_run_success_persists_raw_and_costs(tmp_path):
    seen = {}

    def post(url, headers, body, timeout):
        seen.update(url=url, auth=headers["Authorization"], body=json.loads(body))
        return reply({"verdict": "suppress", "severity": "low", "summary": "ok", "diagnosis": "d"})

    res = make(tmp_path, post).run(INC, SVC, {})
    assert res.verdict.verdict == "suppress" and res.error == ""
    assert (
        seen["url"].endswith("/v1/chat/completions")
        and seen["auth"] == "Bearer llmgw_secretvalue0123"
    )
    assert seen["body"]["model"] == "deepseek-flash" and seen["body"]["temperature"] == 0
    assert res.usd == pytest.approx((100 * 0.30 + 50 * 1.20) / 1e6)
    raw = (tmp_path / "raw").rglob("*.json")
    assert len(list(raw)) == 1
    assert "secretvalue" not in next((tmp_path / "raw").rglob("*.json")).read_text()


def test_unparseable_reply_is_still_saved_and_billed(tmp_path):
    res = make(tmp_path, lambda *a: reply("I think it is fine")).run(INC, SVC, {})
    assert res.verdict is None and "无法解析" in res.error and res.usd > 0
    assert any((tmp_path / "raw").rglob("*.json"))


def test_retry_once_on_5xx_then_give_up(tmp_path):
    calls = []

    def post(*a):
        calls.append(1)
        return 503, b"overloaded"

    res = make(tmp_path, post).run(INC, SVC, {})
    assert len(calls) == 2 and res.verdict is None and "503" in res.error


def test_no_retry_on_4xx(tmp_path):
    calls = []
    res = make(tmp_path, lambda *a: (calls.append(1), (402, b"quota"))[1]).run(INC, SVC, {})
    assert len(calls) == 1 and "402" in res.error


def test_missing_key_file(tmp_path):
    res = make(tmp_path, lambda *a: reply({}), key=False).run(INC, SVC, {})
    assert res.verdict is None and "key" in res.error


def test_budget_caps_calls_and_dollars():
    cfg = LlmConfig(daily_calls=2, daily_usd=0.10)
    b: dict = {}
    assert triage.budget_left(b, cfg, 1000)[0]
    triage.record_spend(b, 1000, 0.04)
    triage.record_spend(b, 1000, 0.04)
    ok, why = triage.budget_left(b, cfg, 1000)
    assert not ok and "调用" in why
    b2: dict = {}
    triage.record_spend(b2, 1000, 0.11)
    assert "花费" in triage.budget_left(b2, cfg, 1000)[1]
    assert triage.budget_left(b, cfg, 1000 + 2 * 86400)[0]  # a new day starts fresh
