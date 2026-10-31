import json

from mini_ops.actions import ActionResult
from mini_ops.config import NotifyConfig
from mini_ops.gate import Incident
from mini_ops.notify import Notifier, render_alert, render_digest
from mini_ops.triage import Verdict

INC = Incident(
    "job_down",
    "asr",
    "asr|job_down",
    "asr 没有在运行",
    "DOWN",
    evidence=("ERROR boom token=abcdefgh1234", "second", "third", "fourth"),
)
V = Verdict(
    "act", "high", "ASR 进程退出", "进程被 SIGKILL，launchd 未拉起", "kickstart", "查内存", ""
)


def test_alert_has_diagnosis_evidence_action_and_no_secrets():
    r = ActionResult("kickstart", "asr", True, True, "pid=7")
    title, text = render_alert(INC, V, r)
    # the phone only shows subject + title (DSH drops `text` in a notify note): all of it is in the title
    assert title.startswith("ASR 进程退出 ｜ 诊断：进程被 SIGKILL")
    assert "\n" not in title and len(title) <= 290
    assert "已执行 kickstart：成功" in title and "建议：查内存" in title
    assert text.startswith("【运维】asr：ASR 进程退出") and "证据：" in text
    assert "abcdefgh1234" not in text and "fourth" not in text  # redacted, max 3 evidence lines


def test_alert_refused_action_and_fallback_without_llm():
    r = ActionResult("kickstart", "asr", False, False, "", "冷却中")
    assert "未执行 kickstart：冷却中" in render_alert(INC, V, r)[0]
    title, text = render_alert(INC, None, None, note="LLM 不可用：今日调用已达上限")
    assert "asr 没有在运行" in title and "LLM 不可用" in title and "LLM 不可用" in text
    v2 = Verdict("act", "low", "s", "d", None, "", "rm_rf")
    assert "不在允许清单" in render_alert(INC, v2, None)[0]


def test_digest_groups_and_orders_by_count():
    items = {
        "a": {
            "service": "kaorou-daemon",
            "summary": "RSS feed failed",
            "count": 12,
            "why": "LLM 判定噪音",
            "last": 1_000_000.0,
        },
        "b": {"service": "asr", "summary": "slow", "count": 2, "why": "静音", "last": 1_000_000.0},
    }
    title, text = render_digest(
        items, {"actions": ["asr kickstart 成功"], "llm": "今日 LLM 3 次 $0.001"}, 0
    )
    assert "2 类" in title and "共 14 次" in title and "\n" not in title and len(title) <= 290
    assert title.index("RSS feed") < title.index("slow") and "×12" in title
    assert text.index("RSS feed") < text.index("slow")
    assert "本期动作：asr kickstart 成功" in text and "今日 LLM 3 次" in text


def mk(tmp_path, posts, max_per_hour=2, clock=lambda: 1000.0):
    tok = tmp_path / "tok"
    tok.write_text("hosttoken123\n")
    state = {"sent": [], "outbox": []}
    cfg = NotifyConfig(token_file=tok, max_per_hour=max_per_hour)

    def post(url, headers, body, timeout):
        posts.append((url, headers, json.loads(body)))
        return posts_status.pop(0) if posts_status else (202, b'{"outcome":"accepted"}')

    posts_status: list = []
    n = Notifier(cfg, state, post=post, clock=clock)
    return n, state, posts_status


def test_enqueue_flush_posts_the_right_event(tmp_path):
    posts: list = []
    n, state, _ = mk(tmp_path, posts)
    assert n.enqueue("alert", "k1", "asr", "title", "text")
    assert n.flush() == (1, 0) and state["outbox"] == []
    url, headers, body = posts[0]
    assert url.endswith("/hooks/lsy") and headers["Authorization"] == "Bearer hosttoken123"
    assert body == {
        "kind": "host.ops.alert",
        "key": "k1",
        "subject": "asr",
        "title": "title",
        "text": "text",
    }


def test_hourly_cap_and_uncapped_digest(tmp_path):
    n, state, _ = mk(tmp_path, [], max_per_hour=2)
    assert n.enqueue("alert", "a", "s", "t", "x") and n.enqueue("alert", "b", "s", "t", "x")
    assert n.enqueue("alert", "c", "s", "t", "x") is False  # over the cap -> caller digests it
    assert n.enqueue("digest", "d", "s", "t", "x", capped=False) is True
    assert len(state["outbox"]) == 3


def test_same_key_is_not_queued_twice(tmp_path):
    n, state, _ = mk(tmp_path, [])
    n.enqueue("alert", "a", "s", "t", "x")
    n.enqueue("alert", "a", "s", "t", "x")
    assert len(state["outbox"]) == 1


def test_failure_backs_off_and_retries(tmp_path):
    t = [1000.0]
    n, state, status = mk(tmp_path, [], clock=lambda: t[0])
    n.enqueue("alert", "a", "s", "t", "x")
    status.append((0, b"ConnectionRefusedError"))
    assert n.flush() == (0, 1) and state["outbox"][0]["tries"] == 1
    assert n.flush() == (0, 0)  # backing off
    t[0] += 301
    assert n.flush() == (1, 0) and state["outbox"] == []


def test_auth_error_drops_instead_of_retrying_forever(tmp_path):
    n, state, status = mk(tmp_path, [])
    n.enqueue("alert", "a", "s", "t", "x")
    status.append((401, b'{"error":"bad token"}'))
    assert n.flush() == (0, 1) and state["outbox"] == []


def test_missing_token_keeps_the_queue(tmp_path):
    n, state, _ = mk(tmp_path, [])
    n.cfg.token_file.unlink()
    n.enqueue("alert", "a", "s", "t", "x")
    assert n.flush() == (0, 0) and len(state["outbox"]) == 1


def test_daily_cap(tmp_path):
    t = [0.0]
    n, state, _ = mk(tmp_path, [], max_per_hour=99, clock=lambda: t[0])
    n.cfg = NotifyConfig(token_file=n.cfg.token_file, max_per_hour=99, max_per_day=3)
    for i in range(3):
        t[0] += 4000
        assert n.enqueue("alert", f"k{i}", "s", "t", "x")
    t[0] += 4000
    assert n.enqueue("alert", "k9", "s", "t", "x") is False
    t[0] += 86400
    assert n.enqueue("alert", "k10", "s", "t", "x") is True
