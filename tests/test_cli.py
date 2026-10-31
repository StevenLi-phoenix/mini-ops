import json

import pytest

from mini_ops import cli

CONF = """
[ops]
state_dir = "{state}"
tick_s = 1
[llm]
key_file = "{tmp}/key"
[notify]
token_file = "{tmp}/tok"
url = "http://127.0.0.1:9/hooks/lsy"
[[service]]
id = "asr"
launchd = "gui/501/com.asr.service"
expect = "running"
actions = ["kickstart"]
"""


@pytest.fixture
def conf(tmp_path):
    p = tmp_path / "ops.toml"
    p.write_text(CONF.format(state=tmp_path / "state", tmp=tmp_path))
    return p


def test_parse_duration():
    assert cli.parse_duration("90s") == 90 and cli.parse_duration("2h") == 7200
    with pytest.raises(Exception):
        cli.parse_duration("soon")


def test_check_reports_missing_credentials(conf, capsys):
    assert cli.main(["-c", str(conf), "check"]) == 0
    out = capsys.readouterr().out
    assert "asr" in out and "llm key: MISSING" in out and "notify token: MISSING" in out


def test_bad_config_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[[service]]\nid = 'Bad Id'\n")
    assert cli.main(["-c", str(bad), "check"]) == 2
    assert "service.id" in capsys.readouterr().err


def test_freeze_roundtrip(conf, capsys):
    assert cli.main(["-c", str(conf), "freeze", "add", "asr", "30m", "migration"]) == 0
    assert "frozen asr" in capsys.readouterr().out
    cli.main(["-c", str(conf), "freeze", "list"])
    assert "asr" in capsys.readouterr().out
    cli.main(["-c", str(conf), "freeze", "rm", "asr"])
    assert "removed" in capsys.readouterr().out


def test_status_before_first_tick(conf, capsys):
    assert cli.main(["-c", str(conf), "status"]) == 0
    assert "LLM today: 0/40" in capsys.readouterr().out


def test_test_notify_without_token_stays_queued(conf, tmp_path, capsys):
    assert cli.main(["-c", str(conf), "test-notify"]) == 1
    assert "queued=1" in capsys.readouterr().out


def test_run_once_survives_everything_unavailable(conf, tmp_path, capsys):
    # launchctl says the job is not loaded; no credentials; no network. A tick must not raise.
    assert cli.main(["-c", str(conf), "run", "--once"]) == 0
    st = json.loads((tmp_path / "state" / "state.json").read_text())
    assert st["baselined"] is True and "asr" in st["status"]["services"]


def test_digest_with_nothing_pending(conf, capsys):
    assert cli.main(["-c", str(conf), "digest"]) == 0
    assert "digest empty" in capsys.readouterr().out
