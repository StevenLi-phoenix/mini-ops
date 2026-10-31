"""``mini-ops``: run the loop, or poke at it (status, freeze, a test notification)."""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import logging.handlers
import os
import signal
import sys
import time
from pathlib import Path

from ams.escalations import EscalationJournal

from mini_ops import freeze as freeze_mod
from mini_ops.config import Config, ConfigError, load
from mini_ops.engine import Engine
from mini_ops.notify import Notifier
from mini_ops.store import Store
from mini_ops.triage import Triage

log = logging.getLogger("mini_ops")
DEFAULT_CONFIG = Path("~/.config/mini-ops/ops.toml").expanduser()
_DURATION = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> float:
    try:
        return float(text[:-1]) * _DURATION[text[-1]]
    except (KeyError, ValueError, IndexError):
        raise argparse.ArgumentTypeError(f"{text!r}: use e.g. 90s, 30m, 2h, 1d") from None


def setup_logging(cfg: Config, verbose: bool, to_file: bool) -> None:
    handlers: list[logging.Handler] = []
    if verbose or not to_file or sys.stderr.isatty():
        handlers.append(logging.StreamHandler(sys.stderr))  # under launchd the file is the log
    if to_file:
        d = cfg.state_dir / "logs"
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                d / "mini-ops.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
        )
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        handlers=handlers,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )


def build(cfg: Config) -> tuple[Engine, Store]:
    cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = Store(cfg.state_dir / "state.json")
    triage = Triage(cfg.llm, cfg.state_dir / "raw")
    notifier = Notifier(cfg.notify, store.data)
    journal = EscalationJournal(cfg.state_dir / "logs" / "incidents.jsonl", "mini-ops")
    return Engine(cfg, store, triage, notifier, journal=journal), store


def _lock(cfg: Config):
    fh = open(cfg.state_dir / "lock", "w")  # noqa: SIM115 - held for the process lifetime
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("mini-ops: another instance holds the state lock")
    return fh


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    engine, store = build(cfg)
    _lock_fh = _lock(cfg)  # noqa: F841
    stop = {"now": False}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.__setitem__("now", True))
    log.info(
        "mini-ops started: %d services, tick %.0fs, mode=%s, model=%s",
        len(cfg.services),
        cfg.tick_s,
        cfg.mode,
        cfg.llm.model,
    )
    while not stop["now"]:
        t0 = time.monotonic()
        try:
            rep = engine.tick()
            if rep.incidents:
                log.info(
                    "tick: incidents=%d triaged=%d suppressed=%d alerts=%d actions=%d",
                    rep.incidents,
                    rep.triaged,
                    rep.suppressed,
                    rep.alerts,
                    len(rep.actions),
                )
        except Exception:  # the loop must outlive any single bad tick
            log.exception("tick failed")
        if args.once:
            break
        slept = 0.0
        while not stop["now"] and slept < max(0.0, cfg.tick_s - (time.monotonic() - t0)):
            time.sleep(0.5)
            slept += 0.5
    store.save()
    log.info("mini-ops stopped")
    return 0


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    d = Store(cfg.state_dir / "state.json").data
    st = d.get("status", {})
    age = time.time() - st.get("ts", 0)
    print(
        f"last tick: {age:.0f}s ago   backlog={st.get('backlog', 0)} outbox={st.get('outbox', 0)} "
        f"digest-pending={len(d['digest'])}   mode={cfg.mode}"
    )
    for sid, info in st.get("services", {}).items():
        job, hl = info.get("job"), info.get("health")
        bits = []
        if job is not None:
            bits.append(
                "not loaded"
                if not job["loaded"]
                else f"{job['state']} pid={job['pid']} runs={job['runs']}"
            )
        if hl is not None:
            bits.append(f"health={'ok' if hl['ok'] else hl['detail']}")
        print(f"  {sid:<18} {'  '.join(bits)}")
    day = time.strftime("%Y-%m-%d")
    b = d["budget"].get(day, {"calls": 0, "usd": 0.0})
    print(
        f"LLM today: {b['calls']}/{cfg.llm.daily_calls} calls, ${b['usd']:.4f}/${cfg.llm.daily_usd:.2f}"
    )
    for fz in freeze_mod.load(cfg.config_dir / "freeze.json").values():
        left = int(fz.until - time.time())
        print(
            f"  FROZEN {fz.service} for {left // 60} more min ({fz.reason}; {'muted' if fz.mute else 'actions off'})"
        )
    recent = d["actions"][-5:]
    for h in recent:
        print(
            f"  action {time.strftime('%m-%d %H:%M', time.localtime(h['ts']))} {h['target']} {h['action']} -> {h['outcome']}"
        )
    if args.json:
        print(json.dumps(st, indent=1, default=str))
    return 0


def cmd_freeze(cfg: Config, args: argparse.Namespace) -> int:
    path = cfg.config_dir / "freeze.json"
    if args.op == "add":
        fz = freeze_mod.add(
            path, args.service, args.duration, args.reason, mute=not args.keep_alerts
        )
        print(
            f"frozen {fz.service} until {time.strftime('%H:%M', time.localtime(fz.until))} ({fz.reason})"
        )
    elif args.op == "rm":
        print("removed" if freeze_mod.remove(path, args.service) else "not frozen")
    else:
        for fz in freeze_mod.load(path).values():
            print(
                f"{fz.service}\t{time.strftime('%F %T', time.localtime(fz.until))}\t"
                f"{'mute' if fz.mute else 'no-actions'}\t{fz.reason}"
            )
    return 0


def cmd_test_notify(cfg: Config, args: argparse.Namespace) -> int:
    store = Store(cfg.state_dir / "state.json")
    n = Notifier(cfg.notify, store.data)
    stamp = time.strftime("%Y%m%d%H%M%S")
    n.enqueue(
        "test",
        f"ops-test-{stamp}",
        "mini-ops",
        "【运维】测试通知",
        args.text or "mini-ops 通知链路测试：如果你在微信里看到这条，链路是通的。",
        capped=False,
    )
    delivered, failed = n.flush()
    store.save()
    print(f"delivered={delivered} failed={failed} queued={len(store.data['outbox'])}")
    return 0 if delivered else 1


def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    print(f"ok: {len(cfg.services)} services, mode={cfg.mode}, state={cfg.state_dir}")
    for s in cfg.services:
        print(
            f"  {s.id:<18} {s.launchd or '-':<48} expect={s.expect:<9} actions={','.join(s.actions) or '-'}"
        )
    for label, path in (("llm key", cfg.llm.key_file), ("notify token", cfg.notify.token_file)):
        print(f"  {label}: {'present' if path.is_file() else 'MISSING'} ({path})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mini-ops", description=__doc__)
    ap.add_argument(
        "-c", "--config", type=Path, default=Path(os.environ.get("MINI_OPS_CONFIG", DEFAULT_CONFIG))
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the loop")
    r.add_argument("--once", action="store_true", help="one tick, then exit")
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    f = sub.add_parser("freeze", help="planned maintenance: stop actions (and mute) for a service")
    fs = f.add_subparsers(dest="op", required=True)
    fa = fs.add_parser("add")
    fa.add_argument("service", help="service id, or * for all")
    fa.add_argument("duration", type=parse_duration)
    fa.add_argument("reason")
    fa.add_argument(
        "--keep-alerts", action="store_true", help="still triage and notify; only block actions"
    )
    fr = fs.add_parser("rm")
    fr.add_argument("service")
    fs.add_parser("list")
    t = sub.add_parser("test-notify", help="send one test message through the DSH host source")
    t.add_argument("text", nargs="?")
    sub.add_parser("check", help="validate the config and the credential files")
    args = ap.parse_args(argv)
    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"mini-ops: {e}", file=sys.stderr)
        return 2
    setup_logging(cfg, args.verbose, to_file=args.cmd == "run")
    fn = {
        "run": cmd_run,
        "status": cmd_status,
        "freeze": cmd_freeze,
        "test-notify": cmd_test_notify,
        "check": cmd_check,
    }[args.cmd]
    return fn(cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())
