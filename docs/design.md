# Design notes

## Goal

The owner asked for exactly one thing on the Mac mini: *an LLM that watches the services, decides
per warning/error whether to suppress it or handle it, and tells the owner.* No isolation layer, no
moving services between users: the services keep running as they are under launchd.

## Reuse decisions

| Candidate | Verdict | Why |
|---|---|---|
| **AMS supervisor** (`agent-managed-services` 2.0.0) | Not used as a supervisor | AMS owns its children as direct subprocesses. These jobs belong to launchd (and one is in the system domain), so an "observe-only AMS" would have none of the machinery that makes AMS what it is (spawner, cgroups, restart policy). |
| **AMS library parts** | Used | `ams.events.LogLine` (severity heuristics), `ams.platform.policy.cause_key`, `ams.escalations.EscalationJournal` (the "one JSON line per escalation" journal). Pinned by commit in `pyproject.toml`. |
| **AMS decision model** | Used, changed in one place | SUPPRESS/ESCALATE stay the vocabulary. AMS keeps the model out of the loop on purpose (log text is attacker-controlled; suppression is the dangerous verdict). Here the model is inside, so: its input is fenced and redacted, it can only name an action from a closed list, code enforces every limit, and a "suppress" is a *remembered, audited* verdict with a 3-day TTL, not a rule it can write. |
| **DSH `ga-watch`** (the operator session's own watcher for global-awareness) | Used | Signature (level, msg, source) + NEW / BACK-after-12h / FLAP (>=5 in 1 h, one report per 6 h) + a baseline pass at start. Replayed cold over 13,747 records it emits 65 lines in 7.9 days (8.2/day). |
| **DSH ingest + bus** | Used as the notification channel | `host` source -> `host-alerts` subscription -> WeChat note, no model, deduped by `key`. No DSH deploy needed. |
| **`api` llm-ops** (`packages/ops`) | Ideas only | Failure class = key; `minOccurrences` before anything is reported; `maxAttempts` per day; evidence retained with the report; tokens from files, never persisted in config. Its output (a GitHub issue) is not wanted here. |

## Replay of the gate (offline, read-only)

Input: the AMS escalation journal of `global-awareness` (13,747 records, 2026-10-23..31, 21 distinct
messages, 99.8 % repeats).

| Rule set | Output |
|---|---|
| AMS default (`DEFAULT_WINDOW_S` 600 s, per cause) | 13,747 escalations (~1,700/day) |
| DSH `ga-watch` (cold start, no baseline) | 65 emitted: 32 BACK, 27 NEW, 6 FLAP |
| mini-ops gate, signature = whole line | 1,694 opens, 550 signatures (numbers inside JSON defeat it) |
| mini-ops gate, structured-log signature (level, msg, source) | **341 opens, 58 signatures** (58 NEW, 57 BACK, 226 FLAP); of these only NEW and BACK reach the model, FLAP of a cached "suppress" goes to the digest |

## Safety model

1. Log lines, process names and error messages are data. `text.sanitize` strips controls and redacts
   bearer tokens, `llmgw_`/`pat_`/`sk-` keys, JWTs, `token=`/`SESSDATA=`-style pairs and long hex before
   anything reaches the model or the phone. The prompt fences them and says so.
2. The model returns JSON: `verdict`, `severity`, `summary`, `diagnosis`, `action{name}`, `advice`.
   An action name outside the service's allow-list is dropped and reported as "not on the list".
3. `actions.Executor` order of refusal: unknown service, not allowed for this service, frozen,
   hard rules (never `kickstart` a `*.kaorou.daemon`), cooldown (30 min), per-target cap (3/day),
   global cap (4/h), `soft_restart_kaorou` guard (ffmpeg process **or** any running job **or** an
   unreachable API **or** a non-running daemon -> refuse), `dry-run`.
4. Everything spawned is an argv list with a timeout; no shell.
5. Credentials are files (0600): the gateway key (daily USD cap on the gateway side) and the DSH
   `host` token. Neither is in the config, the repo, the state file or a log.
6. `dsh-events` has no actions and only its `stderr.log` is read (`stdout.log` carries a login URL).

## Known limits

- If `dsh-events` is down the owner gets nothing until it is back: notifications wait in a durable
  outbox (8 retries, backoff to 1 h, then dropped with an error log). There is no second channel.
- The WeChat note shows subject and title only; long diagnoses live in `incidents.jsonl`.
- A hung (alive but stale) Kaorou daemon is not detected yet; `/system` has `daemon.stale`.
- Triage is capped at 3 calls per tick; the rest wait in a backlog (50).
- Reuses the `host` token. A dedicated `ops` source would need a DSH config change and restart.
