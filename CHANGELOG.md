# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/),
versioned with [SemVer](https://semver.org/).

## [Unreleased]

### Changed

- Archived: merged into agent-managed-services as `ams watch` (2026-10-31). The LLM triage layer was not carried over.

### Added

- Production config watches `system/app.lishuyu.ams` (observe only, no logs): AMS supervises disk-watch and global-awareness, and nothing else noticed when it stopped.

### Changed

- Production config drops the `tts` service: TTS moved to the laptop (feiyu), so `com.tts.service` is stopped and disabled on the mini.

## [0.1.0] - 2026-10-31

### Added

- Observe launchd jobs (`launchctl print`), HTTP and unix-socket health, rotation-safe log tails and Tailscale Service advertising.
- Deterministic gate: log signatures with NEW / BACK / FLAP, job-down grace, restart storm, consecutive failed probes.
- LLM triage through the owner's gateway: suppress or act, fenced and redacted input, raw response saved before parsing, per-day call and dollar caps.
- Guarded actions: `kickstart`, `soft_restart_kaorou`, `clean_tmp`, `advertise_tailscale` with cooldown, daily/hourly caps, freeze and the Kaorou burn guard.
- Notifications through DSH's `host` ingest source with a durable outbox, hourly/daily caps and a 09:00 / 21:00 digest.
- `mini-ops run | status | freeze | check | test-notify`, LaunchAgent plist, production config.
