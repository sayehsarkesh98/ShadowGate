# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ShadowGate / Edge Manager — a single-file Cloudflare Worker that combines an Edge Tunnel proxy (VLESS/Trojan/Shadowsocks over WebSocket, gRPC, and XHTTP, with Chinese-named core functions) with a D1-backed user management layer (UUID accounts, bandwidth quotas, expiry, connection limits, Persian-language admin panel). Cloudflare D1 (SQLite) stores users/plans/settings; KV is also bound.

## Commands

```bash
npm run dev          # wrangler dev (local worker; use db:init:local first for a local D1)
npm run deploy       # wrangler deploy
npm run db:init      # apply schema.sql to remote D1 (edge-manager-db)
npm run db:init:local
npm run db:shell     # interactive D1 shell
node --check <file>  # syntax check (no test/lint runner exists in this repo)
```

No tests or linters are configured. Verify edits with `node --check` after every change.

## Build model (important — the modules are STALE, do not rebuild)

- `wrangler.toml` points `main` at **`src/edge-tunnel-managed.js`** — this ~11k-line single file is the *only* authoritative source. **Edit it directly.**
- **`build.py` and `merge.py` are stale and UNSAFE to run.** Their marker strings no longer match the built file (it says "SHADOWGATE MANAGEMENT SYSTEM", not the marker build.py searches for), and the built file contains ~15 management functions (`ensureTablesExist`, `mgmtAddActiveConnection`, `mgmtGetCleanIPs`, clean-IP endpoints, v2–v7 migrations, subnet-based device tracking…) that exist in **no** module. Running `build.py` would delete them and break the worker; `merge.py` would regress everything to an old upstream. `deploy.bat` runs `merge.py` — do not use it as-is; deploy with `npx wrangler deploy` only.
- `src/management.js`, `src/cron.js`, `src/migrations.js` are stale early drafts (2-arg `mgmtValidateUUID`, v2-only migrations). They do not deploy and should not be edited to "fix" anything — changes go in the built file.
- `src/index.js` is an older standalone API-only worker (own `/admin` panel, in-memory sessions). It is **not** the deployed entry point; don't confuse it with the live routes.

## Architecture

Request flow in `edge-tunnel-managed.js` (`export default` / `__fetchImpl` around line 4560):

1. `fetch` → `__fetchImpl`. First thing: `mgmtHandleRequest(request, env, ctx)`. If it returns a Response, that's the answer; if it returns `null`, the request falls through to the proxy core.
2. `mgmtHandleRequest` (~line 1589) returns `null` **immediately** for WebSocket upgrades and gRPC content-types (before any D1 work). It serves the hidden admin panel at `/{ADMIN_PATH}` (default `gate-x7k9p2` — the original `/admin` login is deliberately disabled, "stealth camouflage"), the user status panel at `/user-status`, the `/sub` subscription endpoint when `?token=`/`?uuid=` is present, and all `/api/*` management routes. Auth: password (`env.ADMIN` / `env.ADMIN_PASSWORD` / DB `settings.admin_password`; **no hardcoded fallback** — login fails closed) → 48-char CSPRNG bearer token stored as `settings` row `auth_token_<token>`, 24h expiry, purged by cron; `POST /api/auth/logout` deletes it. `mgmtCorsHeaders()` is deliberately same-origin only (no `*`).
3. Proxy core handles the rest: `/sub` (native subscription for the env `UUID`), `处理WS请求` (WebSocket), `处理gRPC请求`, XHTTP handling, `/version`, `/locations`, `/robots.txt`. Every path in `处理WS请求` that ends a WebSocket attempt must return a Response (the rejection paths return 403 after `serverSock.close(...)` — a bare `return;` there becomes a thrown exception → Cloudflare error 1101).

Management hooks into the proxy core (do not remove when touching proxy code):

- `获取活跃UUID列表(env)` — active UUID list with a 60s in-memory cache (empty results cached too; `clearUUIDCache()` invalidates), used by WS/gRPC/XHTTP handlers.
- `mgmtValidateUUID(env, uuid, clientIP, protocol)` — checks is_active, frozen, expiry, bandwidth cap, and connection cap **by `/24`–`/64` subnet groups** (`getSubnetGroup`). Fails **closed** (returns `false`) on DB errors.
- `mgmtTrackBandwidth(env, uuid, up, down)` — real byte accounting with 5% overhead compensation, flushed per 1 MB and at connection close via `ctx.waitUntil`.
- `mgmtAddActiveConnection` / `mgmtRemoveActiveConnection` / `mgmtHeartbeatConnection` — per-WebSocket rows in `active_connections` keyed by `connection_id`; stale rows (>5 min without heartbeat) are cleaned passively.

Bandwidth accounting is real bytes (the old 5-requests-per-KB estimate is retired; `REQUESTS_PER_KB` remains as a legacy constant).

Cron (`triggers.crons = ["0 0 * * *"]` → `scheduled` → `handleCron` in the built file): disables expired users, resets bandwidth per `bandwidth_reset_period` (reset marker advances on the shortest elapsed interval), queues expiry warnings, cleans old logs **and expired session tokens**, drains `notification_queue` in batches.

Schema: `schema.sql` (v1) and `schema-v2.sql` (v2). The runtime migration system inside the built file (`runMigrations`, version table, v2–v7) is authoritative — a fresh DB self-upgrades on first non-WS management request.

## Constraints

- The proxy core (WS/gRPC/XHTTP handling, VLESS/Trojan/SS parsing, TLS, `/sub`, Chinese-named utilities) is load-bearing and fragile — change it surgically, and keep the `mgmtHandleRequest` early-return + UUID-validation/tracking hooks intact.
- **Privacy invariants (do not regress):** never forward `CF-Connecting-IP`/`X-Forwarded-*`/`Cookie` etc. to the camouflage site in the camouflage reverse proxy; never store unmasked client IPs (use `maskIPForStorage` — subnet granularity only); never log client IPs to KV/Telegram (query strings are stripped too — they carry the subscription token); `/api/user/status` returns no admin-only fields (`last_ip`, `notes`, `telegram_id`, `tags`, `plan_id`).
- **Error-echo invariant:** exception details go to `console.error` only; responses to callers are generic unless `env.DEBUG` enables `DEBUG_ERROR_DETAIL`.
- Key env vars in `wrangler.toml` `[vars]`: `ADMIN_PATH` (secret panel path — change from the default), `UUID` (default single-user — rotated off the old public default on 2026-09-05), `HOSTNAME`/`PORT` (used in generated VLESS configs), `PROXYIP`, `DEBUG=1` for verbose logs and error traces. Dial concurrency (`PROXY_CONCURRENT_DIAL`/`TCP_CONCURRENT_DIAL`) is clamped to 8/4.
- `ADMIN` is an encrypted **wrangler secret** (set via `npx wrangler secret put ADMIN`), not a `[vars]` entry — login fails closed without it. `CAMOUFLAGE_URL`/`URL` still point at `example.com`; set a real camouflage site before production use.
