# ngx_http_blocklist_module — Design Doc

**Date:** 2026-11-09 (revised 2026-11-10: dropped memcached L2, added REST API)
**Status:** Draft (pending approval)
**Author:** wenchi0920@gmail.com (with Claude)

---

## 1. Intent & Why

A nginx module that rejects requests whose client IP appears on a per-host
blocklist held in nginx shared memory. The blocklist is managed by a REST
API that the same module exposes; external systems add and remove entries
over HTTP. There is no central store — every nginx host holds its own
copy, and the external writer is responsible for pushing changes to each
host it cares about.

Why this architecture:

- The access-phase check must stay O(log n) in-memory, with no network
  I/O on the hot path. A per-host shared-memory table satisfies that.
- Blocklist membership changes are low-volume compared to request rate,
  so a push-based REST API from the writer is cheaper and simpler than
  any pull-based scheme.
- Multi-worker nginx means the table lives in shared memory (slab),
  mutated under the slab mutex by whichever worker handles the API call.
- Keeping state in-process removes the external-dependency failure mode
  that a central store would introduce.

---

## 2. Goals

- Reject requests from blocklisted IPs at the **access phase** with a
  configurable HTTP status (default `403`).
- Blocklist stored in nginx shared memory, shared across all workers on a
  host.
- Entries support optional TTL; no TTL = permanent until explicit delete.
- REST API (same module) for list / query / add / delete, authenticated
  by bearer token.
- Support IPv4 and IPv6 client addresses uniformly.
- Enable/disable the access check per `location` via a single directive.
- Non-blocking from end to end; no I/O on the request path.

## 3. Non-Goals / Anti-Goals (explicit MVP exclusions)

- No CIDR / prefix matching — exact IP only.
- No cross-host synchronisation. If the operator wants the blocklist on
  N hosts, the external writer calls the API on all N.
- No persistence across nginx restart. shared memory is wiped; the
  writer re-pushes on startup.
- No admin UI; API is machine-to-machine.
- No pagination on `GET /list` for MVP (document the practical cap in
  §9's sizing note).
- No audit log of API mutations in MVP (writer is expected to log on
  its side).
- **Anti-goal:** the access check must never block on anything slower
  than a shared-memory lookup. There is no fallback path, no external
  call, no timer.

## 4. Constraints

- All request-path work runs on the nginx event loop → access handler is
  purely in-memory, synchronous from the event-loop's perspective.
- Shared memory is shared across all workers → L1 structures protected
  by `ngx_slab_pool_t->mutex` (spinlock). Every critical section is
  O(log n) in-memory and holds no I/O.
- Shared memory is fixed-size at nginx start → insert-time eviction
  policy is mandatory (LRU on slab-alloc failure).
- `ngx_slab_alloc_locked` must be used while holding the slab mutex.
- IPv4 and IPv6 share the same table → store every address as `in6_addr`
  (IPv4-mapped form `::ffff:a.b.c.d`) so the comparator is a single
  `ngx_memcmp` over 16 bytes.
- Must honour operator-configured real-client-IP resolution — the module
  reads `r->connection->sockaddr` *after* `ngx_http_realip_module` has
  had a chance to rewrite it. See §9a.
- API handlers run in a *location*-mounted content handler, not at
  access phase, so request-body reading (`ngx_http_read_client_request_body`)
  is available for POST.

---

## 5. Approaches considered

### Approach A — single shared-memory table, in-process REST API *(chosen)*
L1 is a fixed-bucket hash table over the 16-byte address, with every
node also threaded into a global LRU doubly-linked list (`ngx_queue_t`).
This is the classic "LRU cache" structure: O(1) average-case lookup
via hash; O(1) LRU ordering via queue. Worst case degrades to O(chain
length), which crc32 over random IP addresses keeps small in practice.
Entries carry optional expire time. The same module registers a content
handler for the REST API paths.

- **+** Zero external dependency; the module is self-contained.
- **+** Access-phase handler is strictly synchronous — no cancellation
  safety story, no phase re-entry, no async state machine.
- **+** API writes land in the same shared memory the access handler
  reads, so a POST is visible to every worker on the host immediately.
- **−** No cross-host state; the writer must fan out to every host.
  Acceptable because fan-out is the writer's concern and keeps this
  module's responsibility small.
- **−** Blocklist is lost on nginx restart. Mitigated by the writer
  re-pushing on startup (a start-up contract documented in §8).

### Approach B — keep memcached as L2
Earlier draft. Rejected because the central-store model forced an async
access-handler state machine (cancellation safety, phase re-entry, L2
timeout handling) whose complexity dwarfed the module's core job. The
operational value of a shared store did not justify the implementation
surface.

### Approach C — file-backed blocklist with reload
nginx reads a blocklist file on `SIGHUP`.

- **+** Simple, nothing to authenticate.
- **−** Every change requires a full reload; coordination with other
  config changes on the host is awkward. Dynamic updates (temporary
  blocks, rate-limiter feedback) become slow and lossy.
- Rejected.

**Chosen: Approach A.**

---

## 6. Request flow (access phase)

```
┌─ access-phase handler ──────────────────────────────────────┐
│ 1. If blocklist is "off" for this location → NGX_DECLINED.  │
│ 2. Extract client IP from r->connection->sockaddr           │
│    (already rewritten by realip if configured — see §9a).   │
│    Normalise to 16-byte v4-mapped form.                     │
│ 3. L1 lookup (lock slab mutex, hash + chain walk, check     │
│    expire, on hit move node to LRU tail, unlock).           │
│      a. Hit (not expired)   → set r status code, return     │
│                                blocklist_status.            │
│      b. Hit but expired     → remove node, treat as miss.   │
│      c. Miss                → return NGX_DECLINED.          │
└──────────────────────────────────────────────────────────────┘
```

The handler holds the slab mutex only across the hash + chain walk,
the expire check, the LRU move, and possibly a slab free on expiry. It
never does I/O.

No per-request module context, no `NGX_AGAIN`, no phase re-entry. The
earlier design's §10b (cancellation safety for async L2) is deleted
because there is no async L2.

---

## 7. L1 — Shared memory layout

Shared zone is initialised once by the master process via
`ngx_shared_memory_add`. Its first allocation is a control struct:

```c
typedef struct {
    ngx_http_blocklist_node_t **buckets;    // hash table head array
    ngx_uint_t                  nbuckets;   // power of 2
    ngx_queue_t                 lru;        // head=oldest, tail=newest
    ngx_atomic_t                size;       // current entry count
    ngx_atomic_t                hits;       // access-phase BLOCK hits
    ngx_atomic_t                misses;     // access-phase misses (allowed)
    ngx_atomic_t                inserts;    // API POST successes
    ngx_atomic_t                deletes;    // API DELETE successes
    ngx_atomic_t                evictions;  // LRU-forced
    ngx_atomic_t                expirations;// removed because expire <= now
} ngx_http_blocklist_shctx_t;
```

`buckets` is a contiguous array of `nbuckets` pointers, allocated once
via `ngx_slab_alloc` at zone init. `nbuckets` is fixed at 16384 (a power
of 2, so `hash & (nbuckets - 1)` indexes without a divide); this costs
128 KiB on 64-bit before any entry is inserted, and keeps average chain
length ≤ 16 even at ~250 k entries.

Each cached IP is one slab allocation:

```c
typedef struct ngx_http_blocklist_node_s {
    struct ngx_http_blocklist_node_s *hash_next; // bucket chain (singly linked)
    ngx_queue_t   lru_queue;                     // in global LRU
    uint32_t      hash;                          // crc32(addr), cached
    u_char        addr[16];                      // in6_addr, v4-mapped for IPv4
    uint8_t       family;                        // AF_INET or AF_INET6 (for display)
    time_t        expire;                        // 0 = permanent, else ngx_time() + ttl
} ngx_http_blocklist_node_t;
```

**Lookup:** compute `hash = crc32(addr)`, then walk
`buckets[hash & (nbuckets - 1)]` comparing the cached `hash` first (one
integer compare per link), then `addr` via `ngx_memcmp` on hash match.
If `expire != 0 && expire <= ngx_time()`, unlink from chain and from
LRU, free, treat as miss.

**Insert (API POST):** compute `hash`, locate bucket, walk chain. If
the key exists, update `expire` and move the node to the LRU tail (no
reallocation). Otherwise `ngx_slab_alloc_locked`; on NULL, pop the LRU
head, unlink it from its bucket chain, free it (counting as an
eviction), retry. On repeat failure log once per minute at `notice`
and return `507 Insufficient Storage` to the API caller — correctness
is unaffected, only cache efficiency, but the writer needs to know its
push did not take effect.

**Delete (API DELETE):** locate bucket, unlink from chain, unlink from
LRU, slab free.

**LRU:** every access-phase hit moves the node to the queue tail; every
API insert of a new key appends to the tail; every refresh (POST on an
existing key) moves to the tail; eviction pops from the head.

**Locking:** `ngx_shmtx_lock(&shpool->mutex)` around every table / queue
op. The critical section contains no system calls other than
`ngx_slab_alloc_locked` / `ngx_slab_free_locked`.

---

## 8. REST API

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`    | `/ngx/api/v1/list`           | List all current entries. |
| `GET`    | `/ngx/api/v1/list?q=<ip>`    | Query whether one IP is blocked. |
| `POST`   | `/ngx/api/v1/ip`             | Add (or refresh) one IP. |
| `DELETE` | `/ngx/api/v1/ip?ip=<ip>`     | Remove one IP. |

Paths are matched exactly by the content handler; a method the endpoint
does not support returns `405 Method Not Allowed` with an `Allow` header
listing the supported methods.

### Authentication

Every request to the API endpoints must carry:

```
Authorization: Bearer <token>
```

The token is configured via `blocklist_api_token <token>;` in the same
`location` that mounts the API. A missing, malformed, or non-matching
token returns `401 Unauthorized` with no body.

The token is compared with `ngx_memn2cmp` in constant time to prevent
timing side-channels — standard practice for shared-secret auth. The
token itself is read from config at startup and held in the main
configuration; it is never logged.

Defense-in-depth: operators are expected to additionally gate the API
location with standard nginx `allow`/`deny` directives against a trusted
CIDR range. The module does not enforce this; the config snippet in the
README shows it.

### Request / response formats

All request and response bodies are JSON, `Content-Type:
application/json`. Response bodies have the shape:

```json
{"ok": true, "data": ...}
{"ok": false, "error": "human-readable", "code": "SNAKE_CASE"}
```

The JSON parser is a small hand-rolled parser scoped to exactly the
shapes below. No general-purpose JSON library is linked in; the input
surface is tiny and fixed.

#### `GET /ngx/api/v1/list`

Returns every non-expired entry.

```json
{"ok": true, "data": [
  {"ip": "1.2.3.4", "expire": 1762819200},
  {"ip": "2001:db8::1", "expire": 0}
]}
```

`expire` is a unix timestamp, or `0` for permanent entries. The list is
unordered. Iterating the table walks every bucket under the slab mutex,
so for very large
tables this is deliberately a slow call; see §9 sizing note.

#### `GET /ngx/api/v1/list?q=<ip>`

Returns one entry or 404. `<ip>` is URL-decoded and parsed with
`ngx_inet_addr` / `ngx_inet6_addr`; invalid input returns `400
Bad Request` with `code: "INVALID_IP"`.

```json
{"ok": true, "data": {"ip": "1.2.3.4", "expire": 1762819200}}
```

#### `POST /ngx/api/v1/ip`

Body:

```json
{"ip": "1.2.3.4", "ttl": 3600}
```

- `ip` (required): dotted-quad or compressed IPv6.
- `ttl` (optional): seconds until automatic expiry. Omitted or `0` means
  permanent.

Response: `201 Created` if the IP was newly added, `200 OK` if an
existing entry was refreshed. Body:

```json
{"ok": true, "data": {"ip": "1.2.3.4", "expire": 1762819200}}
```

Error cases:
- `400 INVALID_IP` — unparseable address.
- `400 INVALID_TTL` — non-integer or negative.
- `401 UNAUTHORIZED` — bad token.
- `413 BODY_TOO_LARGE` — body exceeds `client_max_body_size` (operator
  config) or the module's 4 KiB hard cap, whichever is smaller.
- `507 ZONE_FULL` — slab allocation failed after eviction attempt.

#### `DELETE /ngx/api/v1/ip?ip=<ip>`

Response `200 OK` if removed, `404 NOT_FOUND` if no such entry.

```json
{"ok": true, "data": {"ip": "1.2.3.4"}}
```

### Startup contract for the external writer

Because the blocklist does **not** persist across nginx restarts, the
writer is responsible for repopulating it on nginx startup. A reasonable
pattern:

- Writer holds the authoritative blocklist (database, file, whatever).
- On its own startup and on receipt of some "nginx restarted" signal
  (health-check transition, SIGHUP-driven webhook, periodic reconcile
  loop), it issues one `POST /ngx/api/v1/ip` per entry.
- Until that sync completes, requests pass through — this is a brief
  fail-open window after each nginx restart. Operators who cannot
  tolerate it must size the writer's sync to run before nginx is put
  into rotation (readiness probe gates traffic until sync is done).

This contract is the single most important coordination point between
this module and the writer. It belongs in the module's README once the
design is approved.

---

## 9. Configuration directives

| Directive | Context | Default | Meaning |
|---|---|---|---|
| `blocklist_zone zone=NAME:SIZE;` | `http` | — (required) | Create shared memory zone. |
| `blocklist_status CODE;`          | `http`, `server`, `location` | `403` | Status returned on BLOCK. |
| `blocklist on\|off;`              | `http`, `server`, `location` | `off` | Enable access check in this location. |
| `blocklist_api;`                  | `location` | — | Mount the REST API in this location. |
| `blocklist_api_token TOKEN;`      | `location` | — (required when `blocklist_api;`) | Shared secret for `Authorization: Bearer`. |

Precedence follows standard nginx merging; `blocklist on;` in a `location`
overrides a `server`-level `off`.

**MVP constraint — single zone.** `blocklist_zone` must appear exactly
once in the `http` block. The `zone=NAME` syntax is kept so future
versions can allow multiple blocklists, but for MVP all `blocklist on;`
locations share the one zone and `blocklist_api;` mounts refer to the
same zone implicitly.

**Example config:**

```nginx
http {
    blocklist_zone zone=bl:16m;
    blocklist_status 403;

    server {
        listen 80;

        # protected traffic
        location / {
            blocklist on;
            proxy_pass http://upstream;
        }

        # admin API — internal only
        location /ngx/api/v1/ {
            blocklist_api;
            blocklist_api_token "REPLACE_ME_WITH_RANDOM_BYTES";
            allow 10.0.0.0/8;
            deny  all;
        }
    }
}
```

**Sizing note.** Each entry costs ~`sizeof(ngx_http_blocklist_node_t)` +
slab overhead ≈ 80 bytes. A 16 MiB zone holds roughly 200 k entries
before LRU eviction pressure. `GET /list` iterates the whole table under
the slab mutex; expect it to pause the access handler for a few ms per
10 k entries. Treat `/list` as a diagnostic, not a hot path.

---

## 9a. Phase ordering & real-client-IP interaction

The access handler is registered into `NGX_HTTP_ACCESS_PHASE` via
`cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers` from the module's
`postconfiguration` callback.

`ngx_http_realip_module` does **not** run as a phase handler. It installs
handlers into `NGX_HTTP_POST_READ_PHASE` and
`NGX_HTTP_PREACCESS_PHASE` (both before `NGX_HTTP_ACCESS_PHASE`) that
rewrite `r->connection->sockaddr` in place. Therefore, by the time the
access handler runs, the sockaddr is already the real client IP as
configured by the operator.

Operator-side configuration (not this module's concern, documented here
so the model is clear):

```nginx
set_real_ip_from 10.0.0.0/8;          # trusted LB range
set_real_ip_from 2001:db8::/32;
real_ip_header   X-Forwarded-For;      # or CF-Connecting-IP, etc.
real_ip_recursive on;
```

Security property: the module trusts whatever IP realip gives it. If
realip is misconfigured (trusting a wider range than the operator owns,
or no realip at all while behind a proxy), the module will block on the
wrong IP. This is the standard nginx failure mode for anything reading
`$remote_addr` and is deliberately **not** re-solved here.

---

## 10. Module structure

```
ngx_blocklist_module/
├── config                                   # nginx add-module config
├── src/
│   ├── ngx_http_blocklist_module.c          # directive table, module def,
│   │                                          access handler
│   ├── ngx_http_blocklist_module.h
│   ├── ngx_http_blocklist_l1.c              # hash table + LRU on slab pool
│   ├── ngx_http_blocklist_l1.h
│   ├── ngx_http_blocklist_api.c             # REST API content handler,
│   │                                          auth, JSON in/out
│   └── ngx_http_blocklist_api.h
├── t/                                        # Test::Nginx::Socket tests
│   ├── 01-basic-block.t
│   ├── 02-api-add-delete.t
│   ├── 03-api-query.t
│   ├── 04-api-auth.t
│   ├── 05-ttl-expiry.t
│   ├── 06-ipv6.t
│   ├── 07-lru-eviction.t
│   ├── 08-realip-interaction.t
│   └── 09-concurrent-workers.t
├── docs/superpowers/specs/2026-11-09-ngx-ip-blocklist-design.md
└── README.md                                 # created only after approval
```

- `config` uses `HTTP_MODULES`, `NGX_ADDON_SRCS`, `NGX_ADDON_DEPS`.
- No external library dependencies (no JSON lib, no HTTP client).
  Builds with any nginx ≥ 1.18.

---

## 11. Testing

Use `Test::Nginx::Socket`. Each `.t` file spins up nginx with a config
stanza and asserts response code / headers / body / log lines.

Required cases:

1. `POST /ip` adds an IP → subsequent request from that IP returns 403;
   `DELETE /ip` removes it → next request returns 200.
2. `POST /ip` with `ttl: 2` → IP blocked, wait 3 s, request passes;
   confirm `expirations` counter ticked.
3. `POST /ip` with no `ttl` → IP stays blocked indefinitely (sleep
   short, re-request, still 403; counter on expirations unchanged).
4. `GET /list` returns all current entries; `GET /list?q=<ip>` returns
   one entry or 404; invalid IP → 400.
5. Missing `Authorization` header → 401; wrong token → 401; correct
   token → 200.
6. IPv6 client address, `POST` the IPv6 as compressed lowercase → 403
   on subsequent request from that address; `DELETE` with same form
   removes it.
7. Zone sized to hold ~5 entries; `POST` a 6th → oldest (by LRU) is
   evicted, `evictions` counter increments.
8. `blocklist off;` location → 200 regardless of blocklist content.
9. `realip` interaction: `set_real_ip_from <mock-lb>; real_ip_header
   X-Forwarded-For;` configured; request from mock-lb with
   `X-Forwarded-For: <blocked-ip>` → 403. Second request with a
   different XFF → 200.
10. Two workers, concurrent POST + access traffic for 1 s, no crash,
    `inserts + deletes` counters consistent with issued API calls.

No mock memcached is needed. Tests exercise the API handler directly
via `Test::Nginx::Socket`'s HTTP client.

---

## 12. Observability (MVP)

- `error.log` entries at:
  - `notice`: L1 zone exhaustion (rate-limited to once per minute per
    worker).
  - `info`: 4xx API responses (log method, path, remote_addr, status,
    `code` — **never** the token or body).
  - `warn`: unexpected parser state in API body (short, unlabelled;
    useful for catching writer bugs).
- `access.log` captures the API endpoints as usual.
- Atomic counters in the shared control struct (`hits`, `misses`,
  `inserts`, `deletes`, `evictions`, `expirations`) — exposed via a
  later admin endpoint (post-MVP), useful for gdb / `ngx-debug` today.

---

## 13. What's left to the builder

Minor decisions a competent nginx-module developer can settle without
changing the spec:

- Exact log format strings and levels within the ranges given.
- Whether to use `ngx_crc32_long` or `ngx_murmur_hash2` for the hash
  key — either is fine; both distribute IP bytes well across buckets.
- Whether `nbuckets` stays at the fixed 16384 or becomes a function of
  `blocklist_zone` size (e.g. `size / 1 KiB` rounded to next power of
  2). Fixed is fine for MVP.
- Initial slab-zone sizing hint in docs (10–64 MiB depending on
  working-set estimates; see §9).
- API body read buffering strategy (nginx's standard
  `ngx_http_read_client_request_body` + `r->request_body->bufs` chain
  walk; concatenate into a 4 KiB stack buffer because bodies are tiny).
- Whether `GET /list` streams or buffers its response (buffer is fine
  for MVP; streaming is a post-MVP optimisation once operators hit
  size limits).

Explicitly deferred to post-MVP tickets:

- CIDR / prefix support.
- Persistence snapshot to disk + load on startup.
- Pagination on `GET /list`.
- Audit log of mutations (separate log file, structured).
- Multi-zone / multi-tenant.
- Prometheus-format metrics endpoint.
- Cross-host sync built into the module (webhook fan-out).

---

## 14. Open risks

1. **Fail-open window after nginx restart.** Until the writer finishes
   its re-sync, no IP is blocked. Operators who cannot tolerate this
   must gate traffic on a readiness probe that passes only after sync.
   Document prominently in README.
2. **`GET /list` under load.** Iterates under the slab mutex; a large
   table + a well-meaning cronjob that polls `/list` every second will
   stall access-handler lookups. Document as "treat /list as diagnostic".
3. **Token leaks.** The token is a long-lived shared secret. Rotation
   requires a config reload (`SIGHUP`). Operators should bind the API
   location to an internal-only CIDR regardless; the token is the
   second gate, not the only one.
4. **Zone resize requires nginx restart.** nginx shared zones cannot be
   resized live. Operators must size for peak unique-IP working set.
5. **Clock skew.** `expire` is `ngx_time()` based (per-worker cached
   time). A worker that is paused by the kernel for several seconds
   may briefly serve an expired entry. Negligible in practice.

---

## 15. Approval

Build begins once this document is approved. Implementation then proceeds
through the `superpowers:writing-plans` skill for a step-by-step plan,
tracked in `docs/superpowers/plans/`.
