# ngx_http_blocklist_module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an nginx dynamic module that drops requests from blocklisted IPs at the access phase, backed by a shared-memory hash+LRU table populated and queried through a bearer-token-authenticated REST API.

**Architecture:** Single nginx module, three internal units: (1) `_l1.c` manages the shared-memory hash table with LRU eviction, (2) `_api.c` hosts the REST API content handler with JSON body parsing and auth, (3) `_module.c` wires directives, module definition, and the access-phase handler. All request-path work is synchronous shared-memory lookups under the slab mutex; no external store.

**Tech Stack:** C against nginx core (≥ 1.18), nginx shared slab pool, `ngx_rbtree` is *not* used (custom hash table + `ngx_queue_t` LRU per spec §7). Tests use `Test::Nginx::Socket`.

**Spec:** `docs/superpowers/specs/2026-11-09-ngx-ip-blocklist-design.md`

## Global Constraints

- nginx ≥ 1.18. No external library dependency (no JSON lib, no HTTP client).
- IPv4 and IPv6 share one table; stored as 16-byte IPv4-mapped form (`::ffff:a.b.c.d` for IPv4). Comparator is `ngx_memcmp` over 16 bytes.
- All shared-memory operations run under `ngx_shmtx_lock(&shpool->mutex)`; critical section contains no syscalls other than `ngx_slab_alloc_locked` / `ngx_slab_free_locked`.
- `blocklist_zone` appears exactly once in `http{}`; `nbuckets` fixed at `16384`.
- API responses: `Content-Type: application/json`, shape `{"ok": true, "data": ...}` or `{"ok": false, "error": "...", "code": "SNAKE_CASE"}`.
- Bearer token comparison must be constant-time (`ngx_memn2cmp`); token never logged.
- Hard 4 KiB cap on API request body.
- Default directive values: `blocklist off`, `blocklist_status 403`.
- All code comments in English; commit messages in English following Conventional Commits.
- IPv6 keys stored and surfaced by `inet_ntop`-equivalent output (compressed lowercase, no brackets, no zone id). Reject input with zone id (`%eth0`) at parse.

## Review Focus

Input classes the spec implies but no happy-path test covers — each gets a test in the owning task below.

1. **Malformed JSON POST body** (truncated, non-object, missing `ip`) → 400 with `code: "INVALID_IP"` or `"INVALID_BODY"`; no crash. *Owned by Task 3, extra test in Step list.*
2. **POST body > 4 KiB** → 413 `BODY_TOO_LARGE`; body never fully buffered. *Owned by Task 3.*
3. **IPv6 variant forms on input** — uppercase (`2001:DB8::1`), fully expanded, IPv4-mapped literal (`::ffff:1.2.3.4`), zone id (`fe80::1%eth0`): accept the first three, normalize to v4-mapped internal form; reject the fourth with 400 `INVALID_IP`. *Owned by Task 7.*
4. **URL-encoded / missing `?ip=` or `?q=` on GET/DELETE** — missing → 400 `MISSING_PARAM`; percent-encoded IPv6 colons are decoded correctly. *Owned by Tasks 3 and 5.*
5. **Timing side-channel on token compare** — token comparison uses `ngx_memn2cmp` even when the provided token differs in length from the configured token; no early exit on first mismatched byte. *Owned by Task 4, test is a structural code assertion plus a wrong-length negative test.*

---

## File Structure

```
ngx-ip-blocklist/
├── config                                   # add-module config, built in Task 1
├── src/
│   ├── ngx_http_blocklist_module.h          # shared types, exported L1 fns (Task 2)
│   ├── ngx_http_blocklist_module.c          # module def, directives, access handler (Tasks 1,2,3)
│   ├── ngx_http_blocklist_l1.h              # L1 public API (Task 2)
│   ├── ngx_http_blocklist_l1.c              # hash table + LRU on slab pool (Tasks 2,3,6,8)
│   ├── ngx_http_blocklist_api.h             # API public entrypoint (Task 3)
│   └── ngx_http_blocklist_api.c             # content handler, JSON in/out, auth (Tasks 3,4,5)
├── t/
│   ├── 00-sanity.t                          # Task 1
│   ├── 01-zone-init.t                       # Task 2
│   ├── 02-basic-block.t                     # Task 3
│   ├── 03-api-auth.t                        # Task 4
│   ├── 04-api-get.t                         # Task 5
│   ├── 05-ttl-expiry.t                      # Task 6
│   ├── 06-ipv6.t                            # Task 7
│   ├── 07-lru-eviction.t                    # Task 8
│   ├── 08-realip.t                          # Task 9
│   └── 09-concurrent-workers.t              # Task 10
└── docs/superpowers/plans/2026-11-10-ngx-ip-blocklist-implementation.md
```

Each `.c` file owns one concern; cross-file calls go through the matching `.h`. The access handler stays in `_module.c` next to the directive table because they share the loc-conf lookup; L1 CRUD is factored out so the API handler can call it without pulling in module-config internals.

---

## Task 1: Build scaffold & module loads

**Files:**
- Create: `config`
- Create: `src/ngx_http_blocklist_module.c`
- Create: `src/ngx_http_blocklist_module.h`
- Create: `t/00-sanity.t`

**Interfaces:**
- Consumes: nothing.
- Produces: `ngx_http_blocklist_module` (nginx `ngx_module_t` symbol) — referenced by every later file.

- [ ] **Step 1: Write failing test `t/00-sanity.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: module loaded, nginx starts with empty http{}
--- config
    location / { return 204; }
--- request
GET /
--- error_code: 204
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/00-sanity.t`
Expected: FAIL — module does not build / is not loaded.

- [ ] **Step 3: Write `config`**

Standard `HTTP_MODULES`, `NGX_ADDON_SRCS`, `NGX_ADDON_DEPS` for `ngx_http_blocklist_module`. Sources: just `_module.c` for this task; add the others as they appear.

- [ ] **Step 4: Write `src/ngx_http_blocklist_module.h`**

Declare `extern ngx_module_t ngx_http_blocklist_module;` and include-guard. Nothing else yet.

- [ ] **Step 5: Write `src/ngx_http_blocklist_module.c`**

Define `ngx_http_blocklist_module` with empty `ngx_http_module_t ctx` (all callbacks NULL except `create_main_conf`/`create_loc_conf` which return palloc'd zeroed structs so later tasks can extend) and empty `ngx_command_t commands[]`.

Also define the empty conf structs:
```c
typedef struct { ngx_shm_zone_t *shm_zone; } ngx_http_blocklist_main_conf_t;
typedef struct { /* filled in Task 3 */ } ngx_http_blocklist_loc_conf_t;
```

- [ ] **Step 6: Build & run test**

Build nginx with `./configure --add-dynamic-module=...`. Run `prove -v t/00-sanity.t`.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add config src/ngx_http_blocklist_module.{c,h} t/00-sanity.t
git commit -m "feat: scaffold ngx_http_blocklist_module skeleton"
```

---

## Task 2: `blocklist_zone` directive + shared-memory init

**Files:**
- Modify: `src/ngx_http_blocklist_module.c` (add directive + main-conf handling)
- Create: `src/ngx_http_blocklist_l1.h`
- Create: `src/ngx_http_blocklist_l1.c`
- Create: `t/01-zone-init.t`

**Interfaces:**
- Consumes: `ngx_http_blocklist_module` from Task 1.
- Produces:
  - Types in `_l1.h`:
    ```c
    typedef struct ngx_http_blocklist_node_s {
        struct ngx_http_blocklist_node_s *hash_next;
        ngx_queue_t  lru_queue;
        uint32_t     hash;
        u_char       addr[16];
        uint8_t      family;      // AF_INET or AF_INET6
        time_t       expire;      // 0 = permanent
    } ngx_http_blocklist_node_t;

    typedef struct {
        ngx_http_blocklist_node_t **buckets;
        ngx_uint_t                  nbuckets;
        ngx_queue_t                 lru;
        ngx_atomic_t                size;
        ngx_atomic_t                hits, misses;
        ngx_atomic_t                inserts, deletes;
        ngx_atomic_t                evictions, expirations;
    } ngx_http_blocklist_shctx_t;

    #define NGX_HTTP_BLOCKLIST_NBUCKETS 16384

    ngx_int_t ngx_http_blocklist_l1_init_zone(ngx_shm_zone_t *shm_zone, void *data);
    ```
  - `blocklist_zone zone=NAME:SIZE;` directive in `http{}`, main-conf.

- [ ] **Step 1: Write failing test `t/01-zone-init.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: nginx starts with blocklist_zone
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location / { return 204; }
--- request
GET /
--- error_code: 204

=== TEST 2: missing zone size is a config error
--- http_config
    blocklist_zone zone=bl;
--- must_die
--- error_log
invalid

=== TEST 3: two blocklist_zone directives rejected
--- http_config
    blocklist_zone zone=a:1m;
    blocklist_zone zone=b:1m;
--- must_die
--- error_log
duplicate
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/01-zone-init.t` → all three tests fail (directive unknown).

- [ ] **Step 3: Implement `ngx_http_blocklist_l1_init_zone(shm_zone, data)` in `_l1.c`**

Behavior: if `data != NULL` (reload with same zone), copy `data` into `shm_zone->data` and return `NGX_OK`. Otherwise allocate the `shctx` via `ngx_slab_alloc(shpool, sizeof(ngx_http_blocklist_shctx_t))`, then `shctx->buckets = ngx_slab_calloc(shpool, sizeof(void*) * NGX_HTTP_BLOCKLIST_NBUCKETS)`, set `nbuckets = NGX_HTTP_BLOCKLIST_NBUCKETS`, initialise `ngx_queue_init(&shctx->lru)`, zero all atomic counters, store `shctx` in `shpool->data` and `shm_zone->data`.

- [ ] **Step 4: Implement `blocklist_zone` directive in `_module.c`**

Parse `zone=NAME:SIZE` with the standard nginx pattern (see `ngx_http_limit_req_module.c:zone`). Call `ngx_shared_memory_add(cf, &name, size, &ngx_http_blocklist_module)`. Reject if the main-conf `shm_zone` is already set (duplicate). Reject SIZE smaller than `8 * ngx_pagesize`. Set `shm_zone->init = ngx_http_blocklist_l1_init_zone`.

- [ ] **Step 5: Run tests**

Run: `prove -v t/01-zone-init.t`
Expected: all three PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ngx_http_blocklist_l1.{c,h} src/ngx_http_blocklist_module.c t/01-zone-init.t config
git commit -m "feat: add blocklist_zone directive and shared-memory init"
```

---

## Task 3: End-to-end block path — POST / DELETE / access handler (no auth yet)

This is the first task that produces an observably-working feature: after it, operators can POST an IP and see 403 come back. It is large because every piece below depends on the others to be testable.

**Files:**
- Modify: `src/ngx_http_blocklist_module.c` (loc-conf fields, directives, access handler)
- Modify: `src/ngx_http_blocklist_module.h` (address helpers)
- Modify: `src/ngx_http_blocklist_l1.c`, `.h` (CRUD: `lookup`, `insert`, `delete`)
- Create: `src/ngx_http_blocklist_api.h`
- Create: `src/ngx_http_blocklist_api.c`
- Create: `t/02-basic-block.t`

**Interfaces:**
- Consumes: Task 2 types (`ngx_http_blocklist_shctx_t`, `_node_t`, `_init_zone`).
- Produces:
  - Address helpers (`_module.h`):
    ```c
    // text → 16-byte v4-mapped; returns NGX_OK or NGX_ERROR.
    ngx_int_t ngx_http_blocklist_addr_from_str(ngx_str_t *text,
        u_char addr_out[16], uint8_t *family_out);

    // sockaddr → 16-byte v4-mapped; returns NGX_OK or NGX_ERROR.
    ngx_int_t ngx_http_blocklist_addr_from_sockaddr(struct sockaddr *sa,
        u_char addr_out[16], uint8_t *family_out);

    // 16-byte v4-mapped → text; returns length written.
    size_t ngx_http_blocklist_addr_to_str(const u_char addr[16],
        uint8_t family, u_char *buf, size_t buflen);
    ```
  - L1 CRUD (`_l1.h`):
    ```c
    // NGX_OK: found & not expired, *expire_out set. NGX_DECLINED: miss.
    ngx_int_t ngx_http_blocklist_l1_lookup(ngx_http_blocklist_shctx_t *shctx,
        ngx_slab_pool_t *shpool, const u_char addr[16],
        time_t now, time_t *expire_out);

    // NGX_OK: new node inserted. NGX_DONE: existing refreshed.
    // NGX_ERROR: slab full even after eviction.
    ngx_int_t ngx_http_blocklist_l1_insert(ngx_http_blocklist_shctx_t *shctx,
        ngx_slab_pool_t *shpool, const u_char addr[16],
        uint8_t family, time_t expire);

    // NGX_OK: removed. NGX_DECLINED: not found.
    ngx_int_t ngx_http_blocklist_l1_delete(ngx_http_blocklist_shctx_t *shctx,
        ngx_slab_pool_t *shpool, const u_char addr[16]);
    ```
  - API entrypoint (`_api.h`):
    ```c
    ngx_int_t ngx_http_blocklist_api_handler(ngx_http_request_t *r);
    ```
  - Directives: `blocklist on|off`, `blocklist_status CODE`, `blocklist_api`.
  - Loc-conf fields (`_module.c`, moved to `_module.h`):
    ```c
    typedef struct {
        ngx_flag_t  enabled;
        ngx_uint_t  status;          // default 403
        ngx_flag_t  api_enabled;
        ngx_str_t   api_token;       // populated in Task 4
    } ngx_http_blocklist_loc_conf_t;
    ```

- [ ] **Step 1: Write failing test `t/02-basic-block.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: POST then access → 403; DELETE then access → 200
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
    "DELETE /api/ip?ip=127.0.0.1\r\nHost: localhost\r\n\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403, 200, 200]

=== TEST 2: blocklist off → always 200
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist off; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 200]

=== TEST 3: blocklist_status custom code
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist on; blocklist_status 429; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 429]

=== TEST 4: POST refresh returns 200 not 201
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
]
--- error_code eval
[201, 200]

=== TEST 5: DELETE unknown IP → 404
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request
DELETE /api/ip?ip=10.0.0.1
--- error_code: 404

=== TEST 6: malformed JSON body → 400 INVALID_BODY (Review Focus 1)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{not-json"
--- error_code: 400
--- response_body_like: "INVALID_BODY"

=== TEST 7: POST body over 4 KiB → 413 (Review Focus 2)
--- http_config
    blocklist_zone zone=bl:1m;
    client_max_body_size 1m;
--- config
    location /api/ { blocklist_api; }
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n" . ("x" x 5000)
--- error_code: 413
--- response_body_like: "BODY_TOO_LARGE"

=== TEST 8: DELETE without ?ip= → 400 MISSING_PARAM (Review Focus 4)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request
DELETE /api/ip
--- error_code: 400
--- response_body_like: "MISSING_PARAM"
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/02-basic-block.t`. Expected: all 8 tests fail.

- [ ] **Step 3: Implement address helpers in `_module.c`**

- `addr_from_str`: Try `ngx_inet_addr(text)` first; if parsed as IPv4, write `::ffff:` prefix + 4 bytes into `addr_out`, `*family_out = AF_INET`. Else `ngx_inet6_addr(text)`; if parsed, memcpy 16 bytes, `*family_out = AF_INET6`. Reject input containing `%` (zone id) by returning NGX_ERROR before parsing.
- `addr_from_sockaddr`: dispatch by `sa_family`; for AF_INET, synthesise v4-mapped form; for AF_INET6, memcpy 16 bytes. Detect IPv4-mapped IPv6 and set `family = AF_INET` for display consistency.
- `addr_to_str`: if `family == AF_INET`, write dotted-quad of last 4 bytes with `ngx_snprintf("%ud.%ud.%ud.%ud")`. Else use `ngx_inet6_ntop(addr, buf, buflen)` — nginx's own compressed-lowercase output.

- [ ] **Step 4: Implement L1 CRUD in `_l1.c`**

Hash: `ngx_crc32_long(addr, 16)`. Bucket index: `hash & (nbuckets - 1)`.

- `_l1_lookup`: lock shpool mutex, walk `buckets[idx]`, compare `hash` then `addr`. If found and `expire != 0 && expire <= now`, unlink from chain & LRU, `ngx_slab_free_locked`, increment `expirations`, unlock, return `NGX_DECLINED`. If found and alive, move node to LRU tail, copy `expire` to `*expire_out`, unlock, return `NGX_OK`. Else unlock, return `NGX_DECLINED`. Does **not** increment `hits`/`misses` — that's the access handler's job.
- `_l1_insert`: lock, find; if existing update `expire`, move to LRU tail, increment `inserts`, unlock, return `NGX_DONE`. Else `ngx_slab_alloc_locked`; on NULL pop LRU head → unlink from its bucket → slab_free → increment `evictions` → retry. On repeat NULL: unlock, return `NGX_ERROR`. On success, populate node, prepend to bucket chain, append to LRU, `size++`, `inserts++`, unlock, return `NGX_OK`.
- `_l1_delete`: lock, find; if not found unlock & return `NGX_DECLINED`. Else unlink from chain & LRU, slab_free, `size--`, `deletes++`, unlock, return `NGX_OK`.

- [ ] **Step 5: Implement access handler in `_module.c`**

Register in `postconfiguration` at `NGX_HTTP_ACCESS_PHASE`. Handler:
1. Fetch loc-conf; if `!enabled`, return `NGX_DECLINED`.
2. Fetch main-conf; if `shm_zone == NULL`, log at `warn` once and return `NGX_DECLINED` (fail-open on misconfig).
3. Call `addr_from_sockaddr(r->connection->sockaddr, addr, &family)`; on error return `NGX_DECLINED`.
4. Call `_l1_lookup(shctx, shpool, addr, ngx_time(), &expire)`.
5. On `NGX_OK`: atomic increment `hits`, return `loc_conf->status`.
6. On `NGX_DECLINED`: atomic increment `misses`, return `NGX_DECLINED`.

- [ ] **Step 6: Implement API dispatcher in `_api.c`**

`blocklist_api;` directive sets `clcf->handler = ngx_http_blocklist_api_handler`.

Dispatcher:
1. Compute sub-path = `r->uri` with the enclosing location prefix stripped (use `clcf->name`).
2. Match sub-path against literal `/list` and `/ip`; anything else → 404.
3. Dispatch on method:
   - `/ip` + POST → `api_post_ip(r)` (new, in Task 3)
   - `/ip` + DELETE → `api_delete_ip(r)`
   - `/list` + GET → `api_get_list(r)` (stub returning 501 for now; implemented in Task 5)
   - else → 405 with `Allow` header.

`api_post_ip`:
- Call `ngx_http_read_client_request_body(r, body_cb)`.
- In `body_cb`: if `r->headers_in.content_length_n > 4096` → respond 413 `BODY_TOO_LARGE`. Walk `r->request_body->bufs` concatenating into a 4 KiB stack buffer. Parse JSON (see minimal parser below). Extract `ip` (required string) and `ttl` (optional non-negative integer, default 0). Call `addr_from_str`; on error 400 `INVALID_IP`. Compute `expire = (ttl == 0) ? 0 : ngx_time() + ttl`. Call `_l1_insert`; map return to 201 / 200 / 507. Build JSON response and finalise.

`api_delete_ip`:
- Extract `ip` from `r->args` (walk `r->args.data` looking for `ip=`). If absent → 400 `MISSING_PARAM`. URL-decode the value with `ngx_unescape_uri`. Parse with `addr_from_str`; on error 400 `INVALID_IP`. Call `_l1_delete`; map to 200 / 404 with JSON response.

**Minimal JSON parser** (for Task 3; expanded in Task 6): accept exactly `{"ip":"..."}` or `{"ip":"...","ttl":N}` with optional whitespace. Parser is a state machine over the body buffer; reject anything else with `code: "INVALID_BODY"`. The parser lives in `_api.c` as `static ngx_int_t parse_post_body(const u_char *buf, size_t len, ngx_str_t *ip_out, ngx_int_t *ttl_out)`.

JSON writer: hand-build response bodies with `ngx_snprintf` — bodies are short and fixed-shape.

- [ ] **Step 7: Implement `blocklist on|off`, `blocklist_status`, `blocklist_api` directives**

Standard `ngx_conf_set_flag_slot`, `ngx_conf_set_num_slot` with range check (100–599), and a custom setter for `blocklist_api` that installs the content handler.

Merge loc-conf: `enabled` → `NGX_CONF_UNSET` → 0; `status` → `NGX_CONF_UNSET_UINT` → 403; `api_enabled` → `NGX_CONF_UNSET` → 0; `api_token` → `""`.

- [ ] **Step 8: Run tests**

Run: `prove -v t/02-basic-block.t`
Expected: all 8 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add src/ t/02-basic-block.t config
git commit -m "feat: implement access handler and POST/DELETE API endpoints"
```

---

## Task 4: Bearer-token authentication

**Files:**
- Modify: `src/ngx_http_blocklist_module.c` (add `blocklist_api_token` directive)
- Modify: `src/ngx_http_blocklist_api.c` (auth check before dispatch)
- Create: `t/03-api-auth.t`

**Interfaces:**
- Consumes: loc-conf `api_token` field from Task 3's struct, dispatcher from Task 3.
- Produces: `blocklist_api_token TOKEN;` directive, auth gate at top of `ngx_http_blocklist_api_handler`.

- [ ] **Step 1: Write failing test `t/03-api-auth.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: missing Authorization → 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401
--- response_body_like: ""

=== TEST 2: wrong token → 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer wrong
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401

=== TEST 3: correct token → endpoint reached (404 for unknown IP)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer s3cret
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 404

=== TEST 4: wrong-length token → 401 (Review Focus 5)
# Guards against early-exit on length mismatch.
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer s3cret_longer_than_configured
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401

=== TEST 5: malformed Authorization (no "Bearer ") → 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: s3cret
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401

=== TEST 6: blocklist_api without token → nginx fails to start
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- must_die
--- error_log
blocklist_api_token
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/03-api-auth.t`

- [ ] **Step 3: Add `blocklist_api_token` directive in `_module.c`**

`ngx_conf_set_str_slot` into `loc_conf->api_token`. In the `blocklist_api` setter's post-config phase (or in the merge callback), if `api_enabled == 1 && api_token.len == 0`, return config error "blocklist_api_token is required when blocklist_api is enabled".

- [ ] **Step 4: Add auth gate at top of `ngx_http_blocklist_api_handler`**

```c
static ngx_int_t check_auth(ngx_http_request_t *r, ngx_str_t *token) {
    ngx_table_elt_t *auth = r->headers_in.authorization;
    if (auth == NULL || auth->value.len < sizeof("Bearer ") - 1) return NGX_ERROR;
    if (ngx_strncmp(auth->value.data, "Bearer ", 7) != 0) return NGX_ERROR;
    u_char *provided = auth->value.data + 7;
    size_t len = auth->value.len - 7;
    // constant-time, length-aware.
    if (ngx_memn2cmp(provided, token->data, len, token->len) != 0) return NGX_ERROR;
    return NGX_OK;
}
```

Call from dispatcher before method dispatch. On `NGX_ERROR` return 401 with empty body and `WWW-Authenticate: Bearer` header. Do not log the provided token; log at `info` with only remote_addr, method, uri, status.

- [ ] **Step 5: Run tests**

Run: `prove -v t/03-api-auth.t`
Expected: all 6 PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ t/03-api-auth.t
git commit -m "feat: add bearer-token auth to REST API"
```

---

## Task 5: `GET /list` and `GET /list?q=<ip>` endpoints

**Files:**
- Modify: `src/ngx_http_blocklist_l1.c`, `.h` (add walker)
- Modify: `src/ngx_http_blocklist_api.c` (implement `api_get_list`)
- Create: `t/04-api-get.t`

**Interfaces:**
- Consumes: L1 CRUD from Task 3.
- Produces:
  - L1 walker:
    ```c
    typedef ngx_int_t (*ngx_http_blocklist_walk_pt)(
        const ngx_http_blocklist_node_t *node, void *data);

    // Calls cb for every non-expired node. Expired nodes are pruned.
    // Stops early if cb returns != NGX_OK; return value propagates.
    ngx_int_t ngx_http_blocklist_l1_walk(ngx_http_blocklist_shctx_t *shctx,
        ngx_slab_pool_t *shpool, time_t now,
        ngx_http_blocklist_walk_pt cb, void *data);
    ```
  - Single-node lookup for `?q=`: reuses `_l1_lookup` from Task 3.

- [ ] **Step 1: Write failing test `t/04-api-get.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: GET /list returns all entries as JSON array
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"1.2.3.4\"}\r\n",
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"5.6.7.8\"}\r\n",
    "GET /api/list\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 201, 200]
--- response_body_like eval
['', '', '"ip":"1.2.3.4".*"ip":"5.6.7.8"|"ip":"5.6.7.8".*"ip":"1.2.3.4"']

=== TEST 2: GET /list?q=<existing-ip> → one entry
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"1.2.3.4\"}\r\n",
    "GET /api/list?q=1.2.3.4\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"1.2.3.4"']

=== TEST 3: GET /list?q=<unknown> → 404
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list?q=9.9.9.9
--- error_code: 404

=== TEST 4: GET /list?q=<invalid> → 400 INVALID_IP
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list?q=not-an-ip
--- error_code: 400
--- response_body_like: "INVALID_IP"

=== TEST 5: GET /list on empty table → 200 with empty array
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list
--- error_code: 200
--- response_body_like: '"data":\s*\[\s*\]'

=== TEST 6: URL-encoded IPv6 colons decoded (Review Focus 4)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"ip\":\"2001:db8::1\"}\r\n",
    "GET /api/list?q=2001%3Adb8%3A%3A1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"2001:db8::1"']
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/04-api-get.t`.

- [ ] **Step 3: Implement `_l1_walk` in `_l1.c`**

Lock shpool mutex. Walk LRU queue from head to tail (stable order even under eviction). For each node: if `expire != 0 && expire <= now`, unlink & free & `expirations++`. Else call `cb(node, data)`; if non-OK, remember the return value, stop. Unlock, return the remembered value (or NGX_OK).

- [ ] **Step 4: Implement `api_get_list(r)` in `_api.c`**

Two modes:
- If `r->args` has `q=<ip>`: URL-decode, parse to v4-mapped, call `_l1_lookup`. On OK, build JSON `{"ok":true,"data":{"ip":"...","expire":...}}`. On DECLINED, return 404 with `code: "NOT_FOUND"`.
- Else: allocate response buffer in `r->pool` (grow geometrically: start 4 KiB, double on fill). A walker callback appends `{"ip":"...","expire":...},` to the buffer. After walk, trim trailing comma, wrap with `{"ok":true,"data":[ ... ]}`.

Response must set `Content-Type: application/json`.

- [ ] **Step 5: Run tests**

Run: `prove -v t/04-api-get.t`
Expected: all 6 PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ t/04-api-get.t
git commit -m "feat: add GET /list and GET /list?q= endpoints"
```

---

## Task 6: TTL support on POST + access-time expiry

**Files:**
- Modify: `src/ngx_http_blocklist_api.c` (expand JSON parser to accept `ttl`)
- Create: `t/05-ttl-expiry.t`

**Interfaces:**
- Consumes: Task 3's `_l1_insert(..., expire)` already accepts `expire`; Task 3's `_l1_lookup` already purges expired entries. This task only connects the API-level `ttl` field to `expire`.
- Produces: API accepts `ttl` in POST body (optional, non-negative integer, default 0 = permanent).

- [ ] **Step 1: Write failing test `t/05-ttl-expiry.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: POST with ttl:2 → blocks, after sleep passes
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"ip\":\"127.0.0.1\",\"ttl\":2}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403]

=== TEST 2: after expiry, request passes
# Separate block with a sleep in between.
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- request eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"ip\":\"127.0.0.1\",\"ttl\":1}\r\n",
    "GET /",
]
--- wait: 2
--- error_code eval
[201, 200]

=== TEST 3: no ttl → permanent (short sleep still blocked)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- request eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /",
]
--- wait: 2
--- error_code eval
[201, 403]

=== TEST 4: negative ttl → 400 INVALID_TTL
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"ip\":\"1.2.3.4\",\"ttl\":-1}"
--- error_code: 400
--- response_body_like: "INVALID_TTL"

=== TEST 5: non-integer ttl → 400 INVALID_TTL
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 32\r\n\r\n{\"ip\":\"1.2.3.4\",\"ttl\":\"abc\"}"
--- error_code: 400
--- response_body_like: "INVALID_TTL"
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/05-ttl-expiry.t`.

- [ ] **Step 3: Expand `parse_post_body` in `_api.c`**

Accept the `ttl` field (object members in either order, whitespace allowed between tokens). `ttl` must be a non-negative integer (parse with `ngx_atoi` on a NUL-terminated copy). Non-integer, negative, or non-numeric → return parse error with distinct code `INVALID_TTL`.

- [ ] **Step 4: Compute `expire` in `api_post_ip`**

```c
time_t expire = (ttl == 0) ? 0 : ngx_time() + ttl;
```

Pass to `_l1_insert`. No other changes needed (`_l1_lookup` already handles expire=0 as permanent and prunes expired entries).

- [ ] **Step 5: Run tests**

Run: `prove -v t/05-ttl-expiry.t`
Expected: all 5 PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ngx_http_blocklist_api.c t/05-ttl-expiry.t
git commit -m "feat: support optional TTL on POST /ip"
```

---

## Task 7: IPv6 handling verification

Behavior should already work from Task 3 (addr helpers were written for both families); this task adds the tests that catch IPv6 corner cases.

**Files:**
- Create: `t/06-ipv6.t`
- Modify: `src/ngx_http_blocklist_module.c` (any fixes the tests force)

**Interfaces:**
- Consumes: address helpers and L1 CRUD from Task 3.
- Produces: no new interface. Any changes land in `addr_from_str` / `addr_to_str`.

- [ ] **Step 1: Write failing tests `t/06-ipv6.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: IPv6 POST compressed → stored, GET /list returns same form
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"ip\":\"2001:db8::1\"}\r\n",
    "GET /api/list\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"2001:db8::1"']

=== TEST 2: IPv6 uppercase input normalised (Review Focus 3)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"ip\":\"2001:DB8::1\"}\r\n",
    "GET /api/list?q=2001:db8::1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]

=== TEST 3: IPv4-mapped literal "::ffff:1.2.3.4" treated as 1.2.3.4
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"ip\":\"::ffff:1.2.3.4\"}\r\n",
    "GET /api/list?q=1.2.3.4\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"1.2.3.4"']

=== TEST 4: IPv6 with zone id → 400 INVALID_IP (Review Focus 3)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"ip\":\"fe80::1%eth0\"}"
--- error_code: 400
--- response_body_like: "INVALID_IP"

=== TEST 5: block an IPv6 client via listen [::]:…
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    listen [::1]:$TEST_NGINX_SERVER_PORT;
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"::1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403]
```

- [ ] **Step 2: Run and verify FAIL/PASS**

Run: `prove -v t/06-ipv6.t`. Iterate on `addr_from_str` / `addr_to_str` until all PASS. Likely fix: on IPv6 parse, if the 16-byte result starts with `::ffff:`, set `family = AF_INET` so output is dotted-quad.

- [ ] **Step 3: Commit**

```bash
git add src/ t/06-ipv6.t
git commit -m "feat: harden IPv6 address normalization"
```

---

## Task 8: LRU eviction + `507 ZONE_FULL`

**Files:**
- Create: `t/07-lru-eviction.t`
- Modify: `src/ngx_http_blocklist_api.c` (ensure `_l1_insert → NGX_ERROR` maps to 507)
- Modify: `src/ngx_http_blocklist_l1.c` (rate-limited notice log on repeat failure)

**Interfaces:**
- Consumes: Task 3's L1 CRUD (`_l1_insert` already evicts LRU head on alloc failure and retries once).
- Produces: no new interface; behavior verification only.

- [ ] **Step 1: Write failing test `t/07-lru-eviction.t`**

Insert 500 IPs (`10.0.X.Y`) into a zone too small to hold them all; verify
the earliest IP has been evicted while the latest is still resident.

```perl
use Test::Nginx::Socket 'no_plan';
repeat_each(1);
run_tests();

__DATA__

=== TEST 1: oversubscribe tiny zone → earliest insert evicted
--- http_config
    blocklist_zone zone=bl:16k;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    (map {
        my $o3 = int($_ / 254);
        my $o4 = ($_ % 254) + 1;
        my $body = "{\"ip\":\"10.0.$o3.$o4\"}";
        "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: " . length($body) . "\r\n\r\n$body"
    } 0..499),
    "GET /api/list?q=10.0.0.1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
    "GET /api/list?q=10.0.1.243\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[(201) x 500, 404, 200]
```

- [ ] **Step 2: Run and verify FAIL**

Run: `prove -v t/07-lru-eviction.t`. If it hangs or crashes, that's the fix target.

- [ ] **Step 3: Implement rate-limited `notice` log in `_l1.c`**

In `_l1_insert`'s repeat-NULL branch, keep a worker-local `static time_t last_warn = 0;` and log at `notice` only if `ngx_time() - last_warn > 60`.

- [ ] **Step 4: Confirm `507 ZONE_FULL` in `_api.c`**

Map `_l1_insert == NGX_ERROR` → `507` with `code: "ZONE_FULL"`. Add a dedicated test that fills the zone with large counts if the above test already exercises it, otherwise add Test 2 constructing an impossible-to-evict scenario (unlikely in practice because single LRU head is always evictable).

- [ ] **Step 5: Run tests**

Run: `prove -v t/07-lru-eviction.t`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ t/07-lru-eviction.t
git commit -m "feat: harden LRU eviction and ZONE_FULL response"
```

---

## Task 9: realip integration test

No code change; this task proves the handler sees the realip-rewritten `r->connection->sockaddr`.

**Files:**
- Create: `t/08-realip.t`

**Interfaces:**
- Consumes: access handler from Task 3; nginx's bundled `ngx_http_realip_module`.
- Produces: nothing new.

- [ ] **Step 1: Write failing/passing test `t/08-realip.t`**

```perl
use Test::Nginx::Socket 'no_plan';

# nginx must be compiled with --with-http_realip_module (standard in most builds).

run_tests();

__DATA__

=== TEST 1: XFF ip is what gets blocked
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    set_real_ip_from 127.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"9.9.9.9\"}\r\n",
    "GET /\r\nHost: localhost\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
    "GET /\r\nHost: localhost\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
]
--- error_code eval
[201, 403, 200]
```

- [ ] **Step 2: Run tests**

Run: `prove -v t/08-realip.t`
Expected: PASS without code changes.

- [ ] **Step 3: Commit**

```bash
git add t/08-realip.t
git commit -m "test: verify realip-rewritten addr is used by access handler"
```

---

## Task 10: Concurrent workers stress test

**Files:**
- Create: `t/09-concurrent-workers.t`

**Interfaces:**
- Consumes: full module.
- Produces: no new code.

- [ ] **Step 1: Write test `t/09-concurrent-workers.t`**

```perl
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: multi-worker, concurrent POST + GET, no crash
--- main_config
    worker_processes 4;
--- http_config
    blocklist_zone zone=bl:4m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
# Interleave 200 POSTs and 200 GETs across 4 workers.
[
    (map {
        my $o4 = ($_ % 254) + 1;
        my $body = "{\"ip\":\"10.1.1.$o4\"}";
        ($_ % 2 == 0
            ? "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: " . length($body) . "\r\n\r\n$body"
            : "GET /\r\nHost: localhost\r\n\r\n");
    } 0..399),
]
# No crash-equivalent assertion (nginx would close the connection on segfault);
# every request must get a response code.
--- error_code eval
# Each slot either 201 (POST) or 200/403 (GET). We assert the count of codes is 400.
# Looser form: all codes are in the allowed set.
[map { ($_ % 2 == 0) ? 201 : 200 } 0..399]
# (GET responses may be 200 or 403 depending on race; relax the oracle accordingly.)
--- timeout: 30
```

Refine the oracle during implementation: the test's goal is "no crash, no hang, every request answered"; adjust `--- error_code eval` to tolerate both 200 and 403 for GETs with a post-condition that the response count equals the request count.

- [ ] **Step 2: Run test**

Run: `prove -v t/09-concurrent-workers.t` with `TEST_NGINX_RANDOMIZE=1` if available.
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add t/09-concurrent-workers.t
git commit -m "test: concurrent worker stress test for blocklist module"
```

---

## Out-of-scope reminders (post-MVP)

Documented in spec §13; do **not** build in this plan:
- CIDR / prefix support.
- Persistence snapshot.
- Pagination on `GET /list`.
- Audit log of mutations.
- Multi-zone.
- Prometheus metrics endpoint.
- Cross-host sync (writer concern).
