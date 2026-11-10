#ifndef NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_
#define NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HTTP_BLOCKLIST_NBUCKETS_MIN  64
#define NGX_HTTP_BLOCKLIST_NBUCKETS_MAX  16384


typedef struct ngx_http_blocklist_node_s  ngx_http_blocklist_node_t;

struct ngx_http_blocklist_node_s {
    ngx_http_blocklist_node_t  *hash_next;   /* bucket chain (singly linked) */
    ngx_queue_t                 lru_queue;   /* in global LRU */
    uint32_t                    hash;        /* crc32(addr), cached */
    u_char                      addr[16];    /* in6_addr, v4-mapped for IPv4 */
    uint8_t                     family;      /* AF_INET or AF_INET6 */
    time_t                      expire;      /* 0 = permanent */
};


typedef struct {
    ngx_http_blocklist_node_t **buckets;    /* nbuckets head pointers */
    ngx_uint_t                  nbuckets;   /* power of 2 */
    ngx_queue_t                 lru;        /* head=oldest, tail=newest */
    ngx_atomic_t                size;
    ngx_atomic_t                hits;
    ngx_atomic_t                misses;
    ngx_atomic_t                inserts;
    ngx_atomic_t                deletes;
    ngx_atomic_t                evictions;
    ngx_atomic_t                expirations;
} ngx_http_blocklist_shctx_t;


/* Shared memory initialiser passed to ngx_shared_memory_add. */
ngx_int_t  ngx_http_blocklist_l1_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);


/*
 * CRUD operations. All take the shared ctx + shpool explicitly so they are
 * testable in isolation. Each acquires the slab mutex around its critical
 * section.
 */

/*
 * NGX_OK      : found & not expired; *expire_out set.
 * NGX_DECLINED: miss or expired-and-pruned.
 * Hits/misses counters are not touched here; the caller decides whether
 * this was an access-phase lookup or an API read.
 */
ngx_int_t  ngx_http_blocklist_l1_lookup(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16],
    time_t now, time_t *expire_out);

/*
 * NGX_OK   : new node inserted, LRU tail.
 * NGX_DONE : existing entry refreshed (expire + family updated, moved to tail).
 * NGX_ERROR: slab full even after evicting the LRU head.
 */
ngx_int_t  ngx_http_blocklist_l1_insert(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16],
    uint8_t family, time_t expire);

/*
 * NGX_OK      : removed.
 * NGX_DECLINED: not found.
 */
ngx_int_t  ngx_http_blocklist_l1_delete(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16]);


/*
 * Walk every non-expired entry. Expired entries are pruned in-line. The
 * callback is invoked once per surviving node; if it returns non-OK the walk
 * stops and that value propagates out. The whole walk holds the slab mutex,
 * so the callback must not block or do I/O.
 */
typedef ngx_int_t (*ngx_http_blocklist_walk_pt)(
    const ngx_http_blocklist_node_t *node, void *data);

ngx_int_t  ngx_http_blocklist_l1_walk(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, time_t now,
    ngx_http_blocklist_walk_pt cb, void *data);


#endif /* NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_ */
