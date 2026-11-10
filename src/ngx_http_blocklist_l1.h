#ifndef NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_
#define NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HTTP_BLOCKLIST_NBUCKETS  16384


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


ngx_int_t  ngx_http_blocklist_l1_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);


#endif /* NGX_HTTP_BLOCKLIST_L1_H_INCLUDED_ */
