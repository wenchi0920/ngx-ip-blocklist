#include "ngx_http_blocklist_l1.h"


static uint32_t  l1_hash(const u_char addr[16]);
static ngx_http_blocklist_node_t *l1_find_locked(
    ngx_http_blocklist_shctx_t *shctx, uint32_t hash, const u_char addr[16],
    ngx_http_blocklist_node_t ***pprev_out);
static void  l1_unlink_bucket_locked(ngx_http_blocklist_shctx_t *shctx,
    ngx_http_blocklist_node_t *node);


ngx_int_t
ngx_http_blocklist_l1_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_http_blocklist_shctx_t  *shctx;
    size_t                       bucket_bytes;
    ngx_uint_t                   nbuckets;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shctx = ngx_slab_alloc(shpool, sizeof(ngx_http_blocklist_shctx_t));
    if (shctx == NULL) {
        return NGX_ERROR;
    }

    /*
     * Scale buckets with the zone size: roughly one bucket per 256 bytes
     * of zone. Clamped to [MIN, MAX] and rounded up to the next power of 2
     * so the lookup can mask with `hash & (nbuckets - 1)`.
     */
    nbuckets = NGX_HTTP_BLOCKLIST_NBUCKETS_MIN;
    while (nbuckets * 256 < shm_zone->shm.size
           && nbuckets < NGX_HTTP_BLOCKLIST_NBUCKETS_MAX)
    {
        nbuckets <<= 1;
    }

    bucket_bytes = sizeof(ngx_http_blocklist_node_t *) * nbuckets;

    shctx->buckets = ngx_slab_calloc(shpool, bucket_bytes);
    if (shctx->buckets == NULL) {
        return NGX_ERROR;
    }

    shctx->nbuckets = nbuckets;
    ngx_queue_init(&shctx->lru);

    shctx->size        = 0;
    shctx->hits        = 0;
    shctx->misses      = 0;
    shctx->inserts     = 0;
    shctx->deletes     = 0;
    shctx->evictions   = 0;
    shctx->expirations = 0;

    shpool->data   = shctx;
    shm_zone->data = shctx;

    return NGX_OK;
}


ngx_int_t
ngx_http_blocklist_l1_lookup(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16],
    time_t now, time_t *expire_out)
{
    uint32_t                     hash;
    ngx_http_blocklist_node_t   *node;
    ngx_http_blocklist_node_t  **pprev;

    hash = l1_hash(addr);

    ngx_shmtx_lock(&shpool->mutex);

    node = l1_find_locked(shctx, hash, addr, &pprev);
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    if (node->expire != 0 && node->expire <= now) {
        *pprev = node->hash_next;
        ngx_queue_remove(&node->lru_queue);
        ngx_slab_free_locked(shpool, node);
        shctx->size--;
        shctx->expirations++;
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    /* Alive: move to LRU tail. */
    ngx_queue_remove(&node->lru_queue);
    ngx_queue_insert_tail(&shctx->lru, &node->lru_queue);

    if (expire_out) {
        *expire_out = node->expire;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_http_blocklist_l1_insert(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16],
    uint8_t family, time_t expire)
{
    uint32_t                     hash;
    ngx_http_blocklist_node_t   *node, *victim;
    ngx_http_blocklist_node_t  **pprev;
    ngx_queue_t                 *q;
    int                          retries;

    hash = l1_hash(addr);

    ngx_shmtx_lock(&shpool->mutex);

    node = l1_find_locked(shctx, hash, addr, &pprev);
    if (node != NULL) {
        node->expire = expire;
        node->family = family;
        ngx_queue_remove(&node->lru_queue);
        ngx_queue_insert_tail(&shctx->lru, &node->lru_queue);
        shctx->inserts++;
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DONE;
    }

    /*
     * Try alloc; on failure, evict the LRU head *once* and retry. If the
     * second alloc still fails give up without evicting again, since
     * another worker would have observed the same shortage.
     */
    retries = 0;
    for ( ;; ) {
        node = ngx_slab_alloc_locked(shpool,
            sizeof(ngx_http_blocklist_node_t));
        if (node != NULL) {
            break;
        }

        if (retries++ || ngx_queue_empty(&shctx->lru)) {
            break;
        }

        q = ngx_queue_head(&shctx->lru);
        victim = ngx_queue_data(q, ngx_http_blocklist_node_t, lru_queue);

        l1_unlink_bucket_locked(shctx, victim);
        ngx_queue_remove(&victim->lru_queue);
        ngx_slab_free_locked(shpool, victim);
        shctx->size--;
        shctx->evictions++;
    }

    if (node == NULL) {
        static time_t  last_warn = 0;
        time_t         now = ngx_time();

        ngx_shmtx_unlock(&shpool->mutex);

        /* Rate-limit to once per minute per worker. */
        if (now - last_warn > 60) {
            last_warn = now;
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "blocklist zone full; eviction could not "
                          "free a slot — raise blocklist_zone size");
        }
        return NGX_ERROR;
    }

    node->hash   = hash;
    node->family = family;
    node->expire = expire;
    ngx_memcpy(node->addr, addr, 16);

    /* Prepend to bucket chain. */
    node->hash_next = shctx->buckets[hash & (shctx->nbuckets - 1)];
    shctx->buckets[hash & (shctx->nbuckets - 1)] = node;

    /* Append to LRU tail. */
    ngx_queue_insert_tail(&shctx->lru, &node->lru_queue);

    shctx->size++;
    shctx->inserts++;

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_http_blocklist_l1_delete(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, const u_char addr[16])
{
    uint32_t                     hash;
    ngx_http_blocklist_node_t   *node;
    ngx_http_blocklist_node_t  **pprev;

    hash = l1_hash(addr);

    ngx_shmtx_lock(&shpool->mutex);

    node = l1_find_locked(shctx, hash, addr, &pprev);
    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    *pprev = node->hash_next;
    ngx_queue_remove(&node->lru_queue);
    ngx_slab_free_locked(shpool, node);
    shctx->size--;
    shctx->deletes++;

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


static uint32_t
l1_hash(const u_char addr[16])
{
    return ngx_crc32_long((u_char *) addr, 16);
}


static ngx_http_blocklist_node_t *
l1_find_locked(ngx_http_blocklist_shctx_t *shctx, uint32_t hash,
    const u_char addr[16], ngx_http_blocklist_node_t ***pprev_out)
{
    ngx_http_blocklist_node_t   *n;
    ngx_http_blocklist_node_t  **pprev;

    pprev = &shctx->buckets[hash & (shctx->nbuckets - 1)];
    for (n = *pprev; n != NULL; pprev = &n->hash_next, n = *pprev) {
        if (n->hash == hash && ngx_memcmp(n->addr, addr, 16) == 0) {
            if (pprev_out) {
                *pprev_out = pprev;
            }
            return n;
        }
    }
    return NULL;
}


static void
l1_unlink_bucket_locked(ngx_http_blocklist_shctx_t *shctx,
    ngx_http_blocklist_node_t *node)
{
    ngx_http_blocklist_node_t  **p;

    p = &shctx->buckets[node->hash & (shctx->nbuckets - 1)];
    while (*p != NULL && *p != node) {
        p = &(*p)->hash_next;
    }
    if (*p == node) {
        *p = node->hash_next;
    }
}


ngx_int_t
ngx_http_blocklist_l1_walk(ngx_http_blocklist_shctx_t *shctx,
    ngx_slab_pool_t *shpool, time_t now,
    ngx_http_blocklist_walk_pt cb, void *data)
{
    ngx_queue_t                *q, *next;
    ngx_http_blocklist_node_t  *node;
    ngx_int_t                   rc = NGX_OK;

    ngx_shmtx_lock(&shpool->mutex);

    for (q = ngx_queue_head(&shctx->lru);
         q != ngx_queue_sentinel(&shctx->lru);
         q = next)
    {
        next = ngx_queue_next(q);
        node = ngx_queue_data(q, ngx_http_blocklist_node_t, lru_queue);

        if (node->expire != 0 && node->expire <= now) {
            l1_unlink_bucket_locked(shctx, node);
            ngx_queue_remove(&node->lru_queue);
            ngx_slab_free_locked(shpool, node);
            shctx->size--;
            shctx->expirations++;
            continue;
        }

        rc = cb(node, data);
        if (rc != NGX_OK) {
            break;
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return rc;
}
