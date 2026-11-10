#include "ngx_http_blocklist_l1.h"


ngx_int_t
ngx_http_blocklist_l1_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_http_blocklist_shctx_t  *shctx;
    size_t                       bucket_bytes;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (data) {
        /* Reload with same zone: reuse the control block from the old cycle. */
        shm_zone->data = data;
        return NGX_OK;
    }

    shctx = ngx_slab_alloc(shpool, sizeof(ngx_http_blocklist_shctx_t));
    if (shctx == NULL) {
        return NGX_ERROR;
    }

    bucket_bytes = sizeof(ngx_http_blocklist_node_t *)
                 * NGX_HTTP_BLOCKLIST_NBUCKETS;

    shctx->buckets = ngx_slab_calloc(shpool, bucket_bytes);
    if (shctx->buckets == NULL) {
        return NGX_ERROR;
    }

    shctx->nbuckets = NGX_HTTP_BLOCKLIST_NBUCKETS;
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
