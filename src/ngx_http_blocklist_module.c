#include "ngx_http_blocklist_module.h"
#include "ngx_http_blocklist_l1.h"
#include "ngx_http_blocklist_api.h"


static void *ngx_http_blocklist_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_blocklist_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_blocklist_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_blocklist_init(ngx_conf_t *cf);

static char *ngx_http_blocklist_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_blocklist_status_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_blocklist_api_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_blocklist_access_handler(ngx_http_request_t *r);


static ngx_command_t  ngx_http_blocklist_commands[] = {

    { ngx_string("blocklist_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_blocklist_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("blocklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_blocklist_loc_conf_t, enabled),
      NULL },

    { ngx_string("blocklist_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_blocklist_status_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("blocklist_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_blocklist_api_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("blocklist_api_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_blocklist_loc_conf_t, api_token),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_blocklist_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_blocklist_init,                    /* postconfiguration */

    ngx_http_blocklist_create_main_conf,        /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_blocklist_create_loc_conf,         /* create location configuration */
    ngx_http_blocklist_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_blocklist_module = {
    NGX_MODULE_V1,
    &ngx_http_blocklist_module_ctx,              /* module context */
    ngx_http_blocklist_commands,                 /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_blocklist_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_blocklist_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_blocklist_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    return mcf;
}


static void *
ngx_http_blocklist_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_blocklist_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_blocklist_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enabled     = NGX_CONF_UNSET;
    lcf->status      = NGX_CONF_UNSET_UINT;
    lcf->api_enabled = NGX_CONF_UNSET;
    /* api_token is zero-initialised by ngx_pcalloc. */

    return lcf;
}


static char *
ngx_http_blocklist_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_blocklist_loc_conf_t  *prev = parent;
    ngx_http_blocklist_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_uint_value(conf->status, prev->status, NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_value(conf->api_enabled, prev->api_enabled, 0);
    ngx_conf_merge_str_value(conf->api_token, prev->api_token, "");

    if (conf->api_enabled == 1 && conf->api_token.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"blocklist_api_token\" must be set when "
            "\"blocklist_api\" is enabled");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_blocklist_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_blocklist_access_handler;

    return NGX_OK;
}


static char *
ngx_http_blocklist_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_blocklist_main_conf_t  *mcf = conf;

    ngx_str_t        *value;
    ngx_str_t         name, s;
    ngx_shm_zone_t   *shm_zone;
    ssize_t           size;
    u_char           *p;
    ngx_uint_t        i;

    value     = cf->args->elts;
    name.len  = 0;
    name.data = NULL;
    size      = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;
            if (name.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone name in \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            s.data = p + 1;
            s.len  = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "blocklist_zone \"%V\" is too small",
                                   &name);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" requires \"zone=NAME:SIZE\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (mcf->shm_zone != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate blocklist_zone directive");
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_blocklist_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "blocklist_zone \"%V\" is already in use", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_blocklist_l1_init_zone;
    shm_zone->data = NULL;

    mcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static char *
ngx_http_blocklist_status_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_blocklist_loc_conf_t  *lcf = conf;
    ngx_str_t                      *value;
    ngx_int_t                       n;

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || n < 100 || n > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid status code \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->status = (ngx_uint_t) n;
    return NGX_CONF_OK;
}


static char *
ngx_http_blocklist_api_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_blocklist_loc_conf_t  *lcf = conf;
    ngx_http_core_loc_conf_t       *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_blocklist_api_handler;

    lcf->api_enabled = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_blocklist_access_handler(ngx_http_request_t *r)
{
    ngx_http_blocklist_loc_conf_t   *lcf;
    ngx_http_blocklist_main_conf_t  *mcf;
    ngx_http_blocklist_shctx_t      *shctx;
    ngx_slab_pool_t                 *shpool;
    u_char                           addr[16];
    uint8_t                          family;
    time_t                           expire;
    ngx_int_t                        rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_blocklist_module);
    if (lcf == NULL || lcf->enabled != 1) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_blocklist_module);
    if (mcf == NULL
        || mcf->shm_zone == NULL
        || mcf->shm_zone->shm.addr == NULL
        || mcf->shm_zone->data == NULL)
    {
        /*
         * Rate-limited warn: a misconfigured deployment or the narrow
         * window during reload before the zone is wired would otherwise
         * flood error.log at request rate.
         */
        static time_t  last_zone_warn = 0;
        time_t         now = ngx_time();
        if (now - last_zone_warn > 60) {
            last_zone_warn = now;
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "blocklist: zone not available; passing request");
        }
        return NGX_DECLINED;
    }

    shpool = (ngx_slab_pool_t *) mcf->shm_zone->shm.addr;
    shctx  = mcf->shm_zone->data;

    if (ngx_http_blocklist_addr_from_sockaddr(
            r->connection->sockaddr, addr, &family) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    rc = ngx_http_blocklist_l1_lookup(shctx, shpool, addr,
                                       ngx_time(), &expire);
    if (rc == NGX_OK) {
        /* Counters touched outside the slab mutex must be atomic. */
        (void) ngx_atomic_fetch_add(&shctx->hits, 1);
        return lcf->status;
    }

    (void) ngx_atomic_fetch_add(&shctx->misses, 1);
    return NGX_DECLINED;
}


/* ========================================================================
 * Address helpers
 * ======================================================================== */

ngx_int_t
ngx_http_blocklist_addr_from_str(ngx_str_t *text, u_char addr_out[16],
    uint8_t *family_out)
{
    in_addr_t  in4;

    if (text->len == 0 || text->data == NULL) {
        return NGX_ERROR;
    }

    /* Reject zone id (fe80::1%eth0 and the like) before parsing. */
    if (ngx_strlchr(text->data, text->data + text->len, '%') != NULL) {
        return NGX_ERROR;
    }

    in4 = ngx_inet_addr(text->data, text->len);
    if (in4 != INADDR_NONE) {
        ngx_memzero(addr_out, 10);
        addr_out[10] = 0xff;
        addr_out[11] = 0xff;
        ngx_memcpy(addr_out + 12, &in4, 4);
        *family_out = AF_INET;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (ngx_inet6_addr(text->data, text->len, addr_out) == NGX_OK) {
        if (addr_out[0] == 0 && addr_out[1] == 0 && addr_out[2] == 0
            && addr_out[3] == 0 && addr_out[4] == 0 && addr_out[5] == 0
            && addr_out[6] == 0 && addr_out[7] == 0 && addr_out[8] == 0
            && addr_out[9] == 0
            && addr_out[10] == 0xff && addr_out[11] == 0xff)
        {
            *family_out = AF_INET;
        } else {
            *family_out = AF_INET6;
        }
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


ngx_int_t
ngx_http_blocklist_addr_from_sockaddr(struct sockaddr *sa,
    u_char addr_out[16], uint8_t *family_out)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (sa == NULL) {
        return NGX_ERROR;
    }

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        ngx_memzero(addr_out, 10);
        addr_out[10] = 0xff;
        addr_out[11] = 0xff;
        ngx_memcpy(addr_out + 12, &sin->sin_addr.s_addr, 4);
        *family_out = AF_INET;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        ngx_memcpy(addr_out, sin6->sin6_addr.s6_addr, 16);
        if (addr_out[0] == 0 && addr_out[1] == 0 && addr_out[2] == 0
            && addr_out[3] == 0 && addr_out[4] == 0 && addr_out[5] == 0
            && addr_out[6] == 0 && addr_out[7] == 0 && addr_out[8] == 0
            && addr_out[9] == 0
            && addr_out[10] == 0xff && addr_out[11] == 0xff)
        {
            *family_out = AF_INET;
        } else {
            *family_out = AF_INET6;
        }
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


size_t
ngx_http_blocklist_addr_to_str(const u_char addr[16], uint8_t family,
    u_char *buf, size_t buflen)
{
    u_char  *p;

    if (family == AF_INET) {
        p = ngx_snprintf(buf, buflen, "%ud.%ud.%ud.%ud",
                         (ngx_uint_t) addr[12], (ngx_uint_t) addr[13],
                         (ngx_uint_t) addr[14], (ngx_uint_t) addr[15]);
        return (size_t) (p - buf);
    }

#if (NGX_HAVE_INET6)
    return ngx_inet6_ntop((u_char *) addr, buf, buflen);
#else
    (void) buf;
    (void) buflen;
    return 0;
#endif
}
