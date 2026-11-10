#include "ngx_http_blocklist_module.h"
#include "ngx_http_blocklist_l1.h"


typedef struct {
    ngx_shm_zone_t   *shm_zone;
} ngx_http_blocklist_main_conf_t;


/*
 * Loc-conf carries the fields Task 3 will wire to directives. They are declared
 * here so later tasks only add directive table entries and handler code, not a
 * struct redesign. An empty struct would be undefined behaviour in standard C.
 */
typedef struct {
    ngx_flag_t   enabled;
    ngx_uint_t   status;
    ngx_flag_t   api_enabled;
    ngx_str_t    api_token;
} ngx_http_blocklist_loc_conf_t;


static void *ngx_http_blocklist_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_blocklist_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_blocklist_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_blocklist_commands[] = {

    { ngx_string("blocklist_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_blocklist_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_blocklist_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    ngx_http_blocklist_create_main_conf,        /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_blocklist_create_loc_conf,         /* create location configuration */
    NULL                                        /* merge location configuration */
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
ngx_http_blocklist_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_blocklist_main_conf_t  *mcf = conf;

    ngx_str_t        *value;
    ngx_str_t         name, s;
    ngx_shm_zone_t   *shm_zone;
    ssize_t           size;
    u_char           *p;
    ngx_uint_t        i;

    value   = cf->args->elts;
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
