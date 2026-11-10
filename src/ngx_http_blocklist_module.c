#include "ngx_http_blocklist_module.h"


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


static ngx_command_t  ngx_http_blocklist_commands[] = {

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
