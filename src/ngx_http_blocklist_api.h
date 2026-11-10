#ifndef NGX_HTTP_BLOCKLIST_API_H_INCLUDED_
#define NGX_HTTP_BLOCKLIST_API_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * REST API content handler. Dispatches on method + sub-path to POST/DELETE/GET
 * handlers. Caller (the blocklist_api directive setter) installs this as the
 * location's clcf->handler.
 */
ngx_int_t  ngx_http_blocklist_api_handler(ngx_http_request_t *r);


#endif /* NGX_HTTP_BLOCKLIST_API_H_INCLUDED_ */
