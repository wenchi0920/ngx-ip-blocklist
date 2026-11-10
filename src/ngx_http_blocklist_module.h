#ifndef NGX_HTTP_BLOCKLIST_MODULE_H_INCLUDED_
#define NGX_HTTP_BLOCKLIST_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_shm_zone_t   *shm_zone;
} ngx_http_blocklist_main_conf_t;


typedef struct {
    ngx_flag_t   enabled;
    ngx_uint_t   status;
    ngx_flag_t   api_enabled;
    ngx_str_t    api_token;
} ngx_http_blocklist_loc_conf_t;


extern ngx_module_t  ngx_http_blocklist_module;


/*
 * Address helpers. All addresses are stored as 16-byte IPv4-mapped form so
 * comparators are a single ngx_memcmp over 16 bytes regardless of family.
 */

/* Text (dotted-quad or compressed IPv6) -> 16-byte v4-mapped. */
ngx_int_t  ngx_http_blocklist_addr_from_str(ngx_str_t *text,
    u_char addr_out[16], uint8_t *family_out);

/* sockaddr -> 16-byte v4-mapped. */
ngx_int_t  ngx_http_blocklist_addr_from_sockaddr(struct sockaddr *sa,
    u_char addr_out[16], uint8_t *family_out);

/* 16-byte v4-mapped -> human-readable text. Returns bytes written. */
size_t     ngx_http_blocklist_addr_to_str(const u_char addr[16],
    uint8_t family, u_char *buf, size_t buflen);


#endif /* NGX_HTTP_BLOCKLIST_MODULE_H_INCLUDED_ */
