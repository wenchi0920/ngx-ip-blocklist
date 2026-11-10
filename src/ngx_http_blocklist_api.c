#include "ngx_http_blocklist_api.h"
#include "ngx_http_blocklist_module.h"
#include "ngx_http_blocklist_l1.h"


#define BLOCKLIST_API_MAX_BODY  4096


static ngx_int_t  api_post_ip(ngx_http_request_t *r);
static void       api_post_ip_body_handler(ngx_http_request_t *r);
static ngx_int_t  api_delete_ip(ngx_http_request_t *r);
static ngx_int_t  api_get_list(ngx_http_request_t *r);

static ngx_int_t  send_json_response(ngx_http_request_t *r,
    ngx_uint_t status, u_char *body, size_t body_len);
static ngx_int_t  send_error_json(ngx_http_request_t *r,
    ngx_uint_t status, const char *code);
static ngx_int_t  send_ip_success_json(ngx_http_request_t *r,
    ngx_uint_t status, const u_char addr[16], uint8_t family,
    time_t expire, ngx_flag_t with_expire);

static ngx_int_t  parse_post_body(const u_char *buf, size_t len,
    ngx_str_t *ip_out, ngx_int_t *ttl_out);
static ngx_int_t  query_param_lookup(ngx_str_t *args, const char *key,
    size_t keylen, u_char *out, size_t outcap, size_t *outlen);

static ngx_http_blocklist_shctx_t *get_shctx(ngx_http_request_t *r,
    ngx_slab_pool_t **shpool_out);

static void       add_allow_header(ngx_http_request_t *r, ngx_str_t *value);


ngx_int_t
ngx_http_blocklist_api_handler(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_str_t                  sub;
    ngx_str_t                  allow;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->uri.len < clcf->name.len
        || ngx_strncmp(r->uri.data, clcf->name.data, clcf->name.len) != 0)
    {
        ngx_http_discard_request_body(r);
        return send_error_json(r, NGX_HTTP_NOT_FOUND, "NOT_FOUND");
    }

    sub.data = r->uri.data + clcf->name.len;
    sub.len  = r->uri.len - clcf->name.len;

    if (sub.len == 2 && ngx_strncmp(sub.data, "ip", 2) == 0) {

        if (r->method == NGX_HTTP_POST) {
            return api_post_ip(r);
        }

        if (r->method == NGX_HTTP_DELETE) {
            return api_delete_ip(r);
        }

        ngx_str_set(&allow, "POST, DELETE");
        add_allow_header(r, &allow);
        ngx_http_discard_request_body(r);
        return send_error_json(r, NGX_HTTP_NOT_ALLOWED, "METHOD_NOT_ALLOWED");
    }

    if (sub.len == 4 && ngx_strncmp(sub.data, "list", 4) == 0) {

        if (r->method == NGX_HTTP_GET) {
            return api_get_list(r);
        }

        ngx_str_set(&allow, "GET");
        add_allow_header(r, &allow);
        ngx_http_discard_request_body(r);
        return send_error_json(r, NGX_HTTP_NOT_ALLOWED, "METHOD_NOT_ALLOWED");
    }

    ngx_http_discard_request_body(r);
    return send_error_json(r, NGX_HTTP_NOT_FOUND, "NOT_FOUND");
}


static ngx_int_t
api_post_ip(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->headers_in.content_length_n < 0
        || r->headers_in.content_length_n > BLOCKLIST_API_MAX_BODY)
    {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            return rc;
        }
        return send_error_json(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                               "BODY_TOO_LARGE");
    }

    r->request_body_in_single_buf = 1;

    rc = ngx_http_read_client_request_body(r, api_post_ip_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
api_post_ip_body_handler(ngx_http_request_t *r)
{
    u_char                       buf[BLOCKLIST_API_MAX_BODY];
    size_t                       body_len = 0;
    ngx_chain_t                 *cl;
    ngx_buf_t                   *b;
    size_t                       len;
    ngx_str_t                    ip_text;
    ngx_int_t                    ttl = 0;
    u_char                       addr[16];
    uint8_t                      family;
    time_t                       expire;
    ngx_int_t                    rc;
    ngx_http_blocklist_shctx_t  *shctx;
    ngx_slab_pool_t             *shpool;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        rc = send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_BODY");
        ngx_http_finalize_request(r, rc);
        return;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        b = cl->buf;
        if (!ngx_buf_in_memory(b)) {
            /* Spilled to temp file: exceeds our in-memory cap. */
            rc = send_error_json(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                                 "BODY_TOO_LARGE");
            ngx_http_finalize_request(r, rc);
            return;
        }
        len = b->last - b->pos;
        if (body_len + len > sizeof(buf)) {
            rc = send_error_json(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                                 "BODY_TOO_LARGE");
            ngx_http_finalize_request(r, rc);
            return;
        }
        ngx_memcpy(buf + body_len, b->pos, len);
        body_len += len;
    }

    if (parse_post_body(buf, body_len, &ip_text, &ttl) != NGX_OK) {
        rc = send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_BODY");
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (ngx_http_blocklist_addr_from_str(&ip_text, addr, &family) != NGX_OK) {
        rc = send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_IP");
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (ttl < 0) {
        rc = send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_TTL");
        ngx_http_finalize_request(r, rc);
        return;
    }

    expire = (ttl == 0) ? 0 : ngx_time() + ttl;

    shctx = get_shctx(r, &shpool);
    if (shctx == NULL) {
        rc = send_error_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                             "ZONE_NOT_READY");
        ngx_http_finalize_request(r, rc);
        return;
    }

    rc = ngx_http_blocklist_l1_insert(shctx, shpool, addr, family, expire);
    switch (rc) {
    case NGX_OK:
        rc = send_ip_success_json(r, NGX_HTTP_CREATED, addr, family,
                                  expire, 1);
        break;
    case NGX_DONE:
        rc = send_ip_success_json(r, NGX_HTTP_OK, addr, family, expire, 1);
        break;
    default: /* NGX_ERROR */
        rc = send_error_json(r, 507, "ZONE_FULL");
        break;
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
api_delete_ip(ngx_http_request_t *r)
{
    u_char                       ip_buf[64];
    size_t                       ip_len = 0;
    ngx_str_t                    ip_text;
    u_char                       addr[16];
    uint8_t                      family;
    ngx_int_t                    rc;
    ngx_http_blocklist_shctx_t  *shctx;
    ngx_slab_pool_t             *shpool;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    rc = query_param_lookup(&r->args, "ip", 2, ip_buf, sizeof(ip_buf),
                            &ip_len);
    if (rc == NGX_DECLINED) {
        return send_error_json(r, NGX_HTTP_BAD_REQUEST, "MISSING_PARAM");
    }
    if (rc != NGX_OK) {
        return send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_IP");
    }

    ip_text.data = ip_buf;
    ip_text.len  = ip_len;

    if (ngx_http_blocklist_addr_from_str(&ip_text, addr, &family) != NGX_OK) {
        return send_error_json(r, NGX_HTTP_BAD_REQUEST, "INVALID_IP");
    }

    shctx = get_shctx(r, &shpool);
    if (shctx == NULL) {
        return send_error_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                               "ZONE_NOT_READY");
    }

    rc = ngx_http_blocklist_l1_delete(shctx, shpool, addr);
    if (rc == NGX_DECLINED) {
        return send_error_json(r, NGX_HTTP_NOT_FOUND, "NOT_FOUND");
    }

    return send_ip_success_json(r, NGX_HTTP_OK, addr, family, 0, 0);
}


static ngx_int_t
api_get_list(ngx_http_request_t *r)
{
    /* Task 5 implements. */
    ngx_http_discard_request_body(r);
    return send_error_json(r, NGX_HTTP_NOT_IMPLEMENTED, "NOT_IMPLEMENTED");
}


/*
 * Build and send a JSON response. Takes ownership of neither `body` nor its
 * memory; copies into a pool buf.
 */
static ngx_int_t
send_json_response(ngx_http_request_t *r, ngx_uint_t status,
    u_char *body, size_t body_len)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_int_t     rc;

    r->headers_out.status = status;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (body == NULL || body_len == 0) {
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        return ngx_http_send_header(r);
    }

    r->headers_out.content_length_n = body_len;

    b = ngx_create_temp_buf(r->pool, body_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, body, body_len);
    b->last = b->pos + body_len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
send_error_json(ngx_http_request_t *r, ngx_uint_t status, const char *code)
{
    u_char  body[256];
    u_char *p;

    p = ngx_snprintf(body, sizeof(body),
                     "{\"ok\":false,\"error\":\"%s\",\"code\":\"%s\"}",
                     code, code);
    return send_json_response(r, status, body, p - body);
}


static ngx_int_t
send_ip_success_json(ngx_http_request_t *r, ngx_uint_t status,
    const u_char addr[16], uint8_t family, time_t expire,
    ngx_flag_t with_expire)
{
    u_char     body[256];
    u_char     ip_buf[64];
    u_char    *p;
    ngx_str_t  ip_s;

    ip_s.data = ip_buf;
    ip_s.len  = ngx_http_blocklist_addr_to_str(addr, family, ip_buf,
                                                sizeof(ip_buf));

    if (with_expire) {
        p = ngx_snprintf(body, sizeof(body),
            "{\"ok\":true,\"data\":{\"ip\":\"%V\",\"expire\":%T}}",
            &ip_s, expire);
    } else {
        p = ngx_snprintf(body, sizeof(body),
            "{\"ok\":true,\"data\":{\"ip\":\"%V\"}}",
            &ip_s);
    }

    return send_json_response(r, status, body, p - body);
}


static void
add_allow_header(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    h->value = *value;
}


static ngx_http_blocklist_shctx_t *
get_shctx(ngx_http_request_t *r, ngx_slab_pool_t **shpool_out)
{
    ngx_http_blocklist_main_conf_t  *mcf;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_blocklist_module);
    if (mcf == NULL || mcf->shm_zone == NULL
        || mcf->shm_zone->data == NULL || mcf->shm_zone->shm.addr == NULL)
    {
        return NULL;
    }

    *shpool_out = (ngx_slab_pool_t *) mcf->shm_zone->shm.addr;
    return mcf->shm_zone->data;
}


/*
 * Minimal JSON parser for the POST /ip body. Accepts exactly:
 *   {"ip":"<str>"}
 *   {"ip":"<str>","ttl":<int>}
 *   {"ttl":<int>,"ip":"<str>"}
 * with whitespace allowed between tokens and tolerated trailing content
 * (so a request body with trailing CRLF parses).
 */

static void
skip_ws(const u_char **pp, const u_char *end)
{
    while (*pp < end
        && (**pp == ' ' || **pp == '\t' || **pp == '\r' || **pp == '\n'))
    {
        (*pp)++;
    }
}


static ngx_int_t
expect_ch(const u_char **pp, const u_char *end, u_char c)
{
    skip_ws(pp, end);
    if (*pp >= end || **pp != c) {
        return NGX_ERROR;
    }
    (*pp)++;
    return NGX_OK;
}


static ngx_int_t
parse_string(const u_char **pp, const u_char *end, ngx_str_t *out)
{
    const u_char  *start;

    skip_ws(pp, end);
    if (*pp >= end || **pp != '"') {
        return NGX_ERROR;
    }
    (*pp)++;

    start = *pp;
    while (*pp < end && **pp != '"') {
        if (**pp == '\\') {
            /* MVP: escapes not supported. */
            return NGX_ERROR;
        }
        (*pp)++;
    }
    if (*pp >= end) {
        return NGX_ERROR;
    }

    out->data = (u_char *) start;
    out->len  = (size_t) (*pp - start);
    (*pp)++;  /* consume closing quote */
    return NGX_OK;
}


static ngx_int_t
parse_integer(const u_char **pp, const u_char *end, ngx_int_t *out)
{
    ngx_int_t  v = 0;
    ngx_int_t  sign = 1;
    int        saw_digit = 0;

    skip_ws(pp, end);
    if (*pp < end && **pp == '-') {
        sign = -1;
        (*pp)++;
    }
    while (*pp < end && **pp >= '0' && **pp <= '9') {
        v = v * 10 + (**pp - '0');
        (*pp)++;
        saw_digit = 1;
    }
    if (!saw_digit) {
        return NGX_ERROR;
    }
    *out = sign * v;
    return NGX_OK;
}


static ngx_int_t
parse_post_body(const u_char *buf, size_t len,
    ngx_str_t *ip_out, ngx_int_t *ttl_out)
{
    const u_char  *p = buf;
    const u_char  *end = buf + len;
    ngx_str_t      key;
    int            saw_ip = 0;

    *ttl_out = 0;
    ngx_str_null(ip_out);

    if (expect_ch(&p, end, '{') != NGX_OK) {
        return NGX_ERROR;
    }

    skip_ws(&p, end);
    if (p >= end) {
        return NGX_ERROR;
    }
    if (*p == '}') {
        /* Empty object: "ip" is required. */
        return NGX_ERROR;
    }

    for ( ;; ) {
        if (parse_string(&p, end, &key) != NGX_OK) {
            return NGX_ERROR;
        }
        if (expect_ch(&p, end, ':') != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 2 && ngx_strncmp(key.data, "ip", 2) == 0) {
            if (parse_string(&p, end, ip_out) != NGX_OK) {
                return NGX_ERROR;
            }
            saw_ip = 1;

        } else if (key.len == 3 && ngx_strncmp(key.data, "ttl", 3) == 0) {
            if (parse_integer(&p, end, ttl_out) != NGX_OK) {
                return NGX_ERROR;
            }

        } else {
            return NGX_ERROR;
        }

        skip_ws(&p, end);
        if (p < end && *p == ',') {
            p++;
            continue;
        }
        if (p < end && *p == '}') {
            p++;
            break;
        }
        return NGX_ERROR;
    }

    /* Trailing whitespace/CRLF after the object is tolerated. */
    if (!saw_ip) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * Scan query-string args for `<key>=<value>`, URL-decode value into out buf.
 *
 * Returns:
 *   NGX_OK       - found and decoded; *outlen set.
 *   NGX_DECLINED - key not present in args.
 *   NGX_ERROR    - value empty or longer than outcap.
 */
static ngx_int_t
query_param_lookup(ngx_str_t *args, const char *key, size_t keylen,
    u_char *out, size_t outcap, size_t *outlen)
{
    u_char  *p, *end, *vstart, *vend, *src, *dst;
    size_t   vlen;

    if (args->len == 0) {
        return NGX_DECLINED;
    }

    p   = args->data;
    end = args->data + args->len;

    while (p < end) {
        if ((size_t) (end - p) > keylen
            && ngx_strncmp(p, key, keylen) == 0
            && p[keylen] == '=')
        {
            vstart = p + keylen + 1;
            vend = vstart;
            while (vend < end && *vend != '&') {
                vend++;
            }
            vlen = vend - vstart;

            if (vlen == 0 || vlen > outcap) {
                return NGX_ERROR;
            }

            src = vstart;
            dst = out;
            ngx_unescape_uri(&dst, &src, vlen, 0);
            *outlen = dst - out;
            return NGX_OK;
        }

        while (p < end && *p != '&') {
            p++;
        }
        if (p < end) {
            p++;  /* skip the '&' */
        }
    }

    return NGX_DECLINED;
}
