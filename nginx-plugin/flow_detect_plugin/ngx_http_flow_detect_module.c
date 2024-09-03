#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_flow_detect_common.h"

typedef struct {
    ngx_http_upstream_conf_t   upstream;
    size_t                     flow_detect_req_body_size;
} ngx_http_flow_detect_conf_t;

//detect result
typedef struct {
    uint32_t      status;
}ngx_http_flow_detect_res_t;

typedef struct {
    u_char         dir:1;
    uint32_t       src_ip;
    uint32_t       dst_ip;
    uint16_t       src_port;
    uint16_t       dst_port;
    uint32_t       header_len;
    uint32_t       body_len;

	char           data[0];
}ngx_http_flow_detect_data_t;

static void *ngx_http_flow_detect_create_conf(ngx_conf_t *cf);
static char *ngx_http_flow_detect_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_flow_detect_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_flow_detect_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_flow_detect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_flow_detect_create_req_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_flow_detect_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_flow_detect_process_header(ngx_http_request_t *r);
static void ngx_http_flow_detect_abort_request(ngx_http_request_t *r);
static void ngx_http_flow_detect_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_flow_detect_create_filter_request(ngx_http_request_t *r);


static ngx_command_t  ngx_http_flow_detect_commands[] = {

    { ngx_string("flow_detect_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_flow_detect_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("flow_detect_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_conf_t, upstream.buffer_size),
      NULL },
    { ngx_string("flow_detect_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_conf_t, upstream.connect_timeout),
      NULL },
    { ngx_string("flow_detect_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_conf_t, upstream.send_timeout),
      NULL },
    { ngx_string("flow_detect_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_conf_t, upstream.read_timeout),
      NULL },
    { ngx_string("flow_detect_req_body_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_conf_t, flow_detect_req_body_size),
      NULL },

     ngx_null_command
};


static ngx_http_module_t  ngx_http_flow_detect_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_flow_detect_init,                /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_flow_detect_create_conf,         /* create location configuration */
    ngx_http_flow_detect_merge_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_flow_detect_module = {
    NGX_MODULE_V1,
    &ngx_http_flow_detect_module_ctx,     /* module context */
    ngx_http_flow_detect_commands,        /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_flow_detect_create_conf(ngx_conf_t *cf) {
    ngx_http_flow_detect_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flow_detect_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->flow_detect_req_body_size = NGX_CONF_UNSET_SIZE;

	return conf;
}

static char *
ngx_http_flow_detect_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_flow_detect_conf_t *prev = parent;
    ngx_http_flow_detect_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 1000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 1000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 1000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;

    ngx_conf_merge_size_value(conf->flow_detect_req_body_size,
                              prev->flow_detect_req_body_size,
                              (size_t) 2 * ngx_pagesize);

    return NGX_CONF_OK;
}

static char *
ngx_http_flow_detect_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_flow_detect_conf_t *flow_cf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;

    if (flow_cf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flow_cf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (flow_cf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_flow_detect_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flow_detect_handler;

    return NGX_OK;
}

static ngx_int_t 
ngx_http_flow_detect_handler(ngx_http_request_t *r) {
    ngx_http_flow_detect_conf_t *conf = NULL;
    ngx_http_upstream_t  *u = NULL;
    ngx_http_flow_detect_ctx_t *ctx = NULL;
    ngx_str_t args = {0};
    const char* dir_str = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_module);
    if (r == r->main || conf->upstream.upstream == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flow_detect_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_flow_detect_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "flow_detect_pass://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_flow_detect_module_ctx;

    u->conf = &conf->upstream;

    args = r->args;
    dir_str = "dir=0";
    if (ngx_memcmp(args.data, dir_str, strlen(dir_str)) == 0) {
        //请求方向
        u->create_request = ngx_http_flow_detect_create_req_request;
        ngx_atomic_fetch_add(ngx_http_flow_detect_req_count, 1);
    } else {
        //响应方向
        u->create_request = ngx_http_flow_detect_create_filter_request;
        ngx_atomic_fetch_add(ngx_http_flow_detect_res_count, 1);
    }
    u->reinit_request = ngx_http_flow_detect_reinit_request;
    u->process_header = ngx_http_flow_detect_process_header;
    u->abort_request = ngx_http_flow_detect_abort_request;
    u->finalize_request = ngx_http_flow_detect_finalize_request;

    //nginx和ModSecurity进程维持长连接
    u->keepalive = 1;

    r->header_only = 1;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static ngx_int_t 
ngx_http_flow_detect_reinit_request(ngx_http_request_t *r) {
    return NGX_OK;
}

static void 
ngx_http_flow_detect_abort_request(ngx_http_request_t *r) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort flow detect request");
}

static void
ngx_http_flow_detect_finalize_request(ngx_http_request_t *r,ngx_int_t rc) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "finsh flow detect request");
}

static ngx_int_t 
ngx_http_flow_detect_create_req_request(ngx_http_request_t *r) {

    ngx_chain_t *body = NULL, *cl = NULL, *chain = NULL;
    ngx_buf_t *b = NULL;
    ngx_http_upstream_t  *u = NULL;
    ngx_http_flow_detect_data_t  *flow_detect_data = NULL;
    uint32_t header_length = 0;
    uint32_t body_length = 0;
    uint32_t length = 0;
    ngx_connection_t *connection = NULL;
    struct sockaddr_in *addr = NULL;
    ngx_list_part_t   *part = NULL;
    ngx_table_elt_t   *header = NULL;
    ngx_uint_t i = 0;
    ngx_http_flow_detect_conf_t *conf = NULL;

    header_length = r->request_line.len + (sizeof(CRLF) - 1) * 2;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }
        header_length += header[i].key.len + sizeof(": ") - 1
            + header[i].value.len + sizeof(CRLF) - 1;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_module);
    body_length = r->headers_in.content_length_n == -1 ? 0 : r->headers_in.content_length_n;
    if (body_length > conf->flow_detect_req_body_size) {
        body_length = conf->flow_detect_req_body_size;
    }
        
    length = sizeof(ngx_http_flow_detect_data_t) + header_length;
    flow_detect_data = ngx_pcalloc(r->pool, length);
    if (flow_detect_data == NULL) {
        return NGX_ERROR;
    }

    flow_detect_data->dir = FLOW_DETECT_DIR_REQ;

    connection = r->connection;
    addr = (struct sockaddr_in *)(connection->sockaddr);
    //Already in network byte order
    flow_detect_data->src_ip = addr->sin_addr.s_addr;
    flow_detect_data->src_port = addr->sin_port;

    addr = (struct sockaddr_in *)connection->local_sockaddr;
    flow_detect_data->dst_ip = addr->sin_addr.s_addr;
    flow_detect_data->dst_port = addr->sin_port;

    u = r->upstream;

    flow_detect_data->header_len = htonl(header_length);
    flow_detect_data->body_len = htonl(body_length);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->start = (u_char*)flow_detect_data;
    b->pos = b->start;
    b->end = b->start + sizeof(ngx_http_flow_detect_data_t) + header_length;
    b->last = b->start + sizeof(ngx_http_flow_detect_data_t);
    b->temporary = 1;

    b->last = ngx_copy(b->last, r->request_line.data, r->request_line.len);
    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data,
                           header[i].value.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    //The body has been assigned to u->request_bufs in the ngx_http_upstream_init_request function
    body = u->request_bufs;
    u->request_bufs = cl;
    while (body) {
        b = body->buf;
        length = ngx_buf_size(b);
        if (length == 0) {
            body = body->next;
            continue;
        }
        chain = ngx_alloc_chain_link(r->pool);
        if (chain == NULL) {
            return NGX_ERROR;
        }
        chain->buf = ngx_calloc_buf(r->pool);
        if (chain->buf == NULL) {
            return NGX_ERROR;
        }
        chain->next = NULL;
        ngx_memcpy(chain->buf, b, sizeof(ngx_buf_t));
        cl->next = chain;
        cl = chain;
        if (body_length <= length) {
            if (ngx_buf_in_memory(b)) {
                chain->buf->last = chain->buf->pos + body_length;
            } else {
                chain->buf->file_last = chain->buf->file_pos + body_length;
            }
            break;
        }
        body_length -= length;
        body = body->next;
    }


    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "flow detect req data header:\n%*s", header_length, flow_detect_data->data);

    return NGX_OK;
}

static ngx_int_t 
ngx_http_flow_detect_process_header(ngx_http_request_t *r) {
    ngx_http_upstream_t   *u = NULL;
    ngx_http_flow_detect_res_t *detect_res = NULL;
    uint32_t length = 0;
    ngx_http_flow_detect_ctx_t *ctx = NULL;

    u = r->upstream;
    length = u->buffer.last - u->buffer.pos;
    if (length < sizeof(ngx_http_flow_detect_res_t))
        return NGX_AGAIN;

    detect_res = (ngx_http_flow_detect_res_t*)(u->buffer.pos);

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_module);
    ctx->status = ntohl(detect_res->status);

    return NGX_OK;
}

static ngx_int_t 
ngx_http_flow_detect_create_filter_request(ngx_http_request_t *r) {
    ngx_chain_t *cl = NULL, *l = NULL;
    ngx_buf_t *b = NULL;
    ngx_http_upstream_t  *u = NULL;
    ngx_http_flow_detect_data_t  *flow_detect_data = NULL;
    uint32_t header_length = 0;
    uint32_t body_length = 0;
    uint32_t length = 0;
    ngx_connection_t *connection = NULL;
    struct sockaddr_in *addr = NULL;
    ngx_http_flow_detect_filter_ctx_t    *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);

    header_length = ctx->detect_header->last - ctx->detect_header->pos;
    body_length = ctx->recv_body_size;

    length = sizeof(ngx_http_flow_detect_data_t) + header_length;
    flow_detect_data = ngx_pcalloc(r->pool, length);
    if (flow_detect_data == NULL) {
        return NGX_ERROR;
    }

    flow_detect_data->dir = FLOW_DETECT_DIR_RES;

    connection = r->connection;
    addr = (struct sockaddr_in *)(connection->sockaddr);
    //Already in network byte order
    flow_detect_data->src_ip = addr->sin_addr.s_addr;
    flow_detect_data->src_port = addr->sin_port;

    addr = (struct sockaddr_in *)connection->local_sockaddr;
    flow_detect_data->dst_ip = addr->sin_addr.s_addr;
    flow_detect_data->dst_port = addr->sin_port;

    flow_detect_data->header_len = htonl(header_length);
    flow_detect_data->body_len = htonl(body_length);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->start = (u_char*)flow_detect_data;
    b->pos = b->start;
    b->end = b->start + sizeof(ngx_http_flow_detect_data_t) + header_length;
    b->last = b->start + sizeof(ngx_http_flow_detect_data_t);
    b->temporary = 1;

    b->last = ngx_copy(b->last, ctx->detect_header->pos, header_length);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    u = r->upstream;
    u->request_bufs = cl;

    if (ctx->detect_body_file) {
        l = ngx_alloc_chain_buf(r->pool, 0, 1);
        if (l == NULL)
            return NGX_ERROR;
        b = l->buf;
        ngx_memcpy(l, ctx->detect_body_file, sizeof(ngx_chain_t));
        ngx_memcpy(b, ctx->detect_body_file->buf, sizeof(ngx_buf_t));
        l->buf = b;
        cl->next = l;
        cl = cl->next;
    }

    if (ngx_buf_size(ctx->detect_body->buf)) {
        l = ngx_alloc_chain_buf(r->pool, 0, 1);
        if (l == NULL)
            return NGX_ERROR;
        b = l->buf;
        ngx_memcpy(l, ctx->detect_body, sizeof(ngx_chain_t));
        ngx_memcpy(b, ctx->detect_body->buf, sizeof(ngx_buf_t));
        l->buf = b;
        cl->next = l;
        cl = cl->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "flow detect res header data:\n%*s", header_length, flow_detect_data->data);

    return NGX_OK;
}

