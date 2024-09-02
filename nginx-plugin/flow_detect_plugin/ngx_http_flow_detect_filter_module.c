#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_flow_detect_common.h"

typedef struct {
	size_t        flow_detect_buffer_size;
    size_t        flow_detect_body_size;
    ngx_path_t    *flow_detect_temp_path;
} ngx_http_flow_detect_filter_conf_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void *ngx_http_flow_detect_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_flow_detect_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_flow_detect_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_flow_detect_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_flow_detect_copy_body(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_flow_detect_filter_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_http_flow_detect_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_flow_detect_filter_commands[] = {

    { ngx_string("flow_detect_buffer_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_buffer_size),
      NULL },
    { ngx_string("flow_detect_temp_path"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_temp_path),
      NULL },
    { ngx_string("flow_detect_body_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_body_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flow_detect_filter_module_ctx = {
    NULL,                                        /* preconfiguration */
    ngx_http_flow_detect_filter_init,            /* postconfiguration */

    NULL,                                        /* create main configuration */
    NULL,                                        /* init main configuration */

    NULL,                                        /* create server configuration */
    NULL,                                        /* merge server configuration */

    ngx_http_flow_detect_filter_create_conf,     /* create location configuration */
    ngx_http_flow_detect_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_flow_detect_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_flow_detect_filter_module_ctx,     /* module context */
    ngx_http_flow_detect_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       	     /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t 
ngx_http_flow_detect_filter_init(ngx_conf_t *cf) {

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_flow_detect_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_flow_detect_body_filter;

    return NGX_OK;
}

static void *
ngx_http_flow_detect_filter_create_conf(ngx_conf_t *cf) {
	ngx_http_flow_detect_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flow_detect_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	conf->flow_detect_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->flow_detect_body_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_http_flow_detect_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flow_detect_filter_conf_t *prev = parent;
    ngx_http_flow_detect_filter_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->flow_detect_buffer_size,
                              prev->flow_detect_buffer_size,
                              (size_t) 2 * ngx_pagesize);
    ngx_conf_merge_size_value(conf->flow_detect_body_size,
                              prev->flow_detect_body_size,
                              (size_t) 2 * ngx_pagesize);

    return NGX_CONF_OK;
     
    if (conf->flow_detect_temp_path == NULL && prev->flow_detect_temp_path == NULL) {
        return NGX_CONF_ERROR;
    }
    
    if (ngx_conf_merge_path_value(cf, &conf->flow_detect_temp_path,
                              prev->flow_detect_temp_path,
                              NULL)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_flow_detect_header_filter(ngx_http_request_t *r) {
    ngx_http_flow_detect_req_ctx_t *flow_detect_req_ctx = NULL;
    ngx_http_flow_detect_filter_ctx_t *ctx = NULL;
    ngx_http_upstream_t   *u = NULL;
    ngx_http_flow_detect_filter_conf_t *conf = NULL;
    size_t header_size = 0;
    ngx_buf_t *b = NULL;

    flow_detect_req_ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_req_module);
    if (r != r->main || flow_detect_req_ctx == NULL || r->upstream == NULL) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_filter_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);

    if (ctx != NULL && ctx->done) {
        return ngx_http_next_header_filter(r);
    }
    
    if (ctx == NULL) {
        u = r->upstream;
        //上游服务器连接失败时，u->buffer为空，没有读取到响应头
        b = &(u->buffer);
        if (ngx_buf_size(b) == 0) {
            return ngx_http_next_header_filter(r);
        }
        
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flow_detect_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

	    ngx_http_set_ctx(r, ctx, ngx_http_flow_detect_filter_module);

        //拷贝上游服务器原始响应头
        header_size = u->buffer.pos - u->buffer.start;
        ctx->detect_header = ngx_create_temp_buf(r->pool, header_size);
        if (ctx->detect_header == NULL)
            return NGX_ERROR;
        ctx->detect_header->last = ngx_copy(ctx->detect_header->last, u->buffer.start, header_size);

        //开辟body缓冲区，用于缓存待检测的body
        ctx->body_buf_size = conf->flow_detect_buffer_size;
        if (!u->headers_in.chunked) {
            if ((size_t)u->headers_in.content_length_n < ctx->body_buf_size)
                ctx->body_buf_size = u->headers_in.content_length_n;
        }
        if (ctx->body_buf_size > 0) {
            ctx->detect_body = ngx_create_temp_buf(r->pool, ctx->body_buf_size);
            if (ctx->detect_body == NULL)
                return NGX_ERROR;
        }
    }


    return NGX_OK;
}

static ngx_int_t
ngx_http_flow_detect_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_flow_detect_filter_ctx_t *ctx = NULL;
    ngx_int_t ret = 0;
    ngx_http_post_subrequest_t  *ps   = NULL;
	ngx_http_request_t *sr = NULL;
    ngx_chain_t * chain = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);
    if(ctx == NULL || (ctx->done && ctx->send)) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->done && !ctx->send) {
        ctx->send = 1;
        if (ctx->status == FLOW_DETECT_HAVE_ATTACK) {
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
            return NGX_OK;
        }
        ret = ngx_http_next_header_filter(r);
        if (ret == NGX_ERROR) {
            return ret;
        }
        chain = ngx_alloc_chain_link(r->pool);
        if (chain == NULL) {
            return NGX_ERROR;
        }
        chain->buf = ctx->detect_body;
        chain->next = NULL;
        if (in) {
            chain->next = in;
        }
        return ngx_http_next_body_filter(r, chain);
    }

    if (ctx->recv_finish) {
        return NGX_OK;
    }

    ret = ngx_http_flow_detect_copy_body(r, in);
    if (ret != NGX_OK) {
        return ret;
    }

    if (ctx->recv_finish) {    	
    	ps = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (ps == NULL) {
            return NGX_ERROR;
        }

        ps->handler = ngx_http_flow_detect_filter_done;
        ps->data = ctx;

    	ngx_str_t url = ngx_string("/flow_detect");
        ngx_str_t args = ngx_string("dir=1");
        if (ngx_http_subrequest(r, &url, &args, &sr, ps, 0)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "ngx_http_flow_detect_filter_module create subrequest fail");
        }

        ngx_http_set_ctx(sr, ctx, ngx_http_flow_detect_filter_module);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_flow_detect_copy_body(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_flow_detect_filter_conf_t *conf = NULL;
    ngx_http_flow_detect_filter_ctx_t *ctx = NULL;
    size_t buf_size = 0;
    
    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_filter_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);
    for(; in; in = in->next) {
        buf_size = in->buf->last - in->buf->pos;
        if (buf_size && ctx->recv_body_size < conf->flow_detect_body_size) {
            ctx->detect_body->last = ngx_copy(ctx->detect_body->last, in->buf->pos, buf_size);
            in->buf->pos = in->buf->last;
            ctx->recv_body_size += buf_size;
        }
        if (ctx->recv_body_size >= conf->flow_detect_body_size || in->buf->last_buf) {
            ctx->detect_body->last_buf = 1;
            ctx->recv_finish = 1;
            break;
        }
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_flow_detect_filter_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc) {

	ngx_http_flow_detect_filter_ctx_t   *filter_ctx = data;
	ngx_http_flow_detect_ctx_t          *ctx = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_module);

	filter_ctx->done = 1;
	filter_ctx->status = ctx->status;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx http flow detect filter done, detect result is :%ui", filter_ctx->status);

    ngx_atomic_fetch_add(ngx_http_flow_detect_res_time, r->upstream->state->response_time);

    return rc;
}

