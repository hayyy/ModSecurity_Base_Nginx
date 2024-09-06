#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_flow_detect_common.h"

typedef struct {
    size_t        flow_detect_rsp_buffer_size;
    size_t        flow_detect_rsp_body_size;
    ngx_path_t    *flow_detect_rsp_temp_path;
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

    { ngx_string("flow_detect_rsp_buffer_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_rsp_buffer_size),
      NULL },
    { ngx_string("flow_detect_rsp_temp_path"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_rsp_temp_path),
      NULL },
    { ngx_string("flow_detect_rsp_body_size"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flow_detect_filter_conf_t, flow_detect_rsp_body_size),
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

	conf->flow_detect_rsp_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->flow_detect_rsp_body_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_http_flow_detect_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flow_detect_filter_conf_t *prev = parent;
    ngx_http_flow_detect_filter_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->flow_detect_rsp_buffer_size,
                              prev->flow_detect_rsp_buffer_size,
                              (size_t) 2 * ngx_pagesize);
    ngx_conf_merge_size_value(conf->flow_detect_rsp_body_size,
                              prev->flow_detect_rsp_body_size,
                              (size_t) 2 * ngx_pagesize);

    if (conf->flow_detect_rsp_temp_path == NULL && prev->flow_detect_rsp_temp_path == NULL) {
        return NGX_CONF_OK;
    }
    if (ngx_conf_merge_path_value(cf, &conf->flow_detect_rsp_temp_path,
                              prev->flow_detect_rsp_temp_path,
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
        //上游服务器连接失败时，u->buffer.start为空，没有读取到响应头
        if (u->buffer.start == 0) {
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
        ctx->body_buf_size = conf->flow_detect_rsp_buffer_size;
        ctx->recv_body_size = ctx->remain_body_size = conf->flow_detect_rsp_body_size;
        if (!u->headers_in.chunked) {
            if ((size_t)u->headers_in.content_length_n < ctx->body_buf_size) {
                ctx->body_buf_size = u->headers_in.content_length_n;
            }
            if ((size_t)u->headers_in.content_length_n < ctx->remain_body_size) {
                ctx->recv_body_size = ctx->remain_body_size = u->headers_in.content_length_n;
            }
        }
        if (ctx->body_buf_size > 0) {
            ctx->detect_body = ngx_alloc_chain_buf(r->pool, ctx->body_buf_size, 0);
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
    ngx_chain_t *chain = NULL, **cl = NULL, *l = NULL;
    ngx_buf_t *b = NULL;

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
        cl = &chain;
        if (ctx->detect_body_file) {
            *cl = ctx->detect_body_file;
            cl = &ctx->detect_body_file->next;
        }
        b = ctx->detect_body->buf;
        if (ngx_buf_size(b) || b->last_buf == 1) {
            *cl = ctx->detect_body;
            cl = &ctx->detect_body->next;
        }
        if (ctx->body_chain) {
            *cl = ctx->body_chain;
            if (*cl) {
                l = *cl;
                for (;l->next; l = l->next) {}
                cl = &l->next;
            }
        }
        if (in) {
            *cl = in;
        }
        return ngx_http_next_body_filter(r, chain);
    }

    if (!ctx->done && ctx->recv_finish) {
        if (in) {
            if (in->buf->last_buf == 1) {
                /*这个in指针指向的内存实质是局部变量内存，
                 *需要重新申请一个ngx_chain_t, 将in内容拷贝过去
                 */
                chain = ngx_alloc_chain_link(r->pool);
                if (chain == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(chain, in, sizeof(ngx_chain_t));
                in = chain;
            }
            if (ctx->body_chain) {
                *(ctx->body_chain_next) = in;
                for (;in->next; in = in->next) {}
                ctx->body_chain_next = &in->next;
             }
            else {
                ctx->body_chain = in;
                ctx->body_chain_next = &in->next;
            }
        }
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

        if (ctx->temp_file != NULL) {
            chain = ngx_alloc_chain_buf(r->pool, 0, 1);
            if (chain == NULL)
                return NGX_ERROR;
            
            b = chain->buf;
            b->file = &ctx->temp_file->file;
            b->file_pos = 0;
            b->file_last = ctx->temp_file->offset;

            b->in_file = 1;
            b->temp_file = 1;

            chain->buf = b;
            chain->next = NULL;
            
            ctx->detect_body_file = chain;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_flow_detect_copy_body_detail(ngx_http_request_t *r, ngx_chain_t *in, size_t size) {
    size_t space = 0;
    ngx_http_flow_detect_filter_ctx_t *ctx = NULL;
    ngx_http_flow_detect_filter_conf_t *conf = NULL;
    ngx_buf_t *detect_body = NULL;
    ssize_t n = 0;
    ngx_chain_t cl = {0};

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_filter_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);
    detect_body = ctx->detect_body->buf;
    space = detect_body->end - detect_body->last;
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "space:%d size:%d", space, size);
    if (space) {
        if (space > size) {
            detect_body->last = ngx_copy(detect_body->last, in->buf->pos, size);
            in->buf->pos += size;
            ctx->remain_body_size -= size;
            size = 0;
        } else {
            detect_body->last = ngx_copy(detect_body->last, in->buf->pos, space);
            size -= space;
            in->buf->pos += space;
            ctx->remain_body_size -= space;
        }
    }

    if (ctx->remain_body_size == 0 || size == 0) {
        return NGX_OK;
    }

    if (ctx->temp_file == NULL) {
        ctx->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (ctx->temp_file == NULL) {
            return NGX_ERROR;
        }

        ctx->temp_file->file.fd = NGX_INVALID_FILE;
        ctx->temp_file->file.log = r->connection->log;
        ctx->temp_file->path = conf->flow_detect_rsp_temp_path;
        ctx->temp_file->pool = r->pool;

        ctx->temp_file->log_level = NGX_LOG_WARN;
        ctx->temp_file->warn = "flow detect http response is buffered "
                                        "to a temporary file";
    }

    if (size) {
        cl.buf = detect_body;
        cl.next = NULL;
        n = ngx_write_chain_to_temp_file(ctx->temp_file, &cl);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
        
        ctx->temp_file->offset += n;
        detect_body->pos = detect_body->last = detect_body->start;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "flow detect res body file temp offset: %O", ctx->temp_file->offset);

    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_flow_detect_copy_body(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_flow_detect_filter_ctx_t *ctx = NULL;
    size_t copy_size = 0;
    ngx_int_t ret = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_filter_module);

    //没有响应body
    if (ctx->detect_body->buf == NULL) {
        return NGX_OK;
    }
    
    while(in) {
        copy_size = in->buf->last - in->buf->pos;
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "copy_size: %d, buf:%p, remain_body_size:%d", copy_size, in, ctx->remain_body_size);
        if (copy_size && ctx->remain_body_size) {
            if (copy_size > ctx->remain_body_size)
                copy_size = ctx->remain_body_size;
            ret = ngx_http_flow_detect_copy_body_detail(r, in, copy_size);
            if (ret == NGX_ERROR) {
                return ret;
            }
        }
        if (ctx->remain_body_size == 0 || in->buf->last_buf) {
            ctx->detect_body->buf->last_buf = in->buf->last_buf;
            ctx->recv_finish = 1;
            if (ngx_buf_size(in->buf) == 0)
                in = in->next;
            if (in) {
                ctx->body_chain = in;
                for (;in->next; in = in->next) {}
                ctx->body_chain_next = &in->next;
            }
            break;
        }
        if (ngx_buf_size(in->buf) == 0) {
            in = in->next;
        }
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_flow_detect_filter_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc) {

    ngx_http_flow_detect_filter_ctx_t   *filter_ctx = data;
    ngx_http_flow_detect_ctx_t          *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_module);

    //该函数在子请求异常情况下会执行两次
    //1.ngx_http_finalize_request->2.ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
    if (filter_ctx->done == 0) {
        filter_ctx->done = 1;
        filter_ctx->status = ctx->status;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx http flow detect filter done, detect result is :%ui", filter_ctx->status);

        if (filter_ctx->status == 0) {
            ngx_atomic_fetch_add(ngx_http_flow_detect_res_fail, 1);
        }
        
        ngx_atomic_fetch_add(ngx_http_flow_detect_res_time, r->upstream->state->response_time);
    }

    return rc;
}

