#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_flow_detect_common.h"

static ngx_int_t ngx_http_flow_detect_status_handler(ngx_http_request_t *r);
static char *ngx_http_set_flow_detect_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_flow_detect_status_init_module(ngx_cycle_t *cycle);

ngx_atomic_t *ngx_http_flow_detect_req_count;
ngx_atomic_t *ngx_http_flow_detect_req_time;
ngx_atomic_t *ngx_http_flow_detect_res_count;
ngx_atomic_t *ngx_http_flow_detect_res_time;


static ngx_command_t  ngx_http_flow_detect_status_commands[] = {

    { ngx_string("flow_detect_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_set_flow_detect_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flow_detect_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_flow_detect_status_module = {
    NGX_MODULE_V1,
    &ngx_http_flow_detect_status_module_ctx,     /* module context */
    ngx_http_flow_detect_status_commands,        /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    ngx_http_flow_detect_status_init_module,     /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_flow_detect_status_init_module(ngx_cycle_t *cycle) {
     ngx_shm_t shm;
     size_t size, cl;
     u_char *shared;

     cl = 128;
     size = cl          //ngx_http_flow_detect_req_count;
            + cl        //ngx_http_flow_detect_req_time;
            + cl        //ngx_http_flow_detect_res_count;
            + cl;       //ngx_http_flow_detect_res_time;

    shm.size = size;
    ngx_str_set(&shm.name, "nginx_http_flow_detect_shared_zone");
    shm.log = cycle->log;

    if (ngx_shm_alloc(&shm) != NGX_OK)
    {
        return NGX_ERROR;
    }

    shared = shm.addr;

    ngx_http_flow_detect_req_count = (ngx_atomic_t *)(shared);
    ngx_http_flow_detect_req_time = (ngx_atomic_t *)(shared + cl);
    ngx_http_flow_detect_res_count = (ngx_atomic_t *)(shared + 2 * cl);
    ngx_http_flow_detect_res_time = (ngx_atomic_t *)(shared + 3 * cl);

    return NGX_OK;
}



static ngx_int_t
ngx_http_flow_detect_status_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   req_count, req_time;
    ngx_atomic_int_t   res_count, res_time;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    size = sizeof("Flow detect req count:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("Flow detect req time:  \n") + 2 + NGX_ATOMIC_T_LEN
           + sizeof("Flow detect res count:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("Flow detect res time:  \n") + 2 + NGX_ATOMIC_T_LEN;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    req_count = *ngx_http_flow_detect_req_count;
    req_time = *ngx_http_flow_detect_req_time;
    res_count = *ngx_http_flow_detect_res_count;
    res_time = *ngx_http_flow_detect_res_time;


    b->last = ngx_sprintf(b->last, "Flow detect req count: %uA \n", req_count);
    b->last = ngx_sprintf(b->last, "Flow detect req time: %uA ms\n", req_time);
    b->last = ngx_sprintf(b->last, "Flow detect res count: %uA \n", res_count);
    b->last = ngx_sprintf(b->last, "Flow detect res time: %uA ms\n", res_time);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_set_flow_detect_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flow_detect_status_handler;

    return NGX_CONF_OK;
}

