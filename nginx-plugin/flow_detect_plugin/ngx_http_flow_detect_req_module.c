#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_flow_detect_common.h"


typedef struct {
    ngx_flag_t      flow_detect_switch;
} ngx_http_flow_detect_req_conf_t;

static ngx_int_t ngx_http_flow_detect_req_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_flow_detect_req_handler(ngx_http_request_t *r);
static void *ngx_http_flow_detect_req_create_conf(ngx_conf_t *cf);
static char *ngx_http_flow_detect_req_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_flow_detect_req_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);


static ngx_command_t  ngx_http_flow_detect_req_commands[] = {

    { ngx_string("flow_detect_switch"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flow_detect_req_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_flow_detect_req_init,                /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_flow_detect_req_create_conf,     /* create location configuration */
    ngx_http_flow_detect_req_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_flow_detect_req_module = {
    NGX_MODULE_V1,
    &ngx_http_flow_detect_req_module_ctx,     /* module context */
    ngx_http_flow_detect_req_commands,        /* module directives */
    NGX_HTTP_MODULE,                       	  /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_flow_detect_req_create_conf(ngx_conf_t *cf) {
    ngx_http_flow_detect_req_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flow_detect_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->flow_detect_switch = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_flow_detect_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flow_detect_req_conf_t *prev = parent;
    ngx_http_flow_detect_req_conf_t *conf = child;

    ngx_conf_merge_value(conf->flow_detect_switch, prev->flow_detect_switch, 0);

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_flow_detect_req_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flow_detect_req_handler;

    return NGX_OK;
}

static void
ngx_http_flow_detect_req_subrequest(ngx_http_request_t *r) {
    ngx_http_post_subrequest_t  *ps   = NULL;
    ngx_http_request_t *sr = NULL;
    ngx_http_flow_detect_req_ctx_t  *ctx  = NULL;

    ps = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return ;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_req_module);
    ps->handler = ngx_http_flow_detect_req_done;
    ps->data = ctx;

    ngx_str_t url = ngx_string("/flow_detect");
    ngx_str_t args = ngx_string("dir=0");
    if (ngx_http_subrequest(r, &url, &args, &sr, ps, 0)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "ngx_http_flow_detect_req_module create subrequest fail");
    }

    sr->header_in = r->header_in;
    sr->request_length = r->request_length;
}


static ngx_int_t 
ngx_http_flow_detect_req_handler(ngx_http_request_t *r) {
    ngx_http_flow_detect_req_conf_t *conf = NULL;
    ngx_http_flow_detect_req_ctx_t  *ctx  = NULL;
    ngx_int_t rc = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flow_detect_req_module);

    if (r != r->main || conf->flow_detect_switch == 0) {
    	//Skip this plugin and execute the next plugin in the access phase
    	return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "flow detect handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_req_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == FLOW_DETECT_HAVE_ATTACK) {
            return NGX_HTTP_FORBIDDEN;
        }

        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flow_detect_req_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_flow_detect_req_module);

    rc = ngx_http_read_client_request_body(r, ngx_http_flow_detect_req_subrequest);

    ngx_http_finalize_request(r, NGX_DONE);
	
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_AGAIN;
}

static ngx_int_t ngx_http_flow_detect_req_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc) {

    ngx_http_flow_detect_req_ctx_t   *req_ctx = data;
    ngx_http_flow_detect_ctx_t       *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flow_detect_module);

    if (req_ctx->done == 0) {
        req_ctx->done = 1;
        req_ctx->status = ctx->status;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx http flow detect request done, detect result is :%ui", req_ctx->status);

        if (req_ctx->status == 0) {
            ngx_atomic_fetch_add(ngx_http_flow_detect_req_fail, 1);
        }

        ngx_atomic_fetch_add(ngx_http_flow_detect_req_time, r->upstream->state->response_time);

        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return rc;
}

