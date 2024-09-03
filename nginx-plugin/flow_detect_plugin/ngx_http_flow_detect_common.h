#ifndef _NGX_HTTP_H_DETECT_COMMON_
#define _NGX_HTTP_H_DETECT_COMMON_

#define FLOW_DETECT_OK          200
#define FLOW_DETECT_HAVE_ATTACK 403

#define FLOW_DETECT_DIR_REQ 	 0
#define FLOW_DETECT_DIR_RES 	 1

typedef struct {
	ngx_int_t		status;
} ngx_http_flow_detect_ctx_t;

typedef struct {
    uint32_t                status;
    size_t                  body_buf_size;
    size_t                  remain_body_size;
    size_t                  recv_body_size;
    ngx_chain_t             *detect_body;
    ngx_chain_t             *detect_body_file;
    ngx_buf_t               *detect_header;
    ngx_chain_t             *body_chain;
    ngx_chain_t             **body_chain_next;
    ngx_temp_file_t         *temp_file;
    u_char                  recv_finish:1,
                            done:1,
                            send:1;
} ngx_http_flow_detect_filter_ctx_t;

typedef struct {
    uint32_t                done;
    uint32_t                status;
} ngx_http_flow_detect_req_ctx_t;

extern ngx_module_t  ngx_http_flow_detect_module;
extern ngx_module_t  ngx_http_flow_detect_filter_module;
extern ngx_module_t  ngx_http_flow_detect_req_module;

extern ngx_atomic_t *ngx_http_flow_detect_req_count;
extern ngx_atomic_t *ngx_http_flow_detect_req_time;
extern ngx_atomic_t *ngx_http_flow_detect_res_count;
extern ngx_atomic_t *ngx_http_flow_detect_res_time;

static inline ngx_chain_t * ngx_alloc_chain_buf(ngx_pool_t *pool, size_t size, ngx_int_t type) {
    ngx_chain_t *cl = NULL;
    
    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL)
        return NULL;

    cl->next = NULL;
    
    if (type == 0) {
        cl->buf = ngx_create_temp_buf(pool, size);
        if (cl->buf == NULL)
            return NULL;
    } else {
        cl->buf = ngx_calloc_buf(pool);
        if (cl->buf == NULL)
            return NULL;
    }

    return cl;
}

#endif