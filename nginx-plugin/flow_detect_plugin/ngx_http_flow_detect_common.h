

typedef struct {
	ngx_int_t		status;
} ngx_http_flow_detect_ctx_t;

extern ngx_module_t  ngx_http_flow_detect_module;

extern ngx_atomic_t *ngx_http_flow_detect_req_count;
extern ngx_atomic_t *ngx_http_flow_detect_req_time;



