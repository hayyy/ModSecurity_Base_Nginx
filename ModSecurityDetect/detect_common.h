#ifndef DETECT_COMMON_H
#define DETECT_COMMON_H

#include <stdint.h>
#include <jemalloc/jemalloc.h>
#include "tlog.h"

extern int g_worker_id;
extern int g_module_num;
extern void (**g_module_ctx_free_func)(void*);

#define logger_info(format, ...) tlog(TLOG_INFO, "worker-%d:"format, g_worker_id, ##__VA_ARGS__)
#define logger_error(format, ...) tlog(TLOG_ERROR, "worker-%d:"format, g_worker_id, ##__VA_ARGS__)
#define logger_debug(format, ...) tlog(TLOG_DEBUG, "worker-%d:"format, g_worker_id, ##__VA_ARGS__)

#define HTTP_DETECT_RES_CODE_ATTACK 403
#define HTTP_DETECT_RES_CODE_OK     200

#define HTTP_DETECT_DIR_REQ 0
#define HTTP_DETECT_DIR_RES 1

#define MAX_MODULE 10

#define DETECT_CONFG_FILE "/etc/modSecurityDetect/config/detect.ini"

//链表头插法
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
}while(0)

//链表删除节点
#define LL_REMOVE(item, list) do } { \
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
}while(0)


typedef struct {
    int worker_num;
    int worker_port_start;
    int listen_backlog;
    int epoll_events;
    int conn_timeout;
} detect_config_t;

extern detect_config_t g_detect_config;

typedef struct {
	u_char	       dir:1;
	uint32_t       src_ip;
	uint32_t       dst_ip;
	uint16_t       src_port;
	uint16_t       dst_port;
	uint32_t       header_len;
	uint32_t       body_len;

	char           data[0];
} io_process_data_t;

typedef struct {
    const char *str;
    int len;
} str_t;

typedef struct header_list_item {
    str_t key;
    str_t value;

    struct header_list_item *prev;
    struct header_list_item *next;
} header_list_item_t;

typedef struct {
    int status;

    const char *method;
    const char *version;
    
    str_t url;
    str_t req_header;
    str_t res_header;
    str_t req_body;
    str_t res_body;

    header_list_item_t *req_headers_list;
    header_list_item_t *res_headers_list;
} http_parser_data_t;

typedef struct {
	uint32_t      status;
}http_detect_res_t;

typedef struct {
    uint32_t       src_ip;
	uint32_t       dst_ip;
	uint16_t       src_port;
	uint16_t       dst_port;
} tcp_conn_info_t;

typedef enum {
    RECV_TYPE_HTTP_INIT = 0,
    RECV_TYPE_HTTP_HEAD_BODY
} RECV_BUFFER_TYPE;

typedef struct {
    RECV_BUFFER_TYPE recv_type;
    int   used;
    int   len;
    char *buf;
} recv_buffer_t;

typedef struct detect_conn_s {
    int fd;
    int now_dir;
    tcp_conn_info_t tcp_conn_info;

    http_parser_data_t *http_parse_data;
    http_detect_res_t  *detect_res;

    void **module_ctx;

    recv_buffer_t *req_recv_buf;
    recv_buffer_t *res_recv_buf;
} detect_conn_t;

#endif

