#include <sys/epoll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <jemalloc/jemalloc.h>
#include <errno.h>
#include "detect_common.h"
#include "uthash/uthash.h"
#include "rbt_timer.h"

typedef enum {
    IO_READ_DATA_PROCESS_COMPLETE,
    IO_READ_DATA_PROCESS_UNCOMPLETE,
    IO_READ_DATA_PROCESS_ERROR,
    IO_READ_DATA_PROCESS_GET_FIN,
    IO_READ_DATA_PROCESS_ATTACK,
}IO_READ_DATA_PROCESS_RES;

typedef struct {
    int len;
    int used;
    io_process_data_t *origin;
    io_process_data_t *io_data;
}io_buffer_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} ip_port_info;

typedef struct {
    ip_port_info key;
    detect_conn_t conn;
    
    UT_hash_handle hh;
} hash_element_t;

typedef struct {
    int fd;
    recv_buffer_t *recv_buf;
} epoll_ptr_data_t;

int g_server_fd = 0;
int g_epoll_fd = 0;
struct epoll_event *g_event_array = NULL;
hash_element_t *g_detect_conn_hash = NULL;

static detect_conn_t* get_detect_conn(io_process_data_t *io_data);
static int send_http_detect_res(int fd, detect_conn_t * conn);
static void http_detect_handle(detect_conn_t *conn);
static void free_detect_conn(io_process_data_t *io_data);
static void free_http_parse_data(http_parser_data_t *http_data);

extern int detect_http_parse(detect_conn_t       * conn);
extern int safe_detect_process(detect_conn_t       * conn);


// 设置文件描述符为非阻塞模式
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_socket(int fd, recv_buffer_t *buffer) {
    logger_debug("close connection\n");

    io_process_data_t *io_data = NULL;
    
    close(fd);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    if (buffer->used == buffer->len) {
        io_data = (io_process_data_t *)(buffer->buf);      
        free_detect_conn(io_data);
    }

    je_free(buffer->buf);
    je_free(buffer);
}

int io_read_data_detail(int fd, recv_buffer_t *recv_buffer) {
    io_process_data_t *io_data = NULL;
    int n = 0, free = 0;
    size_t je_malloc_size = 0;
    int err = 0;
    detect_conn_t *conn = NULL;
    recv_buffer_t tmp_buf = {0};

    if (recv_buffer->recv_type == RECV_TYPE_HTTP_INIT && recv_buffer->len == recv_buffer->used) {
        conn = get_detect_conn((io_process_data_t *)(recv_buffer->buf));
        if (conn == NULL) {
            logger_error("get_detect_conn fail\n");
            return IO_READ_DATA_PROCESS_ERROR;
        }
        if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
            recv_buffer = conn->req_recv_buf;
        } else {
            recv_buffer = conn->res_recv_buf;
        }
    }

    while(1) {        
        free = recv_buffer->len - recv_buffer->used;
        n = recv(fd, recv_buffer->buf+recv_buffer->used, free, 0);
        err = errno;
        if (n == 0) {
            return IO_READ_DATA_PROCESS_GET_FIN;
        } else if (n > 0) {
            recv_buffer->used += n;
            if (recv_buffer->recv_type == RECV_TYPE_HTTP_INIT && recv_buffer->used == recv_buffer->len) {
                io_data = (io_process_data_t *)(recv_buffer->buf);

                io_data->src_ip = ntohl(io_data->src_ip);
                io_data->dst_ip = ntohl(io_data->dst_ip);
                io_data->src_port = ntohs(io_data->src_port);
                io_data->dst_port = ntohs(io_data->dst_port);
                io_data->header_len = ntohl(io_data->header_len);
                io_data->body_len = ntohl(io_data->body_len);
                
                conn = get_detect_conn(io_data);
                if (conn == NULL) {
                    logger_error("get_detect_conn fail\n");
                    return IO_READ_DATA_PROCESS_ERROR;
                }
                
                je_malloc_size = sizeof(io_process_data_t) + io_data->header_len + io_data->body_len;
                tmp_buf.buf = je_malloc(je_malloc_size);
                if (tmp_buf.buf == NULL) {
                    logger_error("je_malloc recv_buffer_t->buf fail\n");
                    return IO_READ_DATA_PROCESS_ERROR;
                }
                memset(tmp_buf.buf, 0, je_malloc_size);
                memcpy(tmp_buf.buf, recv_buffer->buf, recv_buffer->len);
                tmp_buf.len = je_malloc_size;
                tmp_buf.used = recv_buffer->used;
                tmp_buf.recv_type = RECV_TYPE_HTTP_HEAD_BODY;

                if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
                    *(conn->req_recv_buf) = tmp_buf;
                    recv_buffer = conn->req_recv_buf;
                } else {
                    *(conn->res_recv_buf) = tmp_buf;
                    recv_buffer = conn->res_recv_buf;
                }
            } 
            else if (recv_buffer->recv_type == RECV_TYPE_HTTP_HEAD_BODY &&
                                        recv_buffer->used == recv_buffer->len) {
                io_data = (io_process_data_t *)recv_buffer->buf;
                logger_debug("http: %.*s\n", io_data->header_len+io_data->body_len, io_data->data);
                http_detect_handle(conn);
                #if 0
                if (conn->now_dir == 1) {
                    conn->detect_res->status = htonl(HTTP_DETECT_RES_CODE_ATTACK);
                }
                #endif
                if (send_http_detect_res(fd, conn)) {
                    return IO_READ_DATA_PROCESS_ERROR;
                }
                if (conn->detect_res->status == htonl(HTTP_DETECT_RES_CODE_ATTACK)) {
                    return IO_READ_DATA_PROCESS_ATTACK;
                }
                return IO_READ_DATA_PROCESS_COMPLETE;
            }
        } else {
            if (err == EINTR)
                continue;
            if (err == EAGAIN)
                break;
            logger_error("read errno:%s\n", strerror(err));
            return IO_READ_DATA_PROCESS_ERROR;
        }
    }

    return IO_READ_DATA_PROCESS_UNCOMPLETE;
}


static void io_read_data_handle(int fd, recv_buffer_t *recv_buf) {

    int ret = 0;
    io_process_data_t *io_data = NULL;

    ret = io_read_data_detail(fd, recv_buf);
    if (ret == IO_READ_DATA_PROCESS_ERROR || ret == IO_READ_DATA_PROCESS_GET_FIN) {
        close_socket(fd, recv_buf);
        if (ret == IO_READ_DATA_PROCESS_GET_FIN)
            logger_error("fin\n");
        else 
            logger_error("error\n");
    } else if (ret == IO_READ_DATA_PROCESS_COMPLETE) {
        io_data = (io_process_data_t *)(recv_buf->buf);
        recv_buf->used = 0;
        if (io_data->dir == HTTP_DETECT_DIR_RES) {
            free_detect_conn(io_data);
        }
    } else if (ret == IO_READ_DATA_PROCESS_ATTACK) {
        recv_buf->used = 0;
        free_detect_conn((io_process_data_t *)(recv_buf->buf));
        logger_error("attack\n");
    }
}


static int alloc_recv_buffer(recv_buffer_t **recv_buf, size_t mem_size) {
    recv_buffer_t *buffer = NULL;

    *recv_buf = je_malloc(sizeof(recv_buffer_t));
    if (*recv_buf == NULL) {
        logger_error("je_malloc recv_buffer_t fail\n");
        return -1;
    }

    memset(*recv_buf, 0, sizeof(recv_buffer_t));

    buffer = *recv_buf;

    buffer->buf = je_malloc(mem_size);
    if (buffer->buf == NULL) {
        je_free(buffer);
        *recv_buf = NULL;
        logger_error("je_malloc recv_buffer_t->buf fail\n");
        return -1;
    }

    memset(buffer->buf, 0, mem_size);
    buffer->len = mem_size;
    buffer->used = 0;

    return 0;
}

static void accept_handle(int server_fd) {
    // 处理新连接
    struct epoll_event ev = {0};
    int conn_fd = 0;
    recv_buffer_t *recv_buf = NULL;
    struct sockaddr_in address = {0};
    int addrlen = sizeof(address);
    epoll_ptr_data_t *ptr = NULL;

    logger_debug("accept new connection\n");
    
    conn_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (conn_fd == -1) {
        logger_error("accept fail:%s\n", strerror(errno));
        return ;
    }
    set_nonblocking(conn_fd);
    
    ev.events = EPOLLIN | EPOLLET;
    if (alloc_recv_buffer(&recv_buf, sizeof(io_process_data_t))) {
        goto accept_handle_fail;
    }
    recv_buf->recv_type = RECV_TYPE_HTTP_INIT;

    ptr = je_malloc(sizeof(epoll_ptr_data_t));
    if (ptr == NULL) {
        logger_error("je_malloc epoll_ptr_data_t fail\n");
        goto accept_handle_fail;
    }

    ptr->fd = conn_fd;
    ptr->recv_buf = recv_buf;
    
    ev.data.ptr = ptr;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) == -1) {
        logger_error("epoll_ctl conn_fd fail:%s\n", strerror(errno));
        goto accept_handle_fail;
    }

    return;

accept_handle_fail:
    close(conn_fd);
    if (recv_buf) {
        je_free(recv_buf->buf);
        je_free(recv_buf);
    }
    if (ptr) {
        je_free(ptr);
    }
}

int io_process_init(int worker_id, detect_config_t *config) {
    
    struct epoll_event ev = {0};
    size_t je_malloc_size = 0;
    struct sockaddr_in address = {0};


    // 创建socket文件描述符
    if ((g_server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        logger_error("socket failed:%s\n", strerror(errno));
        return -1;
    }

    // 绑定端口和地址
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((short int)(config->worker_port_start + worker_id));

    if (bind(g_server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        logger_error("bind failed:%s\n", strerror(errno));
        return -1;
    }

    // 监听连接
    if (listen(g_server_fd, config->listen_backlog) < 0) {
        logger_error("listen fail:%s\n", strerror(errno));
        return -1;
    }

    // 创建epoll实例
    g_epoll_fd = epoll_create(100);
    if (g_epoll_fd == -1) {
        logger_error("epoll_creat fail:%s\n", strerror(errno));
        return -1;
    }

    // 将server_fd添加到epoll实例中
    ev.events = EPOLLIN;
    ev.data.fd = g_server_fd;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_fd, &ev) == -1) {
        logger_error("epoll_ctl server_fd fail:%s\n", strerror(errno));
        return -1;
    }

    je_malloc_size = config->epoll_events * sizeof(struct epoll_event);
    g_event_array = je_malloc(je_malloc_size);
    if (g_event_array == NULL) {
        logger_error("je_malloc epoll_event array fail\n");
        return -1;
    }
    memset(g_event_array, 0, je_malloc_size);

    return 0;
}

void epoll_event_handle(detect_config_t *config, uint32_t timer) {
    int num = 0, revents = 0, i = 0;
    epoll_ptr_data_t *ptr;

    logger_debug("epoll_event_handle\n");
    num = epoll_wait(g_epoll_fd, g_event_array, config->epoll_events, timer);
    if (num == -1) {
        logger_error("epoll_wait fail:%s\n", strerror(errno));
        return ;
    }

    for (i = 0; i < num; i++) {
        revents = g_event_array[i].events;
        ptr = g_event_array[i].data.ptr;

        logger_debug("events:%d\n", revents);
            
        if (g_event_array[i].data.fd == g_server_fd) {
            accept_handle(g_server_fd);
        } else if (revents & (EPOLLERR|EPOLLHUP)) {
            close_socket(ptr->fd, ptr->recv_buf);
        } else if(revents & EPOLLIN) {
            io_read_data_handle(ptr->fd, ptr->recv_buf);
        }
   }
}

static void free_detect_conn_detail(detect_conn_t *conn) {
    int i = 0;

    if (conn->module_ctx) {
        for(i = 0; i < g_module_num; i++) {
            if (conn->module_ctx[i]) {
                g_module_ctx_free_func[i](conn->module_ctx[i]);
            }
        }
        je_free(conn->module_ctx);
    }
        
    if (conn->req_recv_buf) {
        je_free(conn->req_recv_buf->buf);
        je_free(conn->req_recv_buf);
    }
    if (conn->res_recv_buf) {
        je_free(conn->res_recv_buf->buf);
        je_free(conn->res_recv_buf);
    }
    if (conn->detect_res) {
        je_free(conn->detect_res);
    }
    
    free_http_parse_data(conn->http_parse_data);
    je_free(conn->http_parse_data);
}

void timer_conn_handle(void *data) {
    detect_conn_t *conn = (detect_conn_t *)data;

    hash_element_t *element = NULL;
    ip_port_info key = {0};

    key.dst_ip = conn->tcp_conn_info.dst_ip;
    key.src_ip = conn->tcp_conn_info.src_ip;
    key.dst_port = conn->tcp_conn_info.dst_port;
    key.src_port = conn->tcp_conn_info.src_port;

    HASH_FIND(hh, g_detect_conn_hash, &key, sizeof(ip_port_info), element);
    if (!element) {
        return ;
    }

    logger_debug("free detect conn\n");
    
    free_detect_conn_detail(conn);
    
    HASH_DEL(g_detect_conn_hash, element);
    
    je_free(element);
}


static detect_conn_t* get_detect_conn(io_process_data_t *io_data) {
    hash_element_t *element = NULL;
    ip_port_info key = {0};
    detect_conn_t *conn = NULL;
    timer_entry_t* timer_entry = NULL;

    key.dst_ip = io_data->dst_ip;
    key.src_ip = io_data->src_ip;
    key.dst_port = io_data->dst_port;
    key.src_port = io_data->src_port;

    HASH_FIND(hh, g_detect_conn_hash, &key, sizeof(ip_port_info), element);
    if (element) {
        element->conn.now_dir = io_data->dir;
        return &element->conn;
    }

    logger_debug("new detect conn\n");

    //响应方向数据来了，却获取不到连接，报错
    if (io_data->dir == HTTP_DETECT_DIR_RES) {
        logger_error("only get http res data\n");
        return NULL;
    }
    
    element = je_malloc(sizeof(hash_element_t));
    if (element == NULL) {
        logger_error("je_malloc hash_element_t array fail\n");
        return NULL;
    }
    memset(element, 0, sizeof(hash_element_t));
    element->key = key;
    conn = &element->conn;
    conn->now_dir = io_data->dir;

    conn->tcp_conn_info.dst_ip = io_data->dst_ip;
    conn->tcp_conn_info.src_ip = io_data->src_ip;
    conn->tcp_conn_info.dst_port = io_data->dst_port;
    conn->tcp_conn_info.src_port = io_data->src_port;
    
    if (alloc_recv_buffer(&conn->req_recv_buf, sizeof(io_process_data_t))) {
        goto get_detect_conn_fail;
    }

    if (alloc_recv_buffer(&conn->res_recv_buf, sizeof(io_process_data_t))) {
        goto get_detect_conn_fail;
    }

    conn->http_parse_data = je_malloc(sizeof(http_parser_data_t));
    if (conn->http_parse_data == NULL) {
        logger_error("je_malloc req http_parser_data_t fail\n");
        goto get_detect_conn_fail;
    }
    memset(conn->http_parse_data, 0, sizeof(http_parser_data_t));

    conn->detect_res = je_malloc(sizeof(http_detect_res_t));
    if (conn->detect_res == NULL) {
        logger_error("je_malloc http_detect_res_t fail\n");
        goto get_detect_conn_fail;
    }
    memset(conn->detect_res, 0, sizeof(http_detect_res_t));
    conn->detect_res->status = htonl(HTTP_DETECT_RES_CODE_OK);

    conn->module_ctx = je_malloc(g_module_num * sizeof(void*));
    if (conn->module_ctx == NULL) {
        logger_error("je_malloc module_ctx fail\n");
        goto get_detect_conn_fail;
    }
    memset(conn->module_ctx, 0, g_module_num * sizeof(void*));

    HASH_ADD(hh, g_detect_conn_hash, key, sizeof(ip_port_info), element);
    timer_entry = add_timer(g_detect_config.conn_timeout, timer_conn_handle, conn);
    conn->timer_entry = timer_entry;

    return conn;

get_detect_conn_fail:

    free_detect_conn_detail(conn);
    je_free(element);
    
    return NULL;        
}

static void free_http_parse_data(http_parser_data_t *http_data) {
    header_list_item_t *item = NULL;
    header_list_item_t *old = NULL;

    for(item = http_data->req_headers_list; item;) {
        old = item;
        item = item->next;
        je_free(old);
    }

    for(item = http_data->res_headers_list; item;) {
        old = item;
        item = item->next;
        je_free(old);
    }
}

static void free_detect_conn(io_process_data_t *io_data) {
    hash_element_t *element = NULL;
    detect_conn_t *conn = NULL;
    ip_port_info key = {0};

    key.dst_ip = io_data->dst_ip;
    key.src_ip = io_data->src_ip;
    key.dst_port = io_data->dst_port;
    key.src_port = io_data->src_port;

    HASH_FIND(hh, g_detect_conn_hash, &key, sizeof(ip_port_info), element);
    if (!element) {
        return ;
    }

    logger_debug("free detect conn\n");
    
    conn = &element->conn;
    free_detect_conn_detail(conn);

    //删除哈希表中的连接
    HASH_DEL(g_detect_conn_hash, element);

    //删除定时器中的连接
    del_timer(conn->timer_entry);
    
    je_free(element);
}

static int send_http_detect_res(int fd, detect_conn_t * conn) {
    //http_detect_res_t很小，直接send，不通过epoll
    int n = send(fd, conn->detect_res, sizeof(http_detect_res_t), 0);
    
    if (n != sizeof(http_detect_res_t)) {
        logger_error("send http_detect_res_t fail\n");
        return -1;
    }
    
    return 0;
}

static void http_detect_handle(detect_conn_t *conn) {
    int safe_detect_res = HTTP_DETECT_RES_CODE_OK;
    
    if (detect_http_parse(conn) < 0) {
        logger_error("detect_http_parse fail\n");
        return ;
    }
    safe_detect_res = safe_detect_process(conn);
    if (safe_detect_res > 0)
        conn->detect_res->status = htonl(safe_detect_res);
}

