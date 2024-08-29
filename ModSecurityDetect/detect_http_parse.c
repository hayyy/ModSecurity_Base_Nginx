#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <http_parser.h>
#include "detect_common.h"



static http_parser s_http_parser;

static int on_message_begin(http_parser* parser) {
    logger_debug("***MESSAGE BEGIN***\n");
    return 0;
}

static int on_headers_complete(http_parser* parser) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;

    http_data->method = http_method_str(parser->method);
    logger_debug("method: %s\n", http_data->method);

    if (parser->http_major == 1 && parser->http_minor == 1)
        http_data->version = "1.1";
    else if (parser->http_major == 1 && parser->http_minor == 0)
        http_data->version = "1.0";
    else if (parser->http_major == 0 && parser->http_minor == 9)
        http_data->version = "0.9";
    else if (parser->http_major == 2 && parser->http_minor == 0)
        http_data->version = "2.0";
    else {
        logger_error("parser http version fail\n");
        return -1;
    }
    
    logger_debug("version: %s\n", http_data->version);
    
    logger_debug("***HEADERS COMPLETE***\n");
    return 0;
}

static int on_message_complete(http_parser* parser) {
    logger_debug("***MESSAGE COMPLETE***\n");
    return 0;
}

static int on_url(http_parser* parser, const char* at, size_t length) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;
    http_data->url.str = at;
    http_data->url.len = length;

    logger_debug("url: %.*s\n", (int)length, at);
    return 0;
}

static int on_header_field(http_parser* parser, const char* at, size_t length) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;

    header_list_item_t *item = je_malloc(sizeof(header_list_item_t));
    if (item == NULL) {
        logger_error("je_malloc head_list_item fail\n");
        return 0;
    }
    memset(item, 0, sizeof(header_list_item_t));

    item->key.str = at;
    item->key.len = length;

    if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
        LL_ADD(item, http_data->req_headers_list);
    } else {
        LL_ADD(item, http_data->res_headers_list);
    }

    logger_debug("Header field: %.*s\n", (int)length, at);
    return 0;
}

static int on_header_value(http_parser* parser, const char* at, size_t length) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;
    header_list_item_t *item = NULL;

    if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
        item = http_data->req_headers_list;
    } else {
        item = http_data->res_headers_list;
    }
    
    if (item == NULL) {
        logger_error("http head_list is empty\n");
        return 0;
    }

    item->value.str = at;
    item->value.len = length;
    
    logger_debug("Header value: %.*s\n", (int)length, at);
    return 0;
}

static int on_status(http_parser* parser, const char* at, size_t length) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;
    int status = 0, i = 0;

    for(i = 0; i < length; i++) {
        status = status * 10 + at[i] - '0';
    }
    http_data->status = status;

    logger_debug("Header value: %.*s\n", (int)length, at);
    return 0;
}


static int on_body(http_parser* parser, const char* at, size_t length) {
    detect_conn_t *conn = (detect_conn_t *)(parser->data);
    http_parser_data_t *http_data = conn->http_parse_data;
    
    if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
        http_data->req_body.str = at;
        http_data->req_body.len = length;
    } else {
        http_data->res_body.str = at;
        http_data->res_body.len = length;
    }

    logger_debug("Body: %.*s\n", (int)length, at);
    return 0;
}

static http_parser_settings http_parse_callback = {
     .on_message_begin = on_message_begin,
     .on_header_field = on_header_field,
     .on_header_value = on_header_value,
     .on_url = on_url,
     .on_status = on_status,
     .on_body = on_body,
     .on_headers_complete = on_headers_complete,
     .on_message_complete = on_message_complete
};

int detect_http_parse(detect_conn_t       * conn)
{
    const char *data = NULL;
    size_t len = 0, nparsed = 0;
    io_process_data_t *io_buf = NULL;

    s_http_parser.data = conn;    
    if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
        http_parser_init(&s_http_parser, HTTP_REQUEST);
        io_buf = conn->req_recv_buf->buf;
    } else if (conn->now_dir == HTTP_DETECT_DIR_RES) {
        http_parser_init(&s_http_parser, HTTP_RESPONSE);
        io_buf = conn->res_recv_buf->buf;
    }

    data = io_buf->data;
    len = io_buf->header_len + io_buf->body_len;
    
    nparsed = http_parser_execute(&s_http_parser, &http_parse_callback, data, len);

    if (nparsed != len) {
        logger_error("Error: %s (%s)\n",
                http_errno_description(HTTP_PARSER_ERRNO(&s_http_parser)),
                http_errno_name(HTTP_PARSER_ERRNO(&s_http_parser)));
        return -1;
  }

  return 0;
}
