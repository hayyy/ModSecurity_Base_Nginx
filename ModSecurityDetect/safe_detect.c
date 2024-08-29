#include<arpa/inet.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules.h>
#include <iniparser/iniparser.h>
#include "detect_common.h"

#define IP_STR_LEN 20

typedef struct {
    int enable;
    const char *modsecurity_rules_file;
} modesecurity_config_t;

typedef struct {
    Transaction *modsec_transaction;
    char *url;
} modesecurity_ctx_t;

static ModSecurity *s_modsec = NULL;
static void *s_rules_set = NULL;
static modesecurity_config_t s_modesecurity_config;
static int s_modesecurity_module_id;

void http_modsecurity_log(void *log, const void* data)
{
    const char *msg;
    
    msg = (const char *) data;
    logger_info("%s\n", msg);
}

static int safe_detect_load_config(const char *config_file) {

    dictionary *dict = NULL;

    dict = iniparser_load(DETECT_CONFG_FILE);
	if(NULL == dict){
		logger_error("iniparser load ini file failed, please check it...\n");
		return -1;
	}

    s_modesecurity_config.enable = iniparser_getint(dict, "modsecurity:enable", 1);
    s_modesecurity_config.modsecurity_rules_file = iniparser_getstring(dict, "modsecurity:modsecurity_rules_file", NULL);

    if (s_modesecurity_config.modsecurity_rules_file == NULL)
        return -1;
    return 0;
}

static void safe_detect_free(void *module_ctx) {
    modesecurity_ctx_t* ctx = (modesecurity_ctx_t*)module_ctx;

    msc_process_logging(ctx->modsec_transaction);
    msc_transaction_cleanup(ctx->modsec_transaction);

    je_free((char*)ctx->url);
    je_free(ctx);
}

int safe_detect_init(int module_id) {
    const char *error = NULL;
    int res = 0;

    s_modesecurity_module_id = module_id;
    
    s_modsec = msc_init();
    if (s_modsec == NULL) {
        logger_error("failed to create the ModSecurity instance\n");
        return -1;
    }

    msc_set_connector_info(s_modsec, "ModSecurity-nginx v0.0.1-process");
    msc_set_log_cb(s_modsec, http_modsecurity_log);

    s_rules_set = msc_create_rules_set();
    if (s_rules_set == NULL) {
        logger_error("msc_create_rules_set fail\n");
        return -1;
    }

    if (safe_detect_load_config(DETECT_CONFG_FILE)) {
        logger_error("safe_detect_load_config fail\n");
        return -1;
    }

    res = msc_rules_add_file(s_rules_set, s_modesecurity_config.modsecurity_rules_file, &error);
    if (res < 0) {
        logger_error("Failed to load the rules from: '%s' - reason: '%s'\n", 
                                    s_modesecurity_config.modsecurity_rules_file, error);
        return -1;
    }

    g_module_ctx_free_func[s_modesecurity_module_id] = safe_detect_free;
    
    return 0;
}


static int modsecurity_process_intervention (Transaction *transaction)
{
    char *log = NULL;
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    logger_debug("processing intervention");

    if (msc_intervention(transaction, &intervention) == 0) {
        logger_debug("nothing to do");
        return 0;
    }

    log = intervention.log;
    if (intervention.log == NULL) {
        log = "(no log message was specified)";
    }

    logger_debug("%s\n", log);

    if (intervention.log != NULL) {
        free(intervention.log);
    }

    if (intervention.url != NULL)
    {
        logger_debug("intervention -- redirecting to: %s with status code: %d", intervention.url, intervention.status);
        return intervention.status;
    }

    if (intervention.status != 200)
    {
        msc_update_status_code(transaction, intervention.status);
        logger_debug("intervention -- returning code: %d", intervention.status);
        return intervention.status;
    }
    return 0;
}


int safe_detect_res_process(modesecurity_ctx_t *ctx, detect_conn_t       * conn) {
    int ret = 0;
    header_list_item_t *header_list = NULL, *item = NULL;
    str_t http_body = {0};
    http_parser_data_t *http_parse_data = conn->http_parse_data;

    header_list = conn->http_parse_data->res_headers_list;
    http_body = conn->http_parse_data->res_body;

    for(item = header_list; item != NULL; item = item->next) {
        msc_add_n_response_header(ctx->modsec_transaction,
                (const unsigned char *) item->key.str,
                item->key.len,
                (const unsigned char *) item->value.str,
                item->value.len);
    }

    msc_process_response_headers(ctx->modsec_transaction, http_parse_data->status, http_parse_data->version);    
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0) return ret;

    msc_append_response_body(ctx->modsec_transaction, (const unsigned char *)http_body.str, http_body.len);
    msc_process_response_body(ctx->modsec_transaction);
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0) return ret;
    
    return 0;
}

int safe_detect_req_process(modesecurity_ctx_t *ctx, detect_conn_t       * conn) {
    int ret = 0;
    char *ip_str = NULL;
    char src_ip[IP_STR_LEN] = {0};
    char dst_ip[IP_STR_LEN] = {0};
    tcp_conn_info_t *tcp_info = &conn->tcp_conn_info;
    header_list_item_t *header_list = NULL, *item = NULL;
    str_t http_body = {0};
    http_parser_data_t *http_parse_data = conn->http_parse_data;

    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(tcp_info->src_ip);
    ip_str = inet_ntoa(ip_addr);
    if (ip_str == NULL) {
        logger_error("inet_ntoa fail");
        return -1;
    }
    memcpy(src_ip, ip_str, strlen(ip_str));
    
    ip_addr.s_addr = htonl(tcp_info->dst_ip);
    ip_str = inet_ntoa(ip_addr);
    if (ip_str == NULL) {
        logger_error("inet_ntoa fail");
        return -1;
    }
    memcpy(dst_ip, ip_str, strlen(ip_str));

    ret = msc_process_connection(ctx->modsec_transaction, src_ip, tcp_info->src_port, dst_ip, tcp_info->dst_port);
    if (ret != 1) {
        logger_error("Was not able to extract connection information.");
        return -1;
    }
    
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0)
        return ret;

    ctx->url = je_malloc(http_parse_data->url.len+1);
    if (ctx->url == NULL)
        return -1;
    memset(ctx->url, 0, http_parse_data->url.len+1);
    memcpy(ctx->url, http_parse_data->url.str, http_parse_data->url.len);

    ret = msc_process_uri(ctx->modsec_transaction, ctx->url, http_parse_data->method, http_parse_data->version);
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0)
        return ret;
    
    header_list = conn->http_parse_data->req_headers_list;
    http_body = conn->http_parse_data->req_body;

    for(item = header_list; item != NULL; item = item->next) {
        msc_add_n_request_header(ctx->modsec_transaction,
                (const unsigned char *) item->key.str,
               item->key.len,
                (const unsigned char *) item->value.str,
                item->value.len);
    }

    msc_process_request_headers(ctx->modsec_transaction);
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0) return ret;

    msc_append_request_body(ctx->modsec_transaction, (const unsigned char *)http_body.str, http_body.len);
    msc_process_request_body(ctx->modsec_transaction);
    ret = modsecurity_process_intervention(ctx->modsec_transaction);
    if (ret > 0) return ret;

    return 0;
}

int safe_detect_process(detect_conn_t       * conn) {

    modesecurity_ctx_t *ctx = conn->module_ctx[s_modesecurity_module_id];
    if (ctx == NULL) {
        ctx = je_malloc(sizeof(modesecurity_ctx_t));
        if (ctx == NULL) {
            logger_error("je_malloc modesecurity_ctx_t fail");
            return HTTP_DETECT_RES_CODE_OK;
        }
        memset(ctx, 0, sizeof(modesecurity_ctx_t));
        ctx->modsec_transaction = msc_new_transaction(s_modsec, s_rules_set, NULL);
        conn->module_ctx[s_modesecurity_module_id] = ctx;
    }

    if (conn->now_dir == HTTP_DETECT_DIR_REQ) {
        return safe_detect_req_process(ctx, conn);
    } else {
        return safe_detect_res_process(ctx, conn);
    }
}


