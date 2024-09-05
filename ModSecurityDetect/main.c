#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <iniparser/iniparser.h>
#include "detect_common.h"
#include "rbt_timer.h"

#define DETECT_LOG_FILE   "/var/log/modSecurityDetect/detect.log"
#define MAX_NUM_CHILDREN 10

int g_worker_id = 0;
int g_module_num = 0;
void (**g_module_ctx_free_func)(void*);
detect_config_t g_detect_config;

extern int g_epoll_fd;
extern int g_server_fd;
extern struct epoll_event *g_event_array;
extern int safe_detect_init(int);
extern int io_process_init(int worker_id, detect_config_t *config);
void epoll_event_handle(detect_config_t *config, uint32_t timer);
extern int io_process_init(int worker_id, detect_config_t *config);
extern int safe_detect_init(int module_id);
extern void epoll_event_handle(detect_config_t *config, uint32_t timer);

static int module_init(int worker_id, detect_config_t *config) {
    g_module_ctx_free_func = je_malloc(g_module_num*sizeof(void*));
    if (g_module_ctx_free_func == NULL) {
        logger_error("je_malloc g_module_ctx_free_func fail");
        return -1;
    }
    
    if (io_process_init(worker_id, config) < 0) {
        logger_error("io_process_init fail");
        return -1;
    }

    if (safe_detect_init(g_module_num++) < 0) {
        logger_error("safe_detect_init fail");
        return -1;
    }

    return 0;
}

static int detect_worker_loop(int worker_id) {
    int nearest = 0;

    if (module_init(worker_id, &g_detect_config)) {
        return -1;
    }

    init_timer();
    
    while (1) {
        nearest = find_nearest_expire_timer();
        epoll_event_handle(&g_detect_config, nearest);
        expire_timer();
    }

    return 0;
}

static void fork_worker(int i, pid_t *pids) {
    int ret = 0;
    pid_t pid = fork();
    if (pid < 0) {
        tlog(TLOG_ERROR, "worker-%d fork failed\n", i);
        return ;
    } else if (pid == 0) {
        logger_info("worker child %d with PID %d started.\n", i, getpid());
        ret = detect_worker_loop(i);
        exit(ret);
    } else {
        // 父进程保存子进程 PID
        pids[i] = pid;
    }
}

static int load_config(const char *config_file) {

    dictionary *dict = NULL;

    dict = iniparser_load(DETECT_CONFG_FILE);
	if(NULL == dict){
		tlog(TLOG_ERROR, "iniparser load ini file failed, please check it...\n");
		return -1;
	}

    g_detect_config.worker_num = iniparser_getint(dict, "worker:num", 2);
    g_detect_config.worker_port_start = iniparser_getint(dict, "worker:port_start", 10000);
    g_detect_config.listen_backlog = iniparser_getint(dict, "worker:listen_backlog", 512);
    g_detect_config.epoll_events = iniparser_getint(dict, "worker:epoll_events", 512);
    g_detect_config.conn_timeout = iniparser_getint(dict, "worker:conn_timeout", 10000);
    
    return 0;
}

static int logger_init() {
    int ret = 0;
    
    ret = tlog_init(DETECT_LOG_FILE, 1024 * 1024 * 10, 8, 0, TLOG_MULTI_WRITE|TLOG_SUPPORT_FORK);
    if (ret < 0) {
        fprintf(stderr, "tlog_init fail.\n");
        return -1;
    }

    tlog_setlevel(TLOG_INFO);

    return 0;
}


int main() {

    int i = 0;
    pid_t pids[MAX_NUM_CHILDREN] = {0};

    if (logger_init() < 0) {
        fprintf(stderr, "logger_init fail.\n");
        return -1;
    }
    
    if (load_config(DETECT_CONFG_FILE) < 0) {
        tlog(TLOG_ERROR, "load_config fail.\n");
        return -1;
    }

    // 创建并启动多个子进程
    for (i = 0; i < g_detect_config.worker_num; i++) {
        g_worker_id = i;
        fork_worker(i, pids);
    }

    // 监控子进程
    int status;
    pid_t child_pid;
    while (1) {
        child_pid = waitpid(-1, &status, 0); // 等待任意子进程
        if (child_pid > 0) {
            for (i = 0; i < g_detect_config.worker_num; i++) {
                if (child_pid == pids[i]) {
                    if (WIFEXITED(status)) {
                        tlog(TLOG_ERROR, "Worker %d with PID %d exited with status %d. Restarting...\n", i, child_pid, WEXITSTATUS(status));
                    } else if (WIFSIGNALED(status)) {
                        //子进程coredump走该逻辑
                        tlog(TLOG_ERROR, "Worker %d with PID %d was killed by signal %d. Restarting...\n", i, child_pid, WTERMSIG(status));
                    }
                    fork_worker(i, pids); // 重新启动子进程
                    break;
                }
            }
        } else {
            tlog(TLOG_ERROR, "waitpid failed");
            return -1;
        }
        sleep(1);
    }

    return 0;
}
