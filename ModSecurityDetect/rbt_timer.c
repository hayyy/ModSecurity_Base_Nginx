#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h> 
#include <stddef.h> 
#include <sys/time.h>
#include "rbtree.h"
#include "rbt_timer.h"
#include "detect_common.h"

static ngx_rbtree_t         timer;
static ngx_rbtree_node_t    sentinel;

static uint32_t
current_time() {
	uint32_t t;
    
    struct timeval tv;
	gettimeofday(&tv, NULL);
	t = (uint32_t)tv.tv_sec * 1000;
	t += tv.tv_usec / 1000;
    
	return t;
}

ngx_rbtree_t * init_timer() {
    ngx_rbtree_init(&timer, &sentinel, ngx_rbtree_insert_timer_value);
    return &timer;
}

timer_entry_t* add_timer(uint32_t msec, timer_handler_pt func, void *data) {
    timer_entry_t *te = (timer_entry_t *)je_malloc(sizeof(timer_entry_t));
    memset(te, 0, sizeof(timer_entry_t));
    te->handler = func;
    msec += current_time();
    logger_debug("add_timer expire at msec = %u\n", msec);
    te->rbnode.key = msec;
    te->data = data;
    ngx_rbtree_insert(&timer, &te->rbnode);
    return te;
}

void del_timer(timer_entry_t *te) {
    ngx_rbtree_delete(&timer, &te->rbnode);
    je_free(te);
}

int find_nearest_expire_timer() {
    ngx_rbtree_node_t  *node;
    if (timer.root == &sentinel) {
        return -1;
    }
    node = ngx_rbtree_min(timer.root, timer.sentinel);
    int diff = (int)node->key - (int)current_time();
    return diff > 0 ? diff : 0;
}

void expire_timer() {
    timer_entry_t *te;
    ngx_rbtree_node_t *sentinel, *root, *node;
    sentinel = timer.sentinel;
    uint32_t now = current_time();
    for (;;) {
        root = timer.root;
        if (root == sentinel) break;
        node = ngx_rbtree_min(root, sentinel);
        if (node->key > now) break;
        logger_debug("touch timer expire time=%u, now = %u\n", node->key, now);
        te = (timer_entry_t *) ((char *) node - offsetof(timer_entry_t, rbnode));
        te->handler(te->data);
        ngx_rbtree_delete(&timer, &te->rbnode);
        je_free(te);
    }
}
