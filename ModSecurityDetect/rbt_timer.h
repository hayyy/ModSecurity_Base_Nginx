#ifndef RBT_TIMER_H
#define RBT_TIMER_H

#include "rbtree.h"

typedef struct timer_entry_s timer_entry_t;
typedef void (*timer_handler_pt)(void *data);

struct timer_entry_s {
    ngx_rbtree_node_t rbnode;
    timer_handler_pt handler;
    void *data;
};

ngx_rbtree_t * init_timer();
timer_entry_t* add_timer(uint32_t msec, timer_handler_pt func, void *data);
int find_nearest_expire_timer();
void expire_timer();

#endif
