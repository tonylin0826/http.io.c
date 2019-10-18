//
// Created by Tony Lin on 2019/10/17.
//

#ifndef HTTP_IO_C_LIST_H
#define HTTP_IO_C_LIST_H

#include <stdbool.h>

typedef bool (*same_cb_t)(void *, void *);

typedef struct list_node {
    void *data;
    struct list_node *next;
} list_node_t;

typedef struct list {
    list_node_t *head;
    list_node_t *current;
} list_t;

list_t *new_list();

list_node_t *new_list_node(void *data);

void append_to_list(list_t *list, void *data);

list_node_t *search_in_list(list_t *list, void *data_to_search, same_cb_t is_same);

#endif //HTTP_IO_C_LIST_H
