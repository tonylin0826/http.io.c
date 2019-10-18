//
// Created by Tony Lin on 2019/10/17.
//

#include "list.h"
#include <stdlib.h>
#include <stdio.h>

list_t *new_list() {
    list_t *t = calloc(1, sizeof(list_t));

    t->current = NULL;
    t->head = NULL;

    return t;
}

list_node_t *new_list_node(void *data) {
    list_node_t *t = calloc(1, sizeof(list_node_t));
    t->data = data;
    t->next = NULL;
}

void append_to_list(list_t *list, void *data) {
    if (list->head == NULL) {
        list->head = new_list_node(data);
        list->current = list->head;
    } else {
        list->current->next = new_list_node(data);
        list->current = list->current->next;
    }
}

list_node_t *search_in_list(list_t *list, void *data_to_search, same_cb_t is_same) {
    list_node_t *c = list->head;

    while (c) {
        if (is_same(c->data, data_to_search)) {
            return c;
        }
        c = c->next;
    }

    return NULL;
}