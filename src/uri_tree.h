//
// Created by Tony Lin on 2019/10/17.
//

#ifndef HTTP_IO_C_URI_TREE_H
#define HTTP_IO_C_URI_TREE_H

#include "list.h"
#include "httpio_types.h"

struct uri_node;

typedef map_t(struct uri_node*) httpio_node_map_t;

typedef struct uri_node {
    char *name;

    httpio_request_handler_t cb;
    list_t middlewares;

    httpio_node_map_t children;
} uri_node_t;

typedef struct uri_tree {
    httpio_node_map_t roots;
} uri_tree_t;

#endif //HTTP_IO_C_URI_TREE_H
