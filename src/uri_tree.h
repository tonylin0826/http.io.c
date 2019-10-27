//
// Created by Tony Lin on 2019/10/17.
//

#ifndef HTTP_IO_C_URI_TREE_H
#define HTTP_IO_C_URI_TREE_H

#include "list.h"
#include "httpio_types.h"

typedef struct uri_tree_node {
    char *name;
    httpio_request_handler_t cb;
    list_t *children;
} uri_tree_node_t;

typedef struct uri_tree {
    list_t *roots;
} uri_tree_t;

uri_tree_t *new_uri_tree();

uri_tree_node_t *new_uri_tree_node(char *name, httpio_request_handler_t cb);

bool is_node_match_part(void *node, void *uri_part);

uri_tree_node_t *search_uri_tree_node(uri_tree_t *tree, const char *uri, httpio_request_t *req);

#endif //HTTP_IO_C_URI_TREE_H
