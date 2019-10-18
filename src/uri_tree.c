//
// Created by Tony Lin on 2019/10/17.
//

#include "uri_tree.h"

#include <stdlib.h>

uri_tree_t *new_uri_tree() {
    uri_tree_t *t = calloc(1, sizeof(uri_tree_t));
    t->roots = new_list();
}

uri_tree_node_t *new_uri_tree_node(char *name, httpio_request_handler_t cb) {
    uri_tree_node_t *n = calloc(1, sizeof(uri_tree_node_t));

    n->cb = cb;
    n->children = new_list();
    n->name = name;
}


bool is_node_match_part(void *node, void *uri_part) {
    uri_tree_node_t *n = (uri_tree_node_t *) node;
    char *u = (char *) uri_part;

    return strcmp(n->name, u) == 0;
}

uri_tree_node_t *search_uri_tree_node(uri_tree_t *tree, const char *uri) {
    list_t *current = tree->roots;

    uri_tree_node_t *leaf = NULL;

    int len = (int) strlen(uri);
    char part[256] = {0};
    for (int i = 0, c = 0; i < len && uri[i] != '?'; i++) {
        if (uri[i] == '/') {
            printf("part: [%s]\n", part);

            list_node_t *node = search_in_list(current, part, is_node_match_part);

            if (!node) {
                return NULL;
            }

            leaf = (uri_tree_node_t *) node->data;

            memset(part, 0, c);
            c = 0;
        } else {
            part[c++] = uri[i];
        }
    }

    if (strlen(part) > 0) {
        printf("part: [%s]\n", part);

        list_node_t *node = search_in_list(current, part, is_node_match_part);

        if (!node) {
            return NULL;
        }

        leaf = (uri_tree_node_t *) node->data;
    }

    if (!leaf) {
        return NULL;
    }

    return leaf;
}
