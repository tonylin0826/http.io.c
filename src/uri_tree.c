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

    if (n->name[0] == ':') {
        return true;
    }

    return strcmp(n->name, u) == 0;
}


bool search_uri_tree_node(uri_tree_t *tree, const char *uri, httpio_request_t *req, list_t *nodes) {
    list_t *current = tree->roots;

    uri_tree_node_t *leaf = NULL;

    int len = (int) strlen(uri);
    char part[256] = {0};
    for (int i = 1, c = 0; i < len && uri[i] != '?'; i++) {
        if (uri[i] == '/') {
            printf("part: [%s]\n", part);

            list_node_t *node = search_in_list(current, part, is_node_match_part);

            if (!node) {
                return false;
            }

            leaf = (uri_tree_node_t *) node->data;
            append_to_list(nodes, leaf);

            map_set(&req->params, leaf->name, strdup(part));

            memset(part, 0, c);
            c = 0;

            current = leaf->children;
        } else {
            part[c++] = uri[i];
        }
    }

    if (strlen(part) > 0) {
//        printf("part: [%s]\n", part);

        list_node_t *node = search_in_list(current, part, is_node_match_part);

        if (!node) {
            return false;
        }

        leaf = (uri_tree_node_t *) node->data;
        append_to_list(nodes, leaf);
    }

    return leaf != NULL;
}
