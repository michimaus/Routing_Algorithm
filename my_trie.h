#pragma once
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#ifndef TRIE_H
#define TRIE_H

typedef struct my_trie {
    void *data;
    struct my_trie *next_nodes[2];
} trie_node;

trie_node *new_trie_node() {
    trie_node *node = (trie_node*)malloc(sizeof(trie_node));
    node->data = NULL;
    node->next_nodes[1] = NULL;
    node->next_nodes[0] = NULL;

    return node;
}

void add_value(unsigned int *val, void *content, trie_node *root) {
    unsigned int p = 1, bit;
    trie_node *aux = root;

    while(p <= *val) {
        bit = p & *val;
        if (bit) {
            bit = 1;
        }

        if (aux->next_nodes[bit] == NULL) {
            aux->next_nodes[bit] = new_trie_node();
        }
        aux = aux->next_nodes[bit];
        p = (p << 1);
    }
    aux->data = content;
}

void add_value_route(unsigned int *val, route_tab_elm *rt_elm, trie_node *root) {
    unsigned int p = 1, bit;
    trie_node *aux = root;

    while(p <= *val) {
        bit = p & *val;
        if (bit) {
            bit = 1;
        }

        if (aux->next_nodes[bit] == NULL) {
            aux->next_nodes[bit] = new_trie_node();
        }
        aux = aux->next_nodes[bit];
        p = (p << 1);
    }

    if (aux->data == NULL) {
        aux->data = rt_elm;
    } else {
        route_tab_elm *rt_elm_aux = (route_tab_elm *)aux->data;
        if (rt_elm_aux->mask <= rt_elm->mask) {
            aux->data = rt_elm;
        }
    }
}

void *get_value(unsigned int *val, trie_node *root) {
    unsigned int p = 1, bit;
    trie_node *aux = root;

    while(p <= *val) {
        bit = p & *val;
         if (bit) {
            bit = 1;
        }
        
        if (aux->next_nodes[bit] == NULL) {
            return NULL;
        }
        aux = aux->next_nodes[bit];
        p = (p << 1);
    }
    
    return aux->data;
}

void clear_trie(trie_node* root) {
    if (root->next_nodes[0] != NULL) {
        clear_trie(root->next_nodes[0]);
    }
    if (root->next_nodes[1] != NULL) {
        clear_trie(root->next_nodes[1]);
    }
    free(root);
}

void *get_best_route(unsigned int *val,
trie_node *root, unsigned int *masks, unsigned int *nr_masks) {
    unsigned int mask_check;
    route_tab_elm *aux;
    for (int i = 1; i <= *nr_masks; --i) {
        mask_check = (*val & masks[i]);
        aux = (route_tab_elm *)get_value(&mask_check, root);
        if (aux) {
            return aux;
        }
    }
    return NULL;
}


#endif
