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

#ifndef PARSER_H
#define PARSER_H

typedef struct my_parser {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} route_tab_elm;

void readUntilNotDigit(int *fd, char *data) {
    char my_chr;
    int index = 0;
    while (read(*fd, &my_chr, 1)) {
        if (my_chr < '0' || '9' < my_chr) {
            break;
        }
        else {
            data[index] = my_chr;
            ++index;
        }
    }
}

unsigned int getIpAddres(int *fd) {
    int value = 0;
    int take_byte = 0;
    char buf[4];

    for (int i = 0; i < 4; ++i) {
        memset(buf, 0, 4);
        readUntilNotDigit(fd, buf);

        value += (atoi(buf) << take_byte);
        take_byte += 8;
    }

    return value;
}

int getRouteTables(int *fd, route_tab_elm **route_arr) {
    char my_chr;
    int ok = 1;
    int rez = 0;

    while (ok) {
        if (read(*fd, &my_chr, 1)) {
            if (my_chr == '\n') {
                ++rez;
            }
        } else {
            break;
        }
    }

    lseek(*fd, 0, SEEK_SET);
    *route_arr = (route_tab_elm *)malloc(rez * sizeof(route_tab_elm));

    char buf[4];

    for (int i = 0; i < rez; ++i) {
        (*route_arr)[i].prefix = getIpAddres(fd);
        (*route_arr)[i].next_hop = getIpAddres(fd);
        (*route_arr)[i].mask = getIpAddres(fd);

        memset(buf, 0, 4);
        readUntilNotDigit(fd, buf);
        (*route_arr)[i].interface = atoi(buf);
    }

    return rez;
}

#endif
