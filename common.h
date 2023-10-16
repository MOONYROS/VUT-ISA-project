#ifndef _COMMON_H
#define _COMMON_H

// Occupied IP address structure
struct occAddr {
    struct in_addr ip;
    time_t tm;
    struct occAddr *next;
};

extern struct occAddr *head;

#endif
