/**
 * @file listfunc.c
 * @brief This is the file of list functions used in the project.
 * @author Ondrej Lukasek (xlukas15)
 * @date 2023-10
 * @copyright MIT LICENSE
*/

#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>

#include "common.h"

/**
 * @brief Function adds element to the list of elements.
 * @param ip Structure containing the IP address.
 * @param tm Time duration for which the IP address stays in the list.
*/
void addElement(struct in_addr ip, time_t tm) {
    struct occAddr *newNode = malloc(sizeof(struct occAddr));
    newNode->ip = ip;
    newNode->tm = tm;
    newNode->next = head;
    head = newNode;
}

/**
 * @brief Function searches for certain IP address in the list.
 * @param ip Structure containing the IP address.
 * @return Returns NULL if the item is not found. On succes returns the IP address structure.
*/
struct occAddr* findElement(struct in_addr ip) {
    struct occAddr *current = head;
    while (current) {
        if (current->ip.s_addr == ip.s_addr) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/**
 * @brief Function updates the IP address duration.
 * @param ip Structure containing the IP address.
 * @param tm New time duration for which the IP address stays in the list.
 * @return Returns 1 on successful update and 0 after failed attempt to find the element in the list. 
*/
int updateElement(struct in_addr ip, time_t tm) {
    struct occAddr *node = findElement(ip);
    if (node) {
        node->tm = tm;
        return 1;  // Success
    }
    return 0;  // Not found
}

/**
 * @brief Function removes an IP address from the list.
 * @param ip Structure containing the IP address.
 * @return Returns 1 on successful element removal and 0 after failed attempt to find the element in the list.
*/
int removeElement(struct in_addr ip) {
    struct occAddr *current = head;
    struct occAddr *prev = NULL;
    
    while (current) {
        if (current->ip.s_addr == ip.s_addr) {
            if (prev) {
                prev->next = current->next;
            }
            else {
                head = current->next;
            }
            free(current);
            return 1;  // Success
        }
        prev = current;
        current = current->next;
    }
    return 0;  // Not found
}

/**
 * @brief Clears the whole list of IP addresses.
*/
void clearElements() {
    struct occAddr *current = head;
    while (current) {
        struct occAddr *temp = current;
        current = current->next;
        free(temp);
    }
    head = NULL;
}

/**
 * @brief Counts the number of elements (IP addresses) in the list.
 * @return Returns the number of elements in the list.
*/
size_t countElements() {
    size_t count = 0;
    struct occAddr *current = head;
    while (current) {
        count++;
        current = current->next;
    }
    return count;
}