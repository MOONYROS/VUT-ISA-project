/**
 * @file main.c
 * @brief This is the main file of the project, it contains the main loop fo the project.
 * @author Ondrej Lukasek (xlukas15)
 * @date 2023-10
 * @copyright MIT LICENSE
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <syslog.h>
#include <ncurses.h>

#include "common.h"
#include "listfunc.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

// DHCP option for lease time
#define DHCP_OPTION_HOST_NAME 12
#define DHCP_OPTION_REQUESTED_IP 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SERVER_ID 54
#define DHCP_OPTION_PARAM_LIST 55
#define DHCP_OPTION_MAX_MSG_SIZE 57

#define BOOTREQUEST 1
#define BOOTREPLY 2

/**
 * @struct dhcp_packet
 * @brief Structure of a DHCP packet.
*/
struct dhcp_packet {
    u_int8_t op;            /**< Message type: Boot Request (1) or Boot Reply (2) */
    u_int8_t htype;         /**< Hardware address type: Ethernet is 1 */
    u_int8_t hlen;          /**< Hardware address length: Ethernet is 6 */
    u_int8_t hops;          /**< Hops */
    u_int32_t xid;          /**< Transaction ID */
    u_int16_t secs;         /**< Seconds since DHCP process started */
    u_int16_t flags;        /**< Flags */
    struct in_addr ciaddr;  /**< Client IP address if client has a current IP address */
    struct in_addr yiaddr;  /**< 'Your' (client) IP address */
    struct in_addr siaddr;  /**< IP address of next server to use in bootstrap */
    struct in_addr giaddr;  /**< Gateway IP address, if present */
    u_int8_t chaddr[16];    /**< Client hardware address */
    char sname[64];         /**< Optional server host name, null terminated string */
    char file[128];         /**< Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER. */
    u_int8_t options[312];  /**< Optional parameters field. See RFC 2132. */
}; 

/**
 * @struct IP_Prefix
 * @brief Structure of an IP address with its prefix and number of connected devices.
*/
typedef struct {
    struct in_addr ip;      /**< IP address. */
    int prefix;             /**< Prefix of an IP address. */
    int dev_count;          /**< Number of devices connected to an IP address. */
} IP_Prefix;

/**
 * @struct IP_prefixes
 * @brief Structure with an array of IP prefixes and their amount.
*/
typedef struct {
    IP_Prefix *prefixes;    /**< Array of prefixes. */
    int count;              /**< Count of IP prefixes. */
} IP_Prefixes;

struct occAddr *head = NULL;

IP_Prefixes ip_prefixes;

/**
 * @brief Function parses the IP prefix and checks its format.
 * @return 1 on successful parse and 0 on invalid IP prefix format.
*/
int parse_ip_prefix(const char *str, IP_Prefix *prefix) {
    char ip_str[INET_ADDRSTRLEN];
    char *slash = strchr(str, '/');
    if (!slash) return 0;  // Rozsah nema validni format

    // Ziskani IP adresy z rozsahu
    strncpy(ip_str, str, slash - str);
    ip_str[slash - str] = '\0';
    if (inet_pton(AF_INET, ip_str, &prefix->ip) <= 0) return 0;  // Chyba pri konverzi IP adresy

    // Ziskani prefixu
    prefix->prefix = atoi(slash + 1);
    if (prefix->prefix <= 0 || prefix->prefix > 32) return 0;  // Neplatna delka prefixu

    prefix->dev_count = 0;

    return 1;
}

/**
 * @brief Function prints out the information about the IP prefix. How many devices is connected with this prefix and how full the prefix is.
 * @param ip_prefixes Array of IP prefixes.
*/
void print_ip_ranges(const IP_Prefixes *ip_prefixes) {
    char ip_str[INET_ADDRSTRLEN];  // Prostor pro uložení řetězcové reprezentace IP adresy

    for (int i = 0; i < ip_prefixes->count; i++) {
        if (inet_ntop(AF_INET, &ip_prefixes->prefixes[i].ip, ip_str, INET_ADDRSTRLEN)) {
            int max_devs = (1 << (32 - ip_prefixes->prefixes[i].prefix)) - 2;
            int dev_count = ip_prefixes->prefixes[i].dev_count;
            move(i, 0);
            printw("IP rozsah: %s/%d %d %d %.2f%%                        ", ip_str, ip_prefixes->prefixes[i].prefix, max_devs, dev_count, (double) dev_count*100/max_devs);
        } else {
            fprintf(stderr, "Chyba při konverzi IP adresy pro index %d.\n", i);
            exit(1);
        }
    }
    refresh();
}

/**
 * @brief Support function that converts IP address format to regular uint32 format.
 * @param ip IP address to convert.
 * @return IP address in uint32 format.
*/
uint32_t ip_to_uint32(const struct in_addr *ip) {
    return ntohl(ip->s_addr);
}

/**
 * @brief Function checks whether an IP address is within specified IP prefix.
 * @param ip IP address to check.
 * @param prefix Prefix to check.
 * @return 1 if the IP address is within the specified prefix, 0 if it is not.
*/
int is_ip_in_prefix(const struct in_addr *ip, const IP_Prefix *prefix) {
    uint32_t ip_val = ip_to_uint32(ip);
    uint32_t prefix_val = ip_to_uint32(&prefix->ip);

    // Vytvoření masky podle prefixu
    uint32_t mask = prefix->prefix == 0 ? 0 : (~0) << (32 - prefix->prefix);

    // Zjistí, jestli IP adresa patří do rozsahu
    return (ip_val & mask) == (prefix_val & mask);
}

/**
 * @brief Updates the device number for IP prefixes.
 * @param head Head of the linked list.
 * @param ip_prefixes IP prefixes.
*/
void update_dev_count(struct occAddr *head, IP_Prefixes *ip_prefixes) {
    // Nejdříve inicializujeme čítadla na nulu
    for (int i = 0; i < ip_prefixes->count; i++) {
        ip_prefixes->prefixes[i].dev_count = 0;
    }

    // Projdeme všechny IP adresy v seznamu
    struct occAddr *current = head;
    while (current) {
        for (int i = 0; i < ip_prefixes->count; i++) {
            if (is_ip_in_prefix(&current->ip, &ip_prefixes->prefixes[i])) {
                (ip_prefixes->prefixes[i].dev_count)++;
            }
        }
        current = current->next;
    }

    for (int i = 0; i < ip_prefixes->count; i++) {
        int max_devs = (1 << (32 - ip_prefixes->prefixes[i].prefix)) - 2;
        int dev_count = ip_prefixes->prefixes[i].dev_count;
        char ip_str[INET_ADDRSTRLEN];  // Prostor pro uložení řetězcové reprezentace IP adresy
        inet_ntop(AF_INET, &ip_prefixes->prefixes[i].ip, ip_str, INET_ADDRSTRLEN);

        if (dev_count > 8) { //max_devs / 2
            char msg[255];
            sprintf(msg, "prefix %s/%d exceeded 50%% of allocations", ip_str, ip_prefixes->prefixes[i].prefix);
            move(ip_prefixes->count, 0);
            printw("%s\n", msg);
            refresh();
            syslog(LOG_WARNING, "%s", msg);
        }
    }
}

void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);
    struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));
    struct dhcp_packet* dhcp_pkt = (struct dhcp_packet*)(packet + 14 + (ip_header->ip_hl << 2) + sizeof(struct udphdr));

    if (ntohs(udp_header->source) == DHCP_SERVER_PORT || ntohs(udp_header->source) == DHCP_CLIENT_PORT ||
        ntohs(udp_header->dest) == DHCP_SERVER_PORT || ntohs(udp_header->dest) == DHCP_CLIENT_PORT) {
        // printf("DHCP packet captured\n");
        // printf("DHCP packet received from %s to %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        print_ip_ranges(&ip_prefixes);  
        // print_dhcp_packet(dhcp_pkt);

        // time_t expTime;
        // time_t currTime;
        // time(&currTime);
        // expTime = currTime;
        long int lease_time = 24*60*60; // TODO MAGIC CONSTANT
        int wasAck = 0;

        // printf("TIME: %ld CURRTIME: %ld, LEN: %d %d                           \n\n", pkthdr->ts.tv_sec, currTime, pkthdr->caplen, pkthdr->len);

        // Extract DHCP message type from DHCP options
        u_char* dhcp_options = (u_char*)(packet + 14 + (ip_header->ip_hl << 2) + sizeof(struct udphdr) + 240);
        // u_char dhcp_type = 0;

        // print_buffer(dhcp_options, 312);
        // print_buffer(dhcp_pkt->options, 312);

        while (*dhcp_options != 255) {  // End option

            // Print all option codes for debugging
            // printf("DHCP Option: %d ", *dhcp_options);
            
            switch (*dhcp_options) {
                case DHCP_OPTION_HOST_NAME:
                    // printf("Host name: %.*s\n", *(u_char*)(dhcp_options+1), dhcp_options+2);
                    break;
                case DHCP_OPTION_REQUESTED_IP :
                    // printf("Requested IP address: %s\n", inet_ntoa(*(struct in_addr*)(dhcp_options + 2)));
                    break;
                case DHCP_OPTION_MESSAGE_TYPE:
                    u_char dhcp_type = *(dhcp_options + 2);  // Message type is two bytes offset from the start of the option
                    if (dhcp_type == DHCP_ACK) {
                        wasAck = 1;
                        // printf("ACK PRISLO\n");
                    }
                    if (dhcp_type == DHCP_RELEASE)
                    {
                        // printf("Releasing IP: %s\n", inet_ntoa(dhcp_pkt->ciaddr));
                        removeElement(dhcp_pkt->ciaddr);   
                        // printf("items in list: %ld\n", countElements()); 
                        // print_ip_ranges(&ip_prefixes);    
                        update_dev_count(head, &ip_prefixes);
                        print_ip_ranges(&ip_prefixes);    
                    }
                    break;
                case DHCP_OPTION_LEASE_TIME:
                    // uint32_t lease_time = ntohl(*(uint32_t*)(dhcp_options + 2));
                    // expTime += lease_time;
                    // printf("Lease Time: %u seconds\n", lease_time);
                    lease_time = ntohl(*(uint32_t*)(dhcp_options + 2));
                    break;
                case DHCP_OPTION_SERVER_ID:
                    // printf("Server identifier IP: %s\n", inet_ntoa(*(struct in_addr*)(dhcp_options + 2)));
                    break;
                case DHCP_OPTION_PARAM_LIST:
                    // printf("Parameter list: \n");
                    break;
                case DHCP_OPTION_MAX_MSG_SIZE:
                    // printf("Max message size request: \n");
                    break;
                default:
                    // printf("Unknown option %d\n", *dhcp_options);
                    break;
            }

            // if (*dhcp_options == DHCP_OPTION_MESSAGE_TYPE) {  // DHCP Message Type option
            //     u_char dhcp_type = *(dhcp_options + 2);  // Message type is two bytes offset from the start of the option
            //     switch (dhcp_type) {
            //         case DHCP_DISCOVER:
            //             printf("DHCP Type: Discover\n");
            //             break;
            //         case DHCP_OFFER:
            //             printf("DHCP Type: Offer\n");
            //             break;
            //         case DHCP_REQUEST:
            //             printf("DHCP Type: Request\n");
            //             break;
            //         case DHCP_DECLINE:
            //             printf("DHCP Type: Decline\n");
            //             break;
            //         case DHCP_ACK:
            //             printf("DHCP Type: Acknowledgment\n");
            //             break;
            //         case DHCP_NAK:
            //             printf("DHCP Type: Negative Acknowledgment\n");
            //             break;
            //         case DHCP_RELEASE:
            //             printf("DHCP Type: Release\n");
            //             break;
            //         case DHCP_INFORM:
            //             printf("DHCP Type: Inform\n");
            //             break;
            //         default:
            //             printf("Unknown DHCP Type\n");
            //     }
            // }

            dhcp_options += *(dhcp_options + 1) + 2;  // Move to next option
        }
        if(wasAck){
            if (findElement(dhcp_pkt->yiaddr) != NULL) {
                updateElement(dhcp_pkt->yiaddr, pkthdr->ts.tv_sec + lease_time);
            }
            else {
                addElement(dhcp_pkt->yiaddr, pkthdr->ts.tv_sec + lease_time);
            }
            struct occAddr *tmpOccAddr = head;
            struct occAddr *prev = NULL;
            while (tmpOccAddr) {
                if (tmpOccAddr->tm < pkthdr->ts.tv_sec) {
                    if (prev) {
                        prev->next = tmpOccAddr->next;
                        free(tmpOccAddr);
                        tmpOccAddr = prev->next;
                    }
                    else {
                        head = tmpOccAddr->next;
                        free(tmpOccAddr);
                        tmpOccAddr = head;
                    }
                }
                else {
                    prev = tmpOccAddr;
                    tmpOccAddr = tmpOccAddr->next;
                }
            }
            // print_ip_ranges(&ip_prefixes);    
            update_dev_count(head, &ip_prefixes);
            print_ip_ranges(&ip_prefixes);   

        
            // Storing start time
            clock_t start_time = clock();
        
            // looping till required time is not achieved
            while (clock() < start_time + 10000);
            // printf("items in list: %ld\n", countElements());
        }
        // printf("-----------\n");
    }
}



int main(int argc, char* argv[]) {
    pcap_if_t* alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = 0;
    pcap_t* handle;
    char *filename = NULL;
    char *interface = NULL;

    ip_prefixes.count = 0;
    ip_prefixes.prefixes = NULL;
    extern char *optarg;
    extern int optind, opterr, optopt;

    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                filename = optarg;
                if (access(filename, F_OK) == -1) {
                    fprintf(stderr, "Vstupní soubor '%s' neexistuje.\n", filename);
                    return 1;
                }
                break;
            case 'i':
                interface = optarg;
                break;
            default:
                fprintf(stderr, "Neznámá volba: %c\n", opt);
                return 1;
        }
    }

    if (!filename && !interface) {
        fprintf(stderr, "Chyba: Musíte zadat buď -r <filename> nebo -i <interface-name>\n");
        return 1;
    }

    if (interface) {
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Chyba v pcap_findalldevs: %s\n", errbuf);
            return 1;
        }

        pcap_if_t *device;
        int found = 0;
        for (device = alldevs; device; device = device->next) {
            if (strcmp(device->name, interface) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Rozhraní '%s' nenalezeno.\n", interface);
            return 1;
        }
    }

    if (optind == argc) {
        fprintf(stderr, "Chybí IP prefix(y) pro generování statistiky\n");
        return 1;
    }

    // Uložení všech IP prefixů do dynamického pole
    ip_prefixes.count = argc - optind;
    ip_prefixes.prefixes = (IP_Prefix *) malloc(ip_prefixes.count * sizeof(IP_Prefix));
    if (ip_prefixes.prefixes == NULL) {
        fprintf(stderr, "Chyba při alokaci paměti.\n");
        return 1;
    }
    
    for (int i = 0; optind < argc; optind++, i++) {
        if (!parse_ip_prefix(argv[optind], &ip_prefixes.prefixes[i])) {
            fprintf(stderr, "Chyba při parsování IP prefixu: %s\n", argv[optind]);
            free(ip_prefixes.prefixes);
            return 1;
        }
    }

    initscr();

    // printf("Filename: %s\n", filename ? filename : "Není zadán");
    // printf("Interface: %s\n", interface ? interface : "Není zadán");
    print_ip_ranges(&ip_prefixes);

    if (filename)
    {
        /** READING DHCP COMMUNICATION FROM FILE */
        handle = pcap_open_offline(filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening file %s: %s\n", filename, errbuf);
            pcap_freealldevs(alldevs);
            return 2;
        }

        pcap_loop(handle, 0, packet_handler, NULL);

        pcap_close(handle);
        pcap_freealldevs(alldevs);
    }

    if (interface)
    {
        /** OPENING LIVE SESSION */
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening device %s: %s\n", interface, errbuf);
            pcap_freealldevs(alldevs);
            return 2;
        }

        pcap_loop(handle, 0, packet_handler, NULL);

        pcap_close(handle);
        pcap_freealldevs(alldevs);
    }

    endwin();
    free(ip_prefixes.prefixes);

    return 0;
}