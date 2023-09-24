#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>  // For inet_ntoa()
#include <netinet/if_ether.h>
#include <time.h>

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

struct dhcp_packet {
    u_int8_t op;            // Message type: Boot Request (1) or Boot Reply (2)
    u_int8_t htype;         // Hardware address type: Ethernet is 1
    u_int8_t hlen;          // Hardware address length: Ethernet is 6
    u_int8_t hops;          // Hops
    u_int32_t xid;          // Transaction ID
    u_int16_t secs;         // Seconds since DHCP process started
    u_int16_t flags;        // Flags
    struct in_addr ciaddr;  // Client IP address if client has a current IP address
    struct in_addr yiaddr;  // 'Your' (client) IP address
    struct in_addr siaddr;  // IP address of next server to use in bootstrap
    struct in_addr giaddr;  // Gateway IP address, if present
    u_int8_t chaddr[16];    // Client hardware address
    char sname[64];         // Optional server host name, null terminated string
    char file[128];         // Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
    u_int8_t options[312];  // Optional parameters field. See RFC 2132.
};

// Occupied IP address structure
struct occAddr {
    struct in_addr ip;
    time_t tm;
    struct occAddr *next;
};

struct occAddr *head = NULL;

// Add a new item
void add(struct in_addr ip, time_t tm) {
    struct occAddr *newNode = malloc(sizeof(struct occAddr));
    newNode->ip = ip;
    newNode->tm = tm;
    newNode->next = head;
    head = newNode;
}

// Find an item by IP
struct occAddr* find(struct in_addr ip) {
    struct occAddr *current = head;
    while (current) {
        if (current->ip.s_addr == ip.s_addr) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Update an item's time
int update(struct in_addr ip, time_t tm) {
    struct occAddr *node = find(ip);
    if (node) {
        node->tm = tm;
        return 1;  // Success
    }
    return 0;  // Not found
}

// Remove an item by IP
int removeItem(struct in_addr ip) {
    struct occAddr *current = head;
    struct occAddr *prev = NULL;
    
    while (current) {
        if (current->ip.s_addr == ip.s_addr) {
            if (prev) {
                prev->next = current->next;
            } else {
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

// clear all items
void clear() {
    struct occAddr *current = head;
    while (current) {
        struct occAddr *temp = current;
        current = current->next;
        free(temp);
    }
    head = NULL;
}

size_t count_items() {
    size_t count = 0;
    struct occAddr *current = head;
    while (current) {
        count++;
        current = current->next;
    }
    return count;
}

void print_buffer(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; i += 16) {
        // Print hex values
        for (size_t j = 0; j < 16 && (i + j) < size; ++j) {
            printf("%02x ", buffer[i + j]);
        }

        // Add padding if necessary
        for (size_t j = (i + 16 > size ? size - i : 16); j < 16; ++j) {
            printf("   ");
        }

        printf("| ");

        // Print ASCII characters
        for (size_t j = 0; j < 16 && (i + j) < size; ++j) {
            unsigned char ch = buffer[i + j];
            if (ch >= 0x20 && ch <= 0x7E) {  // printable ASCII range
                printf("%c", ch);
            } else {
                printf(".");
            }
        }
        
        printf("\n");
    }
}

void print_dhcp_packet(const struct dhcp_packet* dhcp) {
    // printf("DHCP Packet:\n");
    // printf("-----------\n");

    printf("Message Type: %s\n", dhcp->op == BOOTREQUEST ? "Boot Request" : "Boot Reply");
    printf("Hardware Address Type: %u\n", dhcp->htype);
    printf("Hardware Address Length: %u\n", dhcp->hlen);
    printf("Hops: %u\n", dhcp->hops);
    printf("Transaction ID: 0x%X\n", ntohl(dhcp->xid));
    printf("Seconds Elapsed: %u\n", ntohs(dhcp->secs));
    printf("Flags: 0x%X\n", ntohs(dhcp->flags));
    printf("Client IP: %s\n", inet_ntoa(dhcp->ciaddr));
    printf("Your IP: %s\n", inet_ntoa(dhcp->yiaddr));
    printf("Server IP: %s\n", inet_ntoa(dhcp->siaddr));
    printf("Relay IP: %s\n", inet_ntoa(dhcp->giaddr));

    printf("Client MAC Address: ");
    for(int i = 0; i < dhcp->hlen && i < 16; i++) {
        printf("%02X", dhcp->chaddr[i]);
        if (i < (dhcp->hlen - 1)) printf(":");
    }
    printf("\n");

    printf("Server Name: %s\n", dhcp->sname);
    printf("Boot File Name: %s\n", dhcp->file);

    // Further processing can be done to extract specific DHCP options
    // You can add code here to parse the options if needed.

    printf("\n");
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);
    struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));
    struct dhcp_packet* dhcp_pkt = (struct dhcp_packet*)(packet + 14 + (ip_header->ip_hl << 2) + sizeof(struct udphdr));

    if (ntohs(udp_header->source) == DHCP_SERVER_PORT || ntohs(udp_header->source) == DHCP_CLIENT_PORT ||
        ntohs(udp_header->dest) == DHCP_SERVER_PORT || ntohs(udp_header->dest) == DHCP_CLIENT_PORT) {
        // printf("DHCP packet captured\n");
        printf("DHCP packet received from %s to %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        // print_dhcp_packet(dhcp_pkt);

        time_t expTime;
        time_t currTime;
        time(&currTime);
        expTime = currTime;
        int wasAck = 0;

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
                    }
                    if (dhcp_type == DHCP_RELEASE)
                    {
                        printf("Releasing IP: %s\n", inet_ntoa(dhcp_pkt->ciaddr));
                        removeItem(dhcp_pkt->ciaddr);   
                        printf("items in list: %ld\n", count_items());     
                    }
                    break;
                case DHCP_OPTION_LEASE_TIME:
                    uint32_t lease_time = ntohl(*(uint32_t*)(dhcp_options + 2));
                    expTime += lease_time;
                    // printf("Lease Time: %u seconds\n", lease_time);
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
            if (find(dhcp_pkt->yiaddr) != NULL) {
                update(dhcp_pkt->yiaddr, expTime);
            }
            else {
                add(dhcp_pkt->yiaddr, expTime);
            }
            struct occAddr *current = head;
            struct occAddr *prev = NULL;
            while (current) {
                if (current->tm < currTime) {
                    if (prev) {
                        prev->next = current->next;
                        free(current);
                        current = prev->next;
                    }
                    else {
                        head = current->next;
                        free(current);
                        current = head;
                    }
                }
                else {
                    prev = current;
                    current = current->next;
                }
            }
            printf("items in list: %ld\n", count_items());
        }
    
        // printf("-----------\n");
    }
}

int main(int argc, char* argv[]) {
    pcap_if_t* alldevs, * d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    printf("Tohle je breakpoint");

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // If no device found, exit
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found\n");
        return 1;
    }

    // Use the first device (you can modify this to select a specific device)
    d = alldevs;

    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", d->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}