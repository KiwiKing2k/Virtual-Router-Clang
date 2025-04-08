#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry* rtable;
int rtable_len;

/* Mac table */
struct mac_entry* mac_table;
int mac_table_len;

#define MAX_RTABLE_LEN 100000
#define IPV4_ETHERTYPE 0x0800

uint16_t ip_checksum(uint16_t* data, size_t len)
{
    unsigned long checksum = 0;
    uint16_t extra_byte;
    while (len > 1)
    {
        checksum += ntohs(*data++);
        len -= 2;
    }
    if (len)
    {
        *(uint8_t*)&extra_byte = *(uint8_t*)data;
        checksum += extra_byte;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return (uint16_t)(~checksum);
}

struct node
{
    struct route_table_entry* entry;
    struct node* children[2];
};

struct node* create_node()
{
    struct node* new_node = (struct node*)malloc(sizeof(struct node));
    new_node->entry = NULL;
    new_node->children[0] = NULL;
    new_node->children[1] = NULL;
    return new_node;
}

void insert_trie(struct node* root, struct route_table_entry* entry)
{
    //also handles NULL childern
    struct node* curr = root;
    uint32_t prefix = ntohl(entry->prefix);
    int32_t mask = ntohl(entry->mask);

    for (int i = 31; i >= 0; i--)
    {
        int bit = (prefix >> i) & 1;
        if (curr->children[bit] == NULL)
        {
            curr->children[bit] = create_node();
        }
        curr = curr->children[bit];
        if ((mask & (1 << i)) == 0)
        {
            //checking if we reach the end of the mask
            break;
        }
    }
    curr->entry = entry;
}

struct route_table_entry* lpm(struct node *root, uint32_t ip)
{
    struct node* curr = root;
    struct route_table_entry* best_entry = NULL;
    ip = ntohl(ip);

    for (int i = 31; i >= 0; i--)
    {
        int bit= (ip >> i) & 1;
        if (curr->children[bit] == NULL)
        {
            break;
        }
        curr = curr->children[bit];
        if (curr->entry != NULL)
        {
            best_entry = curr->entry;
            // the more bits we go through the better the entry
        }
    }
    return best_entry;

}

void read_rtable(char* filename, struct node* root)
{
    FILE* file = fopen(filename, "r");
    if (!file) {
        exit(EXIT_FAILURE);
    }
    char buffer[1024];
    while (fgets(buffer, 1024, file))
    {
        struct route_table_entry* entry = (struct route_table_entry*)malloc(sizeof(struct route_table_entry));
        char prefix[16], next_hop[16], mask[16];
        int interface;
        sscanf(buffer, "%s %s %s %d", prefix, next_hop, mask, &interface);
        // use inet_pton to convert the IP addr from string to binary
        inet_pton(AF_INET, prefix, &entry->prefix);
        inet_pton(AF_INET, next_hop, &entry->next_hop);
        inet_pton(AF_INET, mask, &entry->mask);
        entry->interface = interface;
        insert_trie(root, entry);
    }
    fclose(file);
}

int main(int argc, char* argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argv + 2, argc - 2);

    rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_LEN);

    // reading routing table and making a trie
    struct node* root = create_node();
    read_rtable("rtable1.txt", root);
    read_rtable("rtable2.txt", root);

    while (1)
    {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_hdr* eth_hdr = (struct ether_hdr*)buf;
        struct ip_hdr* ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));

        if (eth_hdr->ethr_type != ntohs(IPV4_ETHERTYPE))
        {
            printf("Ignored non-IPv4 packet\n");
            continue;
        }
        for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
        {
            uint32_t router_ip = ntohl(*(uint32_t*)get_interface_ip(i));
            if (ip_hdr->dest_addr == router_ip)
            {
                // received ICMP
            }
        }
        if (ip_hdr->checksum != ip_checksum((uint16_t*)ip_hdr, ip_hdr->ihl))
        {
            printf("Ignored packet with bad checksum\n");
            continue;
        } // check sum
        if (ip_hdr->ttl < 1)
        {
            printf("Time to leave\n");
            continue;
        }
        ip_hdr->ttl--;
        ip_hdr->checksum = ip_checksum((uint16_t*)ip_hdr, ip_hdr->ihl); // update checksum and done with ip hdr

        //lpm

        struct route_table_entry* match = lpm(root, ip_hdr->dest_addr);
        if (match == NULL)
        {
            continue;
            //aruncam pachetul
        }

        //arp to be implemented



        //  Implement the router forwarding logic

        /* Note that packets received are in network order,
            any header field which has more than 1 byte will need to be conerted to
            host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
            sending a packet on the link, */
    }
}
