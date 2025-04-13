#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry* rtable;
int rtable_len;

/* Mac table */
struct mac_entry* mac_table;
int mac_table_len;

#define MAX_RTABLE_LEN 100000
#define IPV4_ETHERTYPE 0x0800
#define MIN_ETH_HDR_LEN 14
#define MIN_IP_HDR_LEN 20
#define MIN_ICMP_HDR_LEN 8


int is_valid_l2_packet(struct ether_hdr* eth_hdr, size_t interface)
{
    uint8_t interface_mac[6];
    get_interface_mac(interface, interface_mac);

    if (memcmp(eth_hdr->ethr_dhost, interface_mac, 6) == 0)
    {
        return 1;
    }

    //verificam daca e adresa de broadcast
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (memcmp(eth_hdr->ethr_dhost, broadcast_mac, 6) == 0)
    {
        return 1;
    }
    //lets print eth_hdr->ethr_dhost
    printf("Received packet with destination MAC: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", eth_hdr->ethr_dhost[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");
    printf("My MAC address: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", interface_mac[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");
    printf("MAC adress not for me\n");
    return 0;
}

int is_packet_too_short(size_t len)
{
    if (len < MIN_ETH_HDR_LEN)
    {
        printf("Packet too short: missing Ethernet header\n");
        return 1;
    }

    if (len < MIN_ETH_HDR_LEN + MIN_IP_HDR_LEN)
    {
        printf("Packet too short: missing IP header\n");
        return 1;
    }

    return 0;
}

void handle_icmp_echo(char* buf, size_t len, size_t interface)
{
    printf("Ajungem in handle icmp");
    struct ether_hdr* eth_hdr = (struct ether_hdr*)buf;
    struct ip_hdr* ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr* icmp_hdr = (struct icmp_hdr*)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    // Type 8 Echo Request
    if (icmp_hdr->mtype == 8)
    {
        icmp_hdr->mtype = 0; // Type 0 Echo Reply
        icmp_hdr->mcode = 0;
        icmp_hdr->check = 0;
        icmp_hdr->check = htons(checksum((uint16_t*)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));
        printf("Checksum in echo reply");
        // Update IP header
        uint32_t temp_ip = ip_hdr->source_addr;
        ip_hdr->source_addr = ip_hdr->dest_addr;
        ip_hdr->dest_addr = temp_ip;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t*)ip_hdr, ip_hdr->ihl * 4));
        printf("Updated IP header");
        // Update Ethernet header
        uint8_t temp_mac[6];
        memcpy(temp_mac, eth_hdr->ethr_shost, 6);
        memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
        memcpy(eth_hdr->ethr_dhost, temp_mac, 6);

        if (send_to_link(len, buf, interface) < 0)
        {
            exit(EXIT_FAILURE);
        }
        printf("Sent ICMP echo reply\n");
    }
}

void handle_ttl_exceeded(char* buf, size_t len, size_t interface)
{
    uint8_t new_buf[MAX_PACKET_LEN];
    struct ether_hdr* eth_hdr = (struct ether_hdr*)buf;
    struct ip_hdr* ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
    struct ether_hdr* new_eth_hdr = (struct ether_hdr*)new_buf;
    struct ip_hdr* new_ip_hdr = (struct ip_hdr*)(new_buf + sizeof(struct ether_hdr));
    struct icmp_hdr* new_icmp_hdr = (struct icmp_hdr*)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    //update Ethernet header
    memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, new_eth_hdr->ethr_shost);
    new_eth_hdr->ethr_type = htons(IPV4_ETHERTYPE);

    //update IP header
    new_ip_hdr->ver = 4;
    new_ip_hdr->ihl = 5;
    new_ip_hdr->tos = 0;
    new_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    new_ip_hdr->id = htons(4);
    new_ip_hdr->frag = htons(0);
    new_ip_hdr->ttl = 64;
    new_ip_hdr->proto = IPPROTO_ICMP;
    new_ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
    new_ip_hdr->dest_addr = ip_hdr->source_addr;
    new_ip_hdr->checksum = 0;
    new_ip_hdr->checksum = htons(checksum((uint16_t*)new_ip_hdr, sizeof(struct ip_hdr)));

    //update ICMP header
    new_icmp_hdr->mtype = 11; // Time Exceeded
    new_icmp_hdr->mcode = 0;
    new_icmp_hdr->check = 0;

    memcpy((uint8_t*)new_icmp_hdr + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);

    new_icmp_hdr->check = checksum((uint16_t*)new_icmp_hdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);

    if (send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8, (char*)new_buf
        , interface) < 0)
    {
        exit(EXIT_FAILURE);
    }
    printf("Sent ICMP Time Exceeded error\n");
}

void handle_host_unreachable(char* buf, size_t len, size_t interface)
{
    uint8_t new_buf[MAX_PACKET_LEN];
    struct ether_hdr* eth_hdr = (struct ether_hdr*)buf;
    struct ip_hdr* ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));
    struct ether_hdr* new_eth_hdr = (struct ether_hdr*)new_buf;
    struct ip_hdr* new_ip_hdr = (struct ip_hdr*)(new_buf + sizeof(struct ether_hdr));
    struct icmp_hdr* new_icmp_hdr = (struct icmp_hdr*)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    //update Ethernet header
    memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, new_eth_hdr->ethr_shost);
    new_eth_hdr->ethr_type = htons(IPV4_ETHERTYPE);

    //update IP header
    new_ip_hdr->ver = 4;
    new_ip_hdr->ihl = 5;
    new_ip_hdr->tos = 0;
    new_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    new_ip_hdr->id = htons(4);
    new_ip_hdr->frag = htons(0);
    new_ip_hdr->ttl = 64;
    new_ip_hdr->proto = IPPROTO_ICMP;
    new_ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
    new_ip_hdr->dest_addr = ip_hdr->source_addr;
    new_ip_hdr->checksum = 0;
    new_ip_hdr->checksum = htons(checksum((uint16_t*)new_ip_hdr, sizeof(struct ip_hdr)));

    //update ICMP header
    new_icmp_hdr->mtype = 3; // host unreachable
    new_icmp_hdr->mcode = 0;
    new_icmp_hdr->check = 0;

    memcpy((uint8_t*)new_icmp_hdr + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);

    new_icmp_hdr->check = checksum((uint16_t*)new_icmp_hdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);

    if (send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8, (char*)new_buf
        , interface) < 0)
    {
        exit(EXIT_FAILURE);
    }
    printf("Sent ICMP Time Exceeded error\n");
}

int validate_and_update_ttl(struct ip_hdr* ip_hdr, char* buf, size_t len, size_t interface)
{
    // Save the old checksum
    uint16_t old_checksum = ntohs(ip_hdr->checksum);
    ip_hdr->checksum = 0;

    // Calculate the checksum
    uint16_t calculated_checksum = checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr));

    // Check if the checksum is valid
    if (old_checksum != calculated_checksum)
    {
        printf("Invalid checksum: old=%hu, calculated=%hu\n", old_checksum, calculated_checksum);
        printf("Ntohs old checksum: %hu\n", ntohs(old_checksum));
        return 0;
    }

    if (ip_hdr->ttl <= 1)
    {
        printf("TTL expired\n");
        // icmp ttl<1
        handle_ttl_exceeded(buf, len, interface);
        return 0;
    }
    ip_hdr->ttl--;

    ip_hdr->checksum = 0;
    //update checksum
    ip_hdr->checksum = htons(checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr)));

    return 1;
}

struct route_table_entry* linear_best_match(uint32_t dest_ip)
{
    struct route_table_entry* best_match = NULL;
    for (int i = 0; i < rtable_len; i++)
    {
        if ((dest_ip & rtable[i].mask) == rtable[i].prefix)
        {
            if (!best_match || ntohl(rtable[i].mask) > ntohl(best_match->mask))
            {
                best_match = &rtable[i];
            }
        }
    }
    return best_match;
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

struct route_table_entry* lpm(struct node* root, uint32_t ip)
{
    struct node* curr = root;
    struct route_table_entry* best_entry = NULL;

    for (int i = 31; i >= 0; i--)
    {
        int bit = (ip >> i) & 1;
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

int main(int argc, char* argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argv + 2, argc - 2);

    rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_LEN);

    // reading routing table and making a trie
    struct node* root = create_node();
    rtable_len = read_rtable(argv[1], rtable);
    printf("Routing table length: %d\n", rtable_len);
    for (int i = 0; i < rtable_len; i++)
    {
        insert_trie(root, &rtable[i]);
    }
    //
    struct arp_table_entry* arp_table = malloc(sizeof(struct arp_table_entry) * 6);
    if (!parse_arp_table("arp_table.txt", arp_table)) exit(EXIT_FAILURE);
    //

    while (1)
    {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
        if (is_packet_too_short(len))
        {
            printf("Short packet detected opinion rejected\n;");
            continue;
        }

        struct ether_hdr* eth_hdr = (struct ether_hdr*)buf;
        struct ip_hdr* ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));

        if (!is_valid_l2_packet(eth_hdr, interface)) continue; // if it is not sent for my mac, then continue

        printf("Received packet on interface %zu\n", interface);

        if (ntohs(eth_hdr->ethr_type) != IPV4_ETHERTYPE)
        {
            printf("Ignored non-IPv4 packet, EtherType: 0x%04x\n", ntohs(eth_hdr->ethr_type));
            continue;
        }

        //check if it is for me

        uint32_t router_ip = inet_addr(get_interface_ip(interface));
        printf("Received packet from IP: %x\n", router_ip);
        printf("Destination Interface ip: %x\n", ntohl(ip_hdr->dest_addr));
        if (ntohl(ip_hdr->dest_addr) == router_ip)
        {
            // Call the handle_icmp function
            handle_icmp_echo(buf, len, interface);
            continue;
        }

        if (!validate_and_update_ttl(ip_hdr, buf, len, interface))
        {
            //also handles ICMP response if ttl <=0
            printf("Packet dropped due to invalid checksum or TTL expiration\n");
            continue;
        }
        printf("Am trecut de ttl\n");
        //lpm
        struct route_table_entry* match = lpm(root, ip_hdr->dest_addr);
        struct route_table_entry* linear_match = linear_best_match(ip_hdr->dest_addr);

        if (match == NULL)
        {
            printf("No match found in by lpm\n");
            match = linear_match;
        }
        if (linear_match == NULL)
        {
            printf("No match found in by linear search\n");
            handle_host_unreachable(buf, len, interface);
            continue;
        }
        /*printf("Lin match is %d , next hop: %u\n", linear_match->interface, linear_match->next_hop);
        printf("LPM match is %d , next hop:  %u\n", match->interface, match->next_hop);*/

        struct in_addr next_hop_addr;
        next_hop_addr.s_addr = match->next_hop;
        printf("Lin match is %d , next hop: %s\n", linear_match->interface, inet_ntoa(*(struct in_addr*)&linear_match->next_hop));
        printf("LPM match is %d , next hop: %s\n", match->interface, inet_ntoa(next_hop_addr));

        //arp to be implemented
        for (int i = 0; i < 6; i++)
        {
            if (arp_table[i].ip == match->next_hop)
            {
                printf("Found match in ARP table\n");
                uint8_t mac[6];
                get_interface_mac(match->interface, mac);
                memcpy(eth_hdr->ethr_shost, mac, 6);
                memcpy(eth_hdr->ethr_dhost, arp_table[i].mac, 6);
                printf("ARP table match found: %s\n", inet_ntoa(*(struct in_addr*)&arp_table[i].ip));
                printf("Sent to MAC address: ");
                for (int i = 0; i < 6; i++)
                {
                    printf("%02x", mac[i]);
                    if (i < 5)
                        printf(":");
                }
                printf("\n");
                if (send_to_link(len, buf, match->interface) < 0) exit(EXIT_FAILURE);
                printf("Sent packet to interface %d\n", match->interface);
                break;
            }
        }
    }


    //  Implement the router forwarding logic

    /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
        sending a packet on the link, */
}
