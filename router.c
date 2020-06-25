#include "skel.h"
#include "queue.h"
#include "list.h"
#include "my_parser.h"
#include "my_trie.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
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
#include <linux/if_ether.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <asm/byteorder.h>

// Structure used when refering to arp packs.
struct arp_structure {
	struct	arphdr ea_hdr;
	uint8_t arp_sha[6];
	uint32_t arp_spa;
	uint8_t arp_tha[6];
	uint32_t arp_tpa;		
} __attribute__((packed));

// Structure used when talking about the content of arp tab.
typedef struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
} arp_tab_elm;

// Helpfull when finding the masks.
#define MAX_UINT 4294967295
#define LAST_BIT_SET 2147483648

int main(int argc, char *argv[]) {
	setvbuf ( stdout , NULL , _IONBF , 0) ;
	packet m;
	packet aux_pack;
	int rc;
	init();

	// Data that is needed for parsing stage
	route_tab_elm *routeArr;
	uint8_t is_mask[35] = {0};
	unsigned int masks[35];
	unsigned int nr_masks = 0;
	int fd = open("rtable.txt", O_RDONLY);
	unsigned int routeTabSize = 0;

	// Call parsing.
	routeTabSize = getRouteTables(&fd, &routeArr);

	// initialize the trie structures
	trie_node *root_router_tab = new_trie_node();
	trie_node *root_arp_tab = new_trie_node();

	// Helpfull when finding the masks.
	unsigned int mask_check = 0;
	unsigned int bit_count = 1;
	unsigned int bit = 1;

	// The queue structures used by the router
	queue my_packet_q = queue_create();
	queue my_aux_q = queue_create();

	// Creating the trie and finding the masks
    for (int i = 0; i < routeTabSize; ++i) {
		mask_check = (routeArr[i].prefix & routeArr[i].mask);
        add_value_route(&mask_check, &routeArr[i], root_router_tab);
		bit = LAST_BIT_SET;
		bit_count = 1;
		while (bit & routeArr[i].mask) {
			bit = (bit >> 1);
		}
		while (bit && !(bit & routeArr[i].mask)) {
			++bit_count;
			bit = (bit >> 1);
		}
		is_mask[bit_count] = 1;
	}

	// Computing the masks
	bit = MAX_UINT;
	bit_count = 1;
	for (int i = 1; i <= 32; ++i) {
		if (is_mask[i]) {
			++nr_masks;
			masks[nr_masks] = htonl(bit);
		}
		bit = bit ^ bit_count;
		bit_count = bit_count << 1;
	}
	close(fd);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *top_hdr = (struct ether_header *)m.payload;

		// Treat the case in which the pack is ARP type, accourding to the ethernet header.
		if (ntohs(top_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_structure *content =
			(struct arp_structure *)(m.payload + sizeof(struct ether_header));

			// In case of a reply then the pack is processed in the following manner
			// the arp table (trie) is updated
			// the que is checked and cleared from all those packs that couldn't be sent previously.
			if (ntohs(content->ea_hdr.ar_op) == ARPOP_REPLY) {
				arp_tab_elm *match_arp;

					match_arp = (arp_tab_elm *)malloc(sizeof(arp_tab_elm *));
					match_arp->ip = content->arp_spa;
					memcpy(match_arp->mac, content->arp_sha, 6);
					add_value(&match_arp->ip, match_arp, root_arp_tab);

				while (!queue_empty(my_packet_q)) {
					packet *next_pack = queue_deq(my_packet_q);
					struct ether_header *top_hdr_new = (struct ether_header *)next_pack->payload;
					struct iphdr *content_new
						= (struct iphdr *)(next_pack->payload + sizeof(struct ether_header));
					
					if (content_new->daddr != match_arp->ip) {
						queue_enq(my_aux_q, next_pack);
						continue;
					}
					route_tab_elm *nex_addr
						= get_best_route(&content_new->daddr, root_router_tab, masks, &nr_masks);

					next_pack->interface = nex_addr->interface;
					get_interface_mac(nex_addr->interface, top_hdr_new->ether_shost);
					memcpy(top_hdr_new->ether_dhost, match_arp->mac, 6);

					send_packet(next_pack->interface, next_pack);
				}
				while (!queue_empty(my_aux_q)) {
					packet *next_pack = queue_deq(my_aux_q);
					queue_enq(my_packet_q, next_pack);
				}
			}

			// In case of arp request then a reply is conceived
			// and sent back to the host that asked for sending a pack
			// outside the local network
			if (ntohs(content->ea_hdr.ar_op) == ARPOP_REQUEST) {

				memcpy(top_hdr->ether_dhost, top_hdr->ether_shost, 6);
				get_interface_mac(m.interface, top_hdr->ether_shost);

				content->ea_hdr.ar_op = htons(ARPOP_REPLY);
				content->arp_tpa = content->arp_spa;
				memcpy(content->arp_tha, content->arp_sha, 6);
				get_interface_mac(m.interface, content->arp_sha);
				content->arp_spa = inet_addr(get_interface_ip(m.interface));

				send_packet(m.interface, &m);
			}
		}

		// Treat the case in which the pack is IP type, accourding to the ethernet header.
		if (ntohs(top_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *content = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_content =
				(struct icmphdr *)(m.payload +
				sizeof(struct ether_header) +
				sizeof(struct iphdr));

			// First of all is checked the integrity of the pack
			uint16_t check_old = content->check;
			content->check = 0;
			if (check_old != ip_checksum(content, sizeof(struct iphdr))) {
				continue;
			}

			content->check = check_old;

			// Onwards, it is performed a look up in the trie for the best route.
			route_tab_elm *next_addr = NULL;
			next_addr = get_best_route(&content->daddr, root_router_tab, masks, &nr_masks);

			// The next fields treat the ICMP response, (accourding to the header)
			if (content->ttl <= 1 ||
				next_addr == NULL ||
				(inet_addr(get_interface_ip(m.interface)) == content->daddr &&
				icmp_content->type == ICMP_ECHO)) {

				// Check if there is an error case or an echo reply situation.
				// update the type.
				if (content->ttl <= 1) {
					icmp_content->type = 11;
				} else {
					if (next_addr == NULL) {
						icmp_content->type = 3;
					} else {
						icmp_content->type = 0;
					}
				}

				// Update all required fields and send the pack
				memcpy(top_hdr->ether_dhost, top_hdr->ether_shost, 6);
				get_interface_mac(m.interface , top_hdr->ether_shost);

				content->ihl = 5;
				content->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

				content->ttl = 64;
				content->protocol = 1;

				unsigned int tmp;
				tmp = content->daddr;
				content->daddr = content->saddr;
				content->saddr = tmp;

				content->check = 0;
				content->check = ip_checksum(content, sizeof(struct iphdr));

				icmp_content->code = 0;
				icmp_content->checksum = 0;
				icmp_content->checksum = ip_checksum(icmp_content, sizeof(struct icmphdr));

				m.len = sizeof(struct ether_header) +
				sizeof(struct iphdr) +
				sizeof(struct icmphdr);

				send_packet(m.interface, &m);
				continue;

			}


			if (next_addr != NULL) {
				// As there is no error to be found, perform the check in the ARP table.
				arp_tab_elm *match_arp = NULL;
				match_arp = get_value(&next_addr->next_hop, root_arp_tab);

				// Update the content that administrates the lifespawn of the pack.
				--content->ttl;
				content->check = 0;
				content->check = ip_checksum(content, sizeof(struct iphdr));

				if (match_arp == NULL) {
					queue_enq(my_packet_q, &m);

					// In the case of a failure then it means that we must have to
					// obtain the unknown mac address, by conceiving an ARP request.
					// and the pack gets queued.
					
					aux_pack.len = sizeof(struct ether_header) + sizeof(struct arp_structure);
					aux_pack.interface = next_addr->interface;

					struct ether_header *top_hdr_new = (struct ether_header *)aux_pack.payload;
					struct arp_structure *content_new
						= (struct arp_structure *)(aux_pack.payload + sizeof(struct ether_header));

					content_new->ea_hdr.ar_op = htons(ARPOP_REQUEST);
					content_new->ea_hdr.ar_pln = sizeof(content_new->arp_spa);
					content_new->ea_hdr.ar_hln = sizeof(content_new->arp_sha);
					content_new->ea_hdr.ar_pro = ntohs(ETHERTYPE_IP);
					content_new->ea_hdr.ar_hrd = ntohs(1);

					content_new->arp_tpa = content->daddr;
					content_new->arp_spa = inet_addr(get_interface_ip(next_addr->interface));

					get_interface_mac(next_addr->interface, content_new->arp_sha);
					hwaddr_aton("00:00:00:00:00:00", content_new->arp_tha);
					hwaddr_aton("ff:ff:ff:ff:ff:ff", top_hdr_new->ether_dhost);
					get_interface_mac(next_addr->interface, top_hdr_new->ether_shost);
					top_hdr_new->ether_type = htons(ETHERTYPE_ARP);

					send_packet(aux_pack.interface, &aux_pack);

				} else {

					// If we made it so far it means that the pack is just fine and
					// it only needs to be forwarded.

					packet *next_pack = &m;
					struct ether_header *top_hdr_new = (struct ether_header *)next_pack->payload;

					next_pack->interface = next_addr->interface;
					get_interface_mac(next_pack->interface, top_hdr_new->ether_shost);
					memcpy(top_hdr_new->ether_dhost, match_arp->mac, 6);
					send_packet(next_pack->interface, next_pack);
				}
			}
		}
	}
}