// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// pcap file format reference:
// 'https://wiki.wireshark.org/Development/LibpcapFileFormat'

#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <time.h>
#include "communication.h"
#include "dns.h"
#include "hash_table.h"
#include "pcap.h"

int process_pcap_file(char* filename, char* buffer, tHTable* rr_table)
{
	FILE* pcap_file;
	struct iphdr* ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct udphdr* udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
	struct dns_hdr* dns_header = (struct dns_hdr *) (buffer + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* dns_data = (char *) (buffer + sizeof(struct dns_hdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* final_answer; // Final string
	char* domain_name; // Domain name of DNS record
	char* answer_type; // Type of resource record
	char* answer_data; // Data of specific resource record
	pcap_file = fopen(filename, "r");

	if (pcap_file == NULL)
	{
		free(rr_table);
		exit(EXIT_FAILURE);
	}

	char* hdr = malloc(sizeof(pcap_hdr_t));
	fread(hdr, sizeof(pcap_hdr_t), 1, pcap_file);

	while (1)
	{
		pcaprec_hdr_t packet_header;
		if(!fread(&packet_header, sizeof(pcaprec_hdr_t), 1, pcap_file)) // Read header and get length of packet
			break;
		if(!fread(buffer, packet_header.incl_len, 1, pcap_file)) // Read dns packet
			break;

		uint16_t offset = 0; // Offset is a 16bit integer which is used to move in DNS data
		uint16_t rr_type; // Type of resource record
		uint16_t rr_data_length; // Data length of specific resource record

		//UDP
		if(ntohs(udp_header->source) == DNS_PORT && (unsigned int)ip_header->protocol == UDP) // Filter incoming packets only on DNS port
		{
			offset = get_offset_to_skip_queries(dns_data, ntohs(dns_header->total_questions)); // Offset will point over the question data
			for (int i = 0; i < ntohs(dns_header->total_answer_RRs) + ntohs(dns_header->total_authority_RRs); i++) {
				final_answer = malloc(sizeof(char) * 1200);
				domain_name = malloc(sizeof(char) * 400);
				answer_data = malloc(sizeof(char) * 400);
				answer_type = malloc(sizeof(char) * 400);

				if (domain_name == NULL || answer_data == NULL || answer_type == NULL)
				{
					free(final_answer);
					free(answer_data);
					free(answer_type);
					free(domain_name);
					free(hdr);
					free(rr_table);
					fclose(pcap_file);
					exit(EXIT_FAILURE);
				}

				get_domain_name(dns_data, offset, &domain_name, 0, 400); // Get domain name of i-answer
				offset = get_offset_to_skip_rr_name(dns_data, offset); // Get over domain name of i-answer
				get_rr_type(dns_data, offset, &rr_type); // Get type of i-answer
				get_rr_data_length(dns_data, offset, &rr_data_length); // Get data length of i-answer
				// Process specific data of i-answer
				process_rr_data(dns_data, (offset + 10), rr_type, rr_data_length, &domain_name, &final_answer, &answer_type, &answer_data, 400, rr_table);
				offset += rr_data_length + 10; // Get offset to point to next answer
			}
		}
	}
	free(hdr);
	fclose(pcap_file);
	return EXIT_SUCCESS;
}