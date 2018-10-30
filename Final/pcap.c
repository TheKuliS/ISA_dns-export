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
	struct ether_header* ethernet_header = (struct ether_header *) buffer;
	struct iphdr* ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct udphdr* udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
	struct dns_hdr* dns_header = (struct dns_hdr *) (buffer + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* dns_data = (char *) (buffer + sizeof(struct dns_hdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* domain_name; // Domain name of DNS record
	char* answer_type; // Type of resource record
	char* answer_data; // Data of specific resource record
	pcap_file = fopen(filename, "r");
	char* hdr = malloc(sizeof(pcap_hdr_t));
	fread(hdr, sizeof(pcap_hdr_t), 1, pcap_file);

	while (1) // Program has to be in loop to receive packets till someone kills the program
	{
		pcaprec_hdr_t packet_header;
		if(!fread(&packet_header, sizeof(pcaprec_hdr_t), 1, pcap_file))
			break;
		if(!fread(buffer, packet_header.incl_len, 1, pcap_file))
			break;
		//fprintf(stderr, "Main: Bytes received: %lu\n", bytes_received);
		//memset(domain_name, 0, max_len);
		//memset(answer_data, 0, max_len);
		//memset(answer_type, 0, max_len);
		uint16_t offset = 0; // Offset is a 16bit integer which is used to move in DNS data
		uint16_t rr_type; // Type of resource record
		uint16_t rr_data_length; // Data length of specific resource record

		//print_ip_header(ip_header);

		//UDP
		if(ntohs(udp_header->source) == DNS_PORT && (unsigned int)ip_header->protocol == UDP) // Filter incoming packets only on DNS port
		{
			//print_ethernet_header(ethernet_header);
			//print_udp_header(udp_header);
			//print_dns_header(dns_header);
			//fprintf(stderr, "Main: data offset: %u\n", offset);
			//debug_data_print(dns_data);
			offset = get_offset_to_skip_queries(dns_data, ntohs(dns_header->total_questions)); // Offset will point over the question data
			//fprintf(stderr, "Main: skipped header offset: %u\n", offset);
			//fprintf(stderr, "Main: skip query offset: %u\n", offset);
			//fprintf(stderr, "Main: answer + authority: %d\n", (ntohs(dns_header->total_answer_RRs) + ntohs(dns_header->total_authority_RRs)));
			for (int i = 0; i < ntohs(dns_header->total_answer_RRs); i++) {
				domain_name = malloc(sizeof(char) * 1000);
				answer_data = malloc(sizeof(char) * 50);
				answer_type = malloc(sizeof(char) * 50);
				//memset(domain_name, 0, 200);
				//memset(answer_data, 0, 100);
				//memset(answer_type, 0, 100);

				if (domain_name == NULL || answer_data == NULL || answer_type == NULL)
				{
					free(answer_data);
					free(answer_type);
					free(domain_name);
					free(rr_table);
					exit(EXIT_FAILURE);
				}

				//fprintf(stderr, "Main: answer index: %d\n", i);
				//fprintf(stderr, "before domain_name: %p\n", domain_name);
				//debug_data_print(dns_data + offset);
				get_domain_name(dns_data, offset, &domain_name, 0, 1000); // Get domain name of i-answer
				//fprintf(stderr, "Main: Domain name: %s | %d\n", domain_name, strlen(domain_name));
				//fprintf(stderr, "after domain_name: %p\n", domain_name);

				offset = get_offset_to_skip_rr_name(dns_data, offset); // Get over domain name of i-answer
				//fprintf(stderr, "Main: skipped rr name offset + 10: %u\n", offset + 10);
				get_rr_type(dns_data, offset, &rr_type); // Get type of i-answer
				//fprintf(stderr, "Main: RR type: %d\n", rr_type);
				//debug_data_print(dns_data + offset);
				get_rr_data_length(dns_data, offset, &rr_data_length); // Get data length of i-answer
				//fprintf(stderr, "Main: RR data length: %d\n", rr_data_length);
				// Process specific data of i-answer
				process_rr_data(dns_data, (offset + 10), rr_type, rr_data_length, &domain_name, &answer_type, &answer_data, 50, rr_table);
				offset += rr_data_length + 10; // Get offset to point to next answer
				//fprintf(stderr, "Main: skipped answer offset: %u\n", offset);
				//fprintf(stderr, "Main: Answer: %s | %d\n", domain_name, strlen(domain_name));


				//fprintf(stderr, "_____________________________\n");
			}
			//fprintf(stderr, "_____________________________//\n");
		}
	}

	free(hdr);
	fclose(pcap_file);
	return 0;
}