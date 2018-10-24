// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#include <stdio.h>
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


void debug_data_print(unsigned char *data)
{
	printf("Dns: byte: \n");
	for (int i = 0; i < 8; i++)
	{
		printf("%#2x ", data[i]);
	}
	printf("\n");
}


void process_rr_data(char* dns_data, unsigned int data_offset, uint16_t rr_type, uint16_t rr_data_length, char** answer_data, char** answer_type, unsigned int max_len)
{
	//debug_data_print(dns_data);
	if (rr_type == A)
	{
		strcpy(*answer_type, "A");
		inet_ntop(AF_INET, (dns_data + data_offset), *answer_data, INET_ADDRSTRLEN);
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == AAAA)
	{
		strcpy(*answer_type, "AAAA");
		//inet_ntop(AF_INET6, (dns_data + data_offset), *answer_data, INET6_ADDRSTRLEN);
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == NS)
	{
		strcpy(*answer_type, "NS");
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == CNAME)
	{
		strcpy(*answer_type, "CNAME");
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == SOA)
	{
		strcpy(*answer_type, "SOA");
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		sprintf(*answer_data, "%s %s %d %d %d %d %d", *answer_data, *answer_type, (dns_data + data_offset + ))
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == MX)
	{
		sprintf(*answer_type, "MX %d", *((uint16_t*) dns_data));
		get_domain_name(dns_data, (data_offset + 2), answer_data, 0, max_len);
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == TXT)
	{
		strcpy(*answer_type, "TXT");
		for (int i = 0; i < rr_data_length; ++i) {
			(*answer_data)[i] = dns_data[data_offset + i];
		}
		//strcat(*answer_type, *answer_data);
	}
	else if (rr_type == SPF)
	{
		strcpy(*answer_type, "SPF");
	}
	else if (rr_type == DNSSECA)
	{
		strcpy(*answer_type, "DNSSEC");
	}
	else if (rr_type == DNSSECV)
	{
		strcpy(*answer_type, "DNSSEC");
	}
}

void print_dns_header(struct dns_hdr* dns_header)
{
	fprintf(stderr, "DNS Header:\n");
	fprintf(stderr, "\t|-Identification : %04x\n", ntohs(dns_header->identification));
	fprintf(stderr, "\t|-Total questions : %hu\n", ntohs(dns_header->total_questions));
	fprintf(stderr, "\t|-Total answer RRs : %hu\n", ntohs(dns_header->total_answer_RRs));
	fprintf(stderr, "\t|-Total authority RRs : %hu\n", ntohs(dns_header->total_authority_RRs));
	fprintf(stderr, "\t|-Total additional RRs : %hu\n", ntohs(dns_header->total_additional_RRs));
}

void get_domain_name(char* dns_data, unsigned int data_offset, char** domain_name, unsigned int index, unsigned int max_len)
{
	uint8_t* name_length = (uint8_t*) dns_data + data_offset; // String length
	uint8_t new_offset = *name_length + data_offset + 1; // Offset that will move over processed string

	//fprintf(stderr, "Dns: data offset: %u\n", data_offset);
	//fprintf(stderr, "Dns: new data offset: %u\n", new_offset);
	//debug_data_print(dns_data);
	//debug_data_print(name_length);

	//fprintf(stderr, "*name_length = %d\n", (uint8_t) *name_length);
	if ((uint8_t) *name_length == 0)
	{
		//fprintf(stderr, "DOMAIN NAME END\n");
		(*domain_name)[index - 1] = '\0';
		return;
	}


	if ((uint8_t) *name_length == C0)
	{
		//fprintf(stderr, "Dns: IF\n");
		new_offset = (uint8_t) dns_data[data_offset + 1] - 12;
		//fprintf(stderr, "Dns: new data offset: %u\n", new_offset);
		get_domain_name(dns_data, new_offset, domain_name, index, max_len);
		return;
	}

	if ((index + *name_length + 1) >= max_len)
	{
		//fprintf(stderr, "*name_length = %d\n", *name_length);
		//fprintf(stderr, "index = %d\n", index);
		//fprintf(stderr, "index + *name_length = %d >= %d\n", (index + *name_length + 1), max_len);
		max_len += (index + *name_length + 1);
		//fprintf(stderr, "Dns: new max_len: %u\n", max_len);
		(*domain_name) = realloc((*domain_name), sizeof(char) * max_len);

		if ((*domain_name) == NULL)
		{
			//fprintf(stderr, "Dns: REALLOC FAIL!!!\n");
			exit(EXIT_FAILURE);
		}
	}

	//fprintf(stderr, "Dns: ELSE\n");
	for (int i = 0; i <= *name_length; i++)
	{
		//fprintf(stderr, "Dns: i: %i | index + i: %i | data_offset + i + 1: %i\n", i, (index + i), (data_offset + i + 1));
		if (i == *name_length)
		{
			(*domain_name)[index + i] = '.';
		}
		else
		{
			(*domain_name)[index + i] = dns_data[data_offset + i + 1];
		}
	}

	//fprintf(stderr, "Dns: part of query name: %s\n", *query_name);
	index = (index + *name_length + 1);
	//fprintf(stderr, "Dns: new index: %u\n", index);
	get_domain_name(dns_data, new_offset, domain_name, index, max_len);
	return;
}

uint16_t get_offset_to_skip_queries(char* dns_queries, uint16_t total_queries)
{
	uint16_t offset = 0;
	for (int i = 0; i < total_queries; ++i) {
		while (dns_queries[offset] != '\0')
			offset++;
		offset = offset + 4;
	}
	return (offset +1);
}

uint16_t get_offset_to_skip_rr_name(char* dns_queries, unsigned int data_offset)
{
	//fprintf(stderr, "Dns: dns_queries[data_offset] = %d | %d\n", (uint8_t) dns_queries[data_offset], C0);
	while ((uint8_t) dns_queries[data_offset] != C0)
	{
		if ((uint8_t) dns_queries[data_offset] == 0)
		{
			data_offset--;
			break;
		}
		data_offset++;
	}
	return (data_offset + 2);
}

void get_rr_type(char* dns_data, unsigned int data_offset, uint16_t* rr_type)
{
	memset(rr_type, 0, sizeof(uint16_t));
	memcpy(rr_type, (dns_data + data_offset), sizeof(uint16_t));
	*rr_type = ntohs(*rr_type);
}

void get_rr_data_length(char* dns_data, unsigned int data_offset, uint16_t* rr_data_length)
{
	memset(rr_data_length, 0, sizeof(uint16_t));
	memcpy(rr_data_length, (dns_data + data_offset + 8), sizeof(uint16_t));
	*rr_data_length = ntohs(*rr_data_length);
}