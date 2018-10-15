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


void debug_data_print(unsigned char *data)
{
	printf("Dns: byte: \n");
	for (int i = 0; i < 8; i++)
	{
		printf("%#2x ", data[i]);
	}
	printf("\n");
}


void process_dns_record(struct dns_hdr* dns_header)
{

}

void print_dns_header(struct dns_hdr* dns_header)
{
	fprintf(stderr, "DNS Header:\n");
	fprintf(stdout, "\t|-Identification : %.4x\n", ntohs(dns_header->identification));
	/*fprintf(stdout, "\t|-Total questions : %hu\n", ntohs(dns_header->total_questions));
	fprintf(stdout, "\t|-Total answer RRs : %hu\n", ntohs(dns_header->total_answer_RRs));
	fprintf(stdout, "\t|-Total authority RRs : %hu\n", ntohs(dns_header->total_authority_RRs));
	fprintf(stdout, "\t|-Total additional RRs : %hu\n", ntohs(dns_header->total_additional_RRs));*/
}

void get_query_name(char* dns_data, unsigned int data_offset, char** query_name, unsigned int index, unsigned int max_len)
{
	char* name_length = (char*) (dns_data + data_offset); // String length
	unsigned int new_offset = *name_length + data_offset + 1; // Offset that will move over processed string

	//fprintf(stderr, "Dns: data offset: %u\n", data_offset);
	//fprintf(stderr, "Dns: new data offset: %u\n", new_offset);
	//debug_data_print(dns_data);
	//debug_data_print(name_length);

	if ((index + *name_length) >= max_len)
	{
		*query_name = realloc(*query_name, sizeof(char) * (max_len + 20));

		if (query_name == NULL)
		{
			free(*query_name);
			exit(EXIT_FAILURE);
		}

		max_len = max_len + 20;
	}

	for (int i = 0; i <= *name_length; i++)
	{
		//fprintf(stderr, "Dns: i: %i | index + i: %i | data_offset + i + 1: %i\n", i, (index + i), (data_offset + i + 1));
		if (i == *name_length)
		{
			if(dns_data[data_offset + i + 1] == '\0')
				(*query_name)[index + i] = '\0';
			else
				(*query_name)[index + i] = '.';
		}
		else
		{
			(*query_name)[index + i] = dns_data[data_offset + i + 1];
		}
	}

	//fprintf(stderr, "Dns: part of query name: %s\n", *query_name);
	index = index + *name_length + 1;
	//fprintf(stderr, "Dns: new index: %u\n", index);

	if ((*query_name)[index-1] != '\0')
	{
		get_query_name(dns_data, new_offset, query_name, index, max_len);
	}
}