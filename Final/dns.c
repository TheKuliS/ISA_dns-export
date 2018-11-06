// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// reference:
// 'http://www.networksorcery.com/enp/protocol/dns.htm#Total%20Answer%20RRs'
// Base 64 encode decode: 'https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/'

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


const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	//fprintf(stderr, "Dns: inlen: %d | ret: %d\n", inlen, ret);
	return ret;
}

void b64_encode(const unsigned char *in, char** out, size_t len) // DNSKEY encoding
{
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return;

	elen = b64_encoded_size(len);
	(*out) = realloc((*out), sizeof(char) * (elen+1));

	if ((*out) == NULL)
	{
		exit(EXIT_FAILURE);
	}

	(*out)[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		(*out)[j]   = b64chars[(v >> 18) & 0x3F];
		(*out)[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			(*out)[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			(*out)[j+2] = '=';
		}
		if (i+2 < len) {
			(*out)[j+3] = b64chars[v & 0x3F];
		} else {
			(*out)[j+3] = '=';
		}
	}
}

void debug_data_print(unsigned char *data) // Debug print
{
	//printf("Dns: byte: \n");
	for (int i = 0; i < 8; i++)
	{
		printf("%#2x ", data[i]);
	}
	printf("\n");
}

int process_dns_packet(char* buffer, tHTable* rr_table, int connection_socket, int syslog_socket,
		struct sockaddr_in server_address, int seconds, int sflag, char* hostname, int ip_version,
        struct sockaddr_in6 server_address6)
{
	struct iphdr* ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct udphdr* udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
	struct dns_hdr* dns_header = (struct dns_hdr *) (buffer + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* dns_data = (char *) (buffer + sizeof(struct dns_hdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* final_answer; // Final string
	char* domain_name; // Domain name of DNS record
	char* answer_type; // Type of resource record
	char* answer_data; // Data of specific resource record
	time_t time_start;
	time_t time_end;
	double time_difference;
	time_start = time(NULL);


	while (1) // Program has to be in loop to receive packets till someone kills the program
	{
		time_end = time(NULL);
		if ((time_difference = difftime(time_end, time_start)) >= (double) seconds && sflag == 1)
		{
			for(int i = 0; i < MAX_HTSIZE; i++)
			{
				tHTItem* processed_item = (*rr_table)[i];
				while (processed_item != NULL)
				{
					char string_time[80];
					get_timestamp(string_time);
					sprintf(buffer, "<134>1 %s %s dns-export - - - %s %d", string_time, hostname,
							processed_item->key, processed_item->data);
					if (ip_version == AF_INET)
						sendto(syslog_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_address, sizeof(struct sockaddr_in));
					else if (ip_version == AF_INET6)
						sendto(syslog_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_address6, sizeof(struct sockaddr_in6));
					memset(buffer, 0, BUFFER_SIZE);
					processed_item = processed_item->ptrnext;
				}
			}
			time_start = time(NULL);
		}
		//memset(buffer, 0, BUFFER_SIZE);
		int bytes_received = receive_packet(buffer, BUFFER_SIZE, connection_socket);
		if (bytes_received == -1)
			continue;

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
			offset = get_offset_to_skip_queries(dns_data, ntohs(dns_header->total_questions)); // Offset will point over the question data
			//fprintf(stderr, "Main: skipped header offset: %u\n", offset);
			//fprintf(stderr, "Main: skip query offset: %u\n", offset);
			//fprintf(stderr, "Main: answer + authority: %d\n", (ntohs(dns_header->total_answer_RRs) + ntohs(dns_header->total_authority_RRs)));
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
					free(rr_table);
					//close(connection_socket);
					exit(EXIT_FAILURE);
				}

				//fprintf(stderr, "Main: answer index: %d\n", i);
				//fprintf(stderr, "before domain_name: %p\n", domain_name);
				//debug_data_print(dns_data + offset);
				get_domain_name(dns_data, offset, &domain_name, 0, 400); // Get domain name of i-answer
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
				process_rr_data(dns_data, (offset + 10), rr_type, rr_data_length, &domain_name, &final_answer, &answer_type, &answer_data, 400, rr_table);
				offset += rr_data_length + 10; // Get offset to point to next answer
				//fprintf(stderr, "Main: skipped answer offset: %u\n", offset);
				//fprintf(stderr, "Main: Answer: %s | %d\n", domain_name, strlen(domain_name));


				//fprintf(stderr, "_____________________________\n");
			}
			//fprintf(stderr, "_____________________________//\n");
		}
	}
	return 0;
}

void process_rr_data(char* dns_data, unsigned int data_offset, uint16_t rr_type, uint16_t rr_data_length, char** domain_name,
                     char** final_answer, char** answer_type, char** answer_data, unsigned int max_len, tHTable* rr_table)
{
	if (rr_type == A)
	{
		inet_ntop(AF_INET, (dns_data + data_offset), *answer_data, INET_ADDRSTRLEN);
		sprintf(*final_answer, "%s A %s", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == AAAA)
	{
		inet_ntop(AF_INET6, (dns_data + data_offset), *answer_data, INET6_ADDRSTRLEN);
		sprintf(*final_answer, "%s AAAA %s", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == NS)
	{
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		sprintf(*final_answer, "%s NS %s", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == CNAME)
	{
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		sprintf(*final_answer, "%s CNAME %s", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == PTR)
	{
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		sprintf(*final_answer, "%s PTR %s", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == SOA)
	{
		get_domain_name(dns_data, data_offset, answer_type, 0, max_len);
		data_offset = get_offset_to_skip_rr_name(dns_data, data_offset);
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		data_offset = get_offset_to_skip_rr_name(dns_data, data_offset);
		//debug_data_print(dns_data + data_offset);

		sprintf(*final_answer, "%s SOA \"%s %s %u %u %u %u %u\"", *domain_name, *answer_type, *answer_data, ntohl(*((uint32_t*) (dns_data + data_offset))),
		        ntohl(*((uint32_t*) (dns_data + data_offset + 4))), ntohl(*((uint32_t*) (dns_data + data_offset + 8))),
		        ntohl(*((uint32_t*) (dns_data + data_offset + 12))), ntohl(*((uint32_t*) (dns_data + data_offset + 16))));
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == MX)
	{
		get_domain_name(dns_data, (data_offset + 2), answer_data, 0, max_len);
		sprintf(*final_answer, "%s MX \"%d %s\"", *domain_name, ntohs(*((uint16_t*) (dns_data + data_offset))), *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == TXT)
	{
		if (rr_data_length >= max_len)
		{
			max_len += rr_data_length;
			//fprintf(stderr, "Dns: new max_len: %u\n", max_len);
			(*answer_data) = realloc((*answer_data), sizeof(char) * max_len);

			if ((*answer_data) == NULL)
			{
				exit(EXIT_FAILURE);
			}
		}

		//debug_data_print(dns_data + data_offset);
		uint8_t* text_length = (uint8_t*) dns_data + data_offset;
		memset(*answer_data, 0, max_len);

		for (int i = 0; i < *text_length; i++) {
			(*answer_data)[i] = dns_data[data_offset + i + 1];
			//fprintf(stderr, "%c", dns_data[data_offset + i + 1]);
		}
		sprintf(*final_answer, "%s TXT \"%s\"", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == DS)
	{

		for (int i = 0; i < (rr_data_length - 4); i++) {
			sprintf((*answer_data) + i * 2, "%02X", ((uint8_t*) dns_data + data_offset + 4)[i]);
		}
		sprintf(*final_answer, "%s DS \"%d %d %d %s\"", *domain_name, ntohs(*((uint16_t*) (dns_data + data_offset))),
		        *((uint8_t*) (dns_data + data_offset + 2)), *((uint8_t*) (dns_data + data_offset + 3)),
		        *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == RRSIG)
	{
		get_domain_name(dns_data, (data_offset + 18), answer_type, 0, max_len);
		//debug_data_print(dns_data);
		//debug_data_print((dns_data + data_offset + 18));
		//fprintf(stderr, "Dns: RRSIG name: %s\n", *answer_type);
		unsigned int new_offset = get_offset_to_skip_rr_name((dns_data + data_offset + 18), data_offset);
		//fprintf(stderr, "Dns: new: %d | data len: %d\n", new_offset, (rr_data_length - 18 - (new_offset - data_offset)));
		b64_encode((const unsigned char*)(dns_data + new_offset + 18), answer_data, (rr_data_length - 18 - (new_offset - data_offset)));
		sprintf(*final_answer, "%s RRSIG \"%d %d %d %u %u %u %d %s %s\"", *domain_name, ntohs(*((uint16_t*) (dns_data + data_offset))),
		        *((uint8_t*) (dns_data + data_offset + 2)), *((uint8_t*) (dns_data + data_offset + 3)),
		        ntohl(*((uint32_t*) (dns_data + data_offset + 4))), ntohl(*((uint32_t*) (dns_data + data_offset + 8))),
		        ntohl(*((uint32_t*) (dns_data + data_offset + 12))), ntohs(*((uint16_t*) (dns_data + data_offset + 16))),
		        *answer_type, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == NSEC)
	{
		get_domain_name(dns_data, data_offset, answer_data, 0, max_len);
		sprintf(*final_answer, "%s NSEC \"%s\"", *domain_name, *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}
	else if (rr_type == DNSKEY)
	{
		//memset(*answer_data, 0, max_len);
		b64_encode((const unsigned char*)(dns_data + data_offset + 4), answer_data, (rr_data_length - 4));
		//fprintf(stderr, "Dns: key strlen: %d\n", strlen(*answer_data));

		sprintf(*final_answer, "%s DNSKEY \"%d %d %d %s\"", *domain_name, ntohs(*((uint16_t*) (dns_data + data_offset))),
		        *((uint8_t*) (dns_data + data_offset + 2)), *((uint8_t*) (dns_data + data_offset + 3)), *answer_data);
		ht_process_rr(rr_table, *final_answer);
	}

	free(*domain_name);
	free(*answer_data);
	free(*answer_type);
}

void print_dns_header(struct dns_hdr* dns_header) // Debug print
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
	unsigned int new_offset = *name_length + data_offset + 1; // Offset that will move over processed string

	//fprintf(stderr, "Dns: data offset: %u\n", data_offset);
	//fprintf(stderr, "Dns: new data offset: %u\n", new_offset);
	//debug_data_print((unsigned char*)dns_data);
	//debug_data_print(name_length);

	//fprintf(stderr, "*name_length = %d\n", (uint8_t) *name_length);
	if (*name_length == 0)
	{
		if (index == 0)
		{
			(*domain_name)[index] = '\0';
		}
		else
		{
			(*domain_name)[index - 1] = '\0';
		}
		//fprintf(stderr, "Dns: Index - 1: %d \n", index - 1);
		return;
	}

	//debug_data_print(name_length);
	//fprintf(stderr, "Dns: compared 2 bytes: %d | AND res: %d | %d\n", *((uint16_t*) name_length), (*((uint16_t*) name_length) & 0b1100000000000000), 0b1100000000000000);
	if ((ntohs(*((uint16_t*) name_length)) & MASK) == MASK)
	{
		//fprintf(stderr, "Dns: IF\n");
		//fprintf(stderr, "Dns: xor 2 bytes: %d \n", ((ntohs(*((uint16_t*) name_length)) ^ 0b1100000000000000));
		new_offset = (ntohs(*((uint16_t*) name_length)) ^ MASK) - 12;
		//fprintf(stderr, "Dns: new data offset: %u\n", new_offset);
		get_domain_name(dns_data, new_offset, domain_name, index, max_len);
		return;
	}

	if ((index + *name_length + 1) >= max_len)
	{
		//fprintf(stderr, "*name_length = %d\n", *name_length);
		//fprintf(stderr, "Dns: index = %d\n", index);
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
	for (int i = 0; i < total_queries; i++) {
		while (*((uint8_t*) dns_queries + offset) != 0)
			offset++;
		offset = offset + 4;
	}
	return (offset +1);
}

uint16_t get_offset_to_skip_rr_name(char* dns_queries, unsigned int data_offset)
{
	while ((*((uint8_t*) (dns_queries + data_offset)) & 0xc0) != 0xc0)
	{
		if (*((uint8_t*) dns_queries + data_offset) == 0)
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