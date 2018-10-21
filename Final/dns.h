// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// reference:
// 'http://www.networksorcery.com/enp/protocol/dns.htm#Total%20Answer%20RRs'

#ifndef ISA_DNS_H
#define ISA_DNS_H

// Ports
#define DNS_PORT 53
#define C0 192

// DNS record types
#define A 1
#define AAAA 28
#define NS 2
#define CNAME 5
#define SOA 6
#define MX 15
#define TXT 16
#define SPF 99
#define DNSSECA 32768
#define DNSSECV 32769


struct dns_hdr
{
	uint16_t identification;
	uint16_t flags;
	uint16_t total_questions;
	uint16_t total_answer_RRs;
	uint16_t total_authority_RRs;
	uint16_t total_additional_RRs;
};

void process_rr_data(char* dns_data, unsigned int data_offset, uint16_t rr_type, uint16_t rr_data_length, char** answer_data, char** answer_type, unsigned int max_len);
void print_dns_header(struct dns_hdr* dns_header);
void get_domain_name(char* dns_data, unsigned int data_offset, char** domain_name, unsigned int index, unsigned int max_len);
void debug_data_print(unsigned char *data);
uint16_t get_offset_to_skip_queries(char* dns_queries, uint16_t total_queries);
uint16_t get_offset_to_skip_rr_name(char* dns_queries, unsigned int data_offset);
void get_rr_type(char* dns_data, unsigned int data_offset, uint16_t* rr_type);
void get_rr_data_length(char* dns_data, unsigned int data_offset, uint16_t* rr_data_length);

#endif //ISA_DNS_H
