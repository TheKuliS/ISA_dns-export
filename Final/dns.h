// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// reference:
// 'http://www.networksorcery.com/enp/protocol/dns.htm#Total%20Answer%20RRs'
// Base 64 encode decode: 'https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/'

#ifndef ISA_DNS_H
#define ISA_DNS_H

// Ports
#define DNS_PORT 53

// DNS record types
#define A 1
#define AAAA 28
#define NS 2
#define CNAME 5
#define SOA 6
#define PTR 12
#define MX 15
#define TXT 16
#define DS 43
#define RRSIG 46
#define NSEC 47
#define DNSKEY 48
#define NSEC3 50
#define DNSSECA 32768
#define DNSSECV 32769

// Mask
#define MASK 0xc000

#include "hash_table.h"

/*
 * DNS header
 */
struct dns_hdr
{
	uint16_t identification;
	uint16_t flags;
	uint16_t total_questions;
	uint16_t total_answer_RRs;
	uint16_t total_authority_RRs;
	uint16_t total_additional_RRs;
};

/*
 * Help function for key encoding that returns new size that needs to be allocated.
 */
size_t b64_encoded_size(size_t inlen);

/*
 * Procedure that encodes DNS key.
 */
void b64_encode(const unsigned char *in, char** out, size_t len);

/*
 * Function that processes DNS records and sends them to syslog server if given.
 */
int process_dns_packet(char* buffer, tHTable* rr_table, int connection_socket, int syslog_socket,
                       struct sockaddr_in server_address, int seconds, int sflag, char* hostname, int ip_version,
                       struct sockaddr_in6 server_address6);
/*
 * Procedure that processes DNS record based on its type.
 */
void process_rr_data(char* dns_data, unsigned int data_offset, uint16_t rr_type, uint16_t rr_data_length, char** domain_name,
                     char** final_answer, char** answer_type, char** answer_data, unsigned int max_len, tHTable* rr_table);

/*
 * Debug print for DNS header.
 */
void print_dns_header(struct dns_hdr* dns_header);

/*
 * Recursive procedure that gets domain name of processed DNS record.
 */
void get_domain_name(char* dns_data, unsigned int data_offset, char** domain_name, unsigned int index, unsigned int max_len);

/*
 * Debug print for DNS data.
 */
void debug_data_print(unsigned char *data);

/*
 * Function that counts and returns offset which needs to be skipped to process first RR answer.
 */
uint16_t get_offset_to_skip_queries(char* dns_queries, uint16_t total_queries);

/*
 * Function that dynamically skips domain name of RR answer.
 */
uint16_t get_offset_to_skip_rr_name(char* dns_queries, unsigned int data_offset);

/*
 * Procedure that gets type of currently processed RR answer.
 */
void get_rr_type(char* dns_data, unsigned int data_offset, uint16_t* rr_type);

/*
 * Procedure that gets data length of currently processed RR answer.
 */
void get_rr_data_length(char* dns_data, unsigned int data_offset, uint16_t* rr_data_length);

#endif //ISA_DNS_H
