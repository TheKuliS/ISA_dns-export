// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// reference:
// 'http://www.networksorcery.com/enp/protocol/dns.htm#Total%20Answer%20RRs'

#ifndef ISA_DNS_H
#define ISA_DNS_H

// Ports
#define DNS_PORT 53

// DNS record types
#define A 1
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
	uint16_t query;
	uint16_t total_questions;
	uint16_t total_answer_RRs;
	uint16_t total_authority_RRs;
	uint16_t total_additional_RRs;
};

struct dns_data
{

};

void process_dns_record(struct dns_hdr* dns_header);
#endif //ISA_DNS_H
