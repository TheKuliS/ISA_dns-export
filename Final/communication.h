// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#ifndef ISA_COMMUNICATION_H
#define ISA_COMMUNICATION_H

#define BUFFER_SIZE 1500
#define TCP 6
#define UDP 17
#define SYSLOG_PORT 514

#include <net/ethernet.h>

/*
 * Checksum of UDP packet.
 */
unsigned short checksum(unsigned short *buf, int nwords);

/*
 * Creates raw socket.
 */
int open_raw_socket();

/*
 * Creates udp socket of given version (IPv4 or IPv6).
 */
int open_udp_socket(int version);

/*
 * Function for receiving a message for specific socket.
 */
unsigned long receive_packet(void* buffer, unsigned int packet_size, int connection_socket);

/*
 * Procedure for debug print of ethernet header.
 */
void print_ethernet_header(struct ether_header* ethernet_header);

/*
 * Procedure for debug print of ip header.
 */
void print_ip_header(struct iphdr* ip_header);

/*
 * Procedure for debug print of udp header.
 */
void print_udp_header(struct udphdr* udp_header);

/*
 * Procedure that creates timestamp formated for syslog message.
 */
void get_timestamp(char* string_time);

#endif //ISA_COMMUNICATION_H
