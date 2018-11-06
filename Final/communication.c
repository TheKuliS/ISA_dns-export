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

// Checksum for UDP packet
unsigned short checksum(unsigned short *buf, int nwords) // Checksum
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

// Open new raw connection socket
int open_raw_socket()
{
	return socket(AF_PACKET, SOCK_RAW, htons(0x800));
}

// Open new udp connection socket
int open_udp_socket()
{
	return socket(AF_INET, SOCK_DGRAM, 0);
}

// Gets index of given interface
int get_interface_index(struct ifreq if_id, char* if_name, int connection_socket)
{
	memset(&if_id, 0, sizeof(struct ifreq));
	strncpy(if_id.ifr_name, if_name, strlen(if_name)+1);
	return ioctl(connection_socket, SIOCGIFINDEX, &if_id);
}

// Gets mac of given interface
int get_interface_mac(struct ifreq if_id, char* if_name, int connection_socket)
{
	memset(&if_id, 0, sizeof(struct ifreq));
	strncpy(if_id.ifr_name, if_name, strlen(if_name)+1);
	return ioctl(connection_socket, SIOCGIFHWADDR, &if_id);
}

unsigned long receive_packet(void* buffer, unsigned int packet_size, int connection_socket)
{
	memset(buffer, 0, packet_size);
	return recvfrom(connection_socket, buffer, packet_size, 0, NULL, NULL);
}

void print_ethernet_header(struct ether_header* ethernet_header) // Debug print
{
	fprintf(stdout, "\nEthernet Header:\n");
	fprintf(stdout, "\t|-Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->ether_shost[0],ethernet_header->ether_shost[1],ethernet_header->ether_shost[2],ethernet_header->ether_shost[3],ethernet_header->ether_shost[4],ethernet_header->ether_shost[5]);
	fprintf(stdout, "\t|-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->ether_dhost[0],ethernet_header->ether_dhost[1],ethernet_header->ether_dhost[2],ethernet_header->ether_dhost[3],ethernet_header->ether_dhost[4],ethernet_header->ether_dhost[5]);
	fprintf(stdout, "\t|-Protocol : %d\n",ethernet_header->ether_type);
}

void print_ip_header(struct iphdr* ip_header) // Debug print
{
	struct sockaddr_in source;
	struct sockaddr_in destination;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_header->saddr;
	memset(&destination, 0, sizeof(destination));
	destination.sin_addr.s_addr = ip_header->daddr;

	fprintf(stdout, "\nIP Header:\n");
	fprintf(stdout, "\t|-Version : %d\n",(unsigned int)ip_header->version);
	fprintf(stdout , "\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip_header->ihl,((unsigned int)(ip_header->ihl))*4);
	fprintf(stdout , "\t|-Type Of Service : %d\n",(unsigned int)ip_header->tos);
	fprintf(stdout , "\t|-Total Length : %d Bytes\n",ntohs(ip_header->tot_len));
	fprintf(stdout , "\t|-Identification : %d\n",ntohs(ip_header->id));
	fprintf(stdout , "\t|-Time To Live : %d\n",(unsigned int)ip_header->ttl);
	fprintf(stdout , "\t|-Protocol : %d\n",(unsigned int)ip_header->protocol);
	fprintf(stdout , "\t|-Header Checksum : %d\n",ntohs(ip_header->check));
	fprintf(stdout , "\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(stdout , "\t|-Destination IP : %s\n",inet_ntoa(destination.sin_addr));
}
void print_udp_header(struct udphdr* udp_header) // Debug print
{
	fprintf(stdout, "\nUDP Header:\n");
	fprintf(stdout , "\t|-Source Port : %d\n" , ntohs(udp_header->source));
	fprintf(stdout , "\t|-Destination Port : %d\n" , ntohs(udp_header->dest));
	fprintf(stdout , "\t|-UDP Length : %d\n" , ntohs(udp_header->len));
	fprintf(stdout , "\t|-UDP Checksum : %d\n" , ntohs(udp_header->check));
}

void get_timestamp(char* string_time)
{
	time_t atm;
	struct tm *ltm;

	atm = time(NULL);
	ltm = localtime(&atm);
	strftime(string_time, 79, "%Y-%m-%dT%H:%M:%SZ", ltm); // Format for syslog message
}