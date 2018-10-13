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
	return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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