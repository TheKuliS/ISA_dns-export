// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#include <stdio.h>
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

int main(int argc, char** argv)
{
	fprintf(stdout, "Program started...\n");
	/*
	// Input parameters parsing
	if (argc == 1)
	{
		fprintf(stdout, "Program has been executed without input parameters\nProgram ended successfully\n");
		exit(EXIT_SUCCESS);
	}
	*/

	// Input parameters variables
	bool rflag = 0;
	bool iflag = 0;
	bool sflag = 0;
	bool tflag = 0;
	char* file_name = NULL;
	char* if_name = "eth0";
	char* syslog_server = NULL;
	time_t seconds = 60;
	opterr = 0;
	int arg = 0;

	fprintf(stdout, "Interface: %s\n", if_name);

	/*
	while ((arg = getopt(argc, argv, "r:i:s:t:")) != -1)
	{
		switch (arg)
		{
			case 'r':
				rflag = 1;
				file_name = optarg;
				break;

			case 'i':
				iflag = 1;
				if_name = optarg;
				break;

			case 's':
				sflag = 1;
				syslog_server = optarg;
				break;

			case 't':
				tflag = 1;
				seconds = optarg;
				break;
		}
	}

	if (rflag == 1 && iflag == 1)
	{
		fprintf(stderr, "Program can analyze only a file or an interface at once\n");
		exit(EXIT_FAILURE);
	}
	*/


	// Socket variables
	int connection_socket;
	int sock_opt = 1;
	struct sockaddr_in source;
	struct sockaddr_in destination;
	struct ifreq if_id;
	struct ifreq if_mac;
	char buffer[BUFFER_SIZE];
	struct ether_header* ethernet_header = (struct ether_header *) buffer; // Ethernet header
	struct iphdr* ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header)); // IP header
	struct udphdr* udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header)); // UDP header
	struct dns_hdr* dns_header = (struct dns_hdr *) (buffer + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));

	// Open RAW socket to send on
	/*
	if ((connection_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		fprintf(stderr, "Creating socket failed.\n");
		exit(EXIT_FAILURE);
	}
	*/

	connection_socket = open_raw_socket();

	fprintf(stdout, "Connection socket number: %i\n", connection_socket);

	if (connection_socket == -1)
	{
		fprintf(stderr, "Creating socket failed.\n");
		exit(EXIT_FAILURE);
	}
/*
	// Get the index of the interface to send on
	if (get_interface_index(if_id, if_name, connection_socket) < 0)
	{
		fprintf(stderr, "Retrieving of interface index failed.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Interface index: %i.\n", if_id.ifr_ifindex);

	// Get the mac of the interface to send on
	if (get_interface_mac(if_mac, if_name, connection_socket) < 0)
	{
		fprintf(stderr, "Retrieving of interface mac failed.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Interface mac successfully processed.\n");

	// Allow reuse of the socket
	if (setsockopt(connection_socket, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof sock_opt) == -1) {
		fprintf(stderr, "Reusing socket failed.\n");
		close(connection_socket);
		exit(EXIT_FAILURE);
	}

	// Bind socket to device
	if (setsockopt(connection_socket, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)+1) == -1)
	{
		fprintf(stderr, "Binding socket failed.\n");
		close(connection_socket);
		exit(EXIT_FAILURE);
	}

*/
	while (1)
	{
		unsigned long bytes_received = receive_packet(buffer, BUFFER_SIZE, connection_socket);

		if(ntohs(udp_header->source) == DNS_PORT)
		{
			fprintf(stdout, "\nEthernet Header:\n");
			fprintf(stdout, "\t|-Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->ether_shost[0],ethernet_header->ether_shost[1],ethernet_header->ether_shost[2],ethernet_header->ether_shost[3],ethernet_header->ether_shost[4],ethernet_header->ether_shost[5]);
			fprintf(stdout, "\t|-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header->ether_dhost[0],ethernet_header->ether_dhost[1],ethernet_header->ether_dhost[2],ethernet_header->ether_dhost[3],ethernet_header->ether_dhost[4],ethernet_header->ether_dhost[5]);
			fprintf(stdout, "\t|-Protocol : %d\n",ethernet_header->ether_type);

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

			fprintf(stdout, "\nUDP Header:\n");
			fprintf(stdout , "\t|-Source Port : %d\n" , ntohs(udp_header->source));
			fprintf(stdout , "\t|-Destination Port : %d\n" , ntohs(udp_header->dest));
			fprintf(stdout , "\t|-UDP Length : %d\n" , ntohs(udp_header->len));
			fprintf(stdout , "\t|-UDP Checksum : %d\n" , ntohs(udp_header->check));
		}

	}

	close(connection_socket);
	fprintf(stdout, "Connection closed, program ended successfully.\n");

	return 0;
}