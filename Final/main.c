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
	fprintf(stderr, "Main: Program started...\n");
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

	fprintf(stderr, "Main: Interface: %s\n", if_name);

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
	struct ifreq if_id;
	struct ifreq if_mac;
	char buffer[BUFFER_SIZE];
	struct ether_header* ethernet_header = (struct ether_header *) buffer; // Ethernet header
	struct iphdr* ip_header = (struct iphdr *) (buffer + sizeof(struct ether_header)); // IP header
	struct udphdr* udp_header = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header)); // UDP header
	struct dns_hdr* dns_header = (struct dns_hdr *) (buffer + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
	char* dns_data = (char *) (buffer + sizeof(struct dns_hdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));

	// Open RAW socket to send on
	/*
	if ((connection_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		fprintf(stderr, "Creating socket failed.\n");
		exit(EXIT_FAILURE);
	}
	*/

	connection_socket = open_raw_socket();

	fprintf(stderr, "Main: Connection socket number: %i\n", connection_socket);

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
		char* query_name = malloc(sizeof(char) * 50);
		if (query_name == NULL)
		{
			exit(EXIT_FAILURE);
		}

		if(ntohs(udp_header->source) == DNS_PORT)
		{
			//print_ethernet_header(ethernet_header);
			//print_ip_header(ip_header);
			fprintf(stdout , "\t|-Identification : %d\n",ntohs(ip_header->id));
			//print_udp_header(udp_header);
			//print_dns_header(dns_header);
			//printf("size of dns_hdr: %i\tsize of dns_header: %i\tsize of dns_data: %i\n", sizeof(struct dns_hdr), sizeof(dns_header),
			  //    sizeof(dns_data));
			get_query_name(dns_data, 0, &query_name, 0, 50);
			fprintf(stderr, "Main: Query name: %s\n", query_name);
			free(query_name);
		}

	}

	close(connection_socket);
	fprintf(stdout, "Connection closed, program ended successfully.\n");

	return 0;
}