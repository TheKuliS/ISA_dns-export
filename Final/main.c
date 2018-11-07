// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#define _BSD_SOURCE

#include <stdio.h>
#include <signal.h>
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
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <time.h>
#include <sys/time.h>
#include <getopt.h>
#include "communication.h"
#include "dns.h"
#include "hash_table.h"
#include "pcap.h"

tHTable* rr_table; // Hash table of resource records

// SIGUSR1 handler
void my_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		ht_foreach(rr_table, ht_print_item);
		fprintf(stdout, "\n");
	}
	return;
}

int main(int argc, char** argv)
{
	fprintf(stderr, "Program started...\n");

	// Input parameters parsing
	if (argc == 1)
	{
		fprintf(stderr, "Program has been executed without input parameters\nProgram ended successfully\n");
		exit(EXIT_SUCCESS);
	}

	// Input parameters variables
	int rflag = 0;
	int iflag = 0;
	int sflag = 0;
	int tflag = 0;
	char* file_name = NULL;
	char* if_name = NULL;
	char* syslog_server = NULL;
	int seconds = 60;
	opterr = 0;
	int arg = 0;
	int result = EXIT_SUCCESS;

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
				seconds = atoi(optarg);
				break;
			default:
				fprintf(stderr, "Unknown parameter was passed.\nUsage: dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]\n");
				exit(EXIT_FAILURE);
		}
	}

	if (rflag == 1 && iflag == 1)
	{
		fprintf(stderr, "Program can analyze only a file or an interface at once\n");
		exit(EXIT_FAILURE);
	}

	if (rflag == 1 && tflag == 1)
	{
		fprintf(stderr, "Parameters -r and -t can't be active at once\n");
		exit(EXIT_FAILURE);
	}

	// Socket variables
	int syslog_socket;
	int ip_version = 0;
	struct sockaddr_in server_address;
	struct sockaddr_in6 server_address6;
	struct hostent* server;
	char hostname[256];

	if (sflag)
	{
		// Get server info
		if((server = gethostbyname(syslog_server)) != NULL)
		{
			memset(&server_address, 0, sizeof(server_address)); // Zeroing server_address
			server_address.sin_family = AF_INET; // IPv4
			server_address.sin_port = htons(SYSLOG_PORT); // Port number
			memcpy((char *)&server_address.sin_addr.s_addr, (char *)server->h_addr_list[0], server->h_length); // server_address initial
			syslog_socket = open_udp_socket(AF_INET);

			if (syslog_socket <= 0) // If opening socket failed
			{
				fprintf(stderr, "Creating socket failed.\n");
				close(syslog_socket);
				exit(EXIT_FAILURE);
			}
			ip_version = AF_INET;
		}
		else
		{
			memset(&server_address6, 0, sizeof(server_address6)); // Zeroing server_address
			server_address6.sin6_family = AF_INET6; // IPv6
			server_address6.sin6_port = htons(SYSLOG_PORT); // Port number
			inet_pton(AF_INET6, syslog_server, (char *)&server_address6.sin6_addr.s6_addr);
			syslog_socket = open_udp_socket(AF_INET6);

			if (syslog_socket <= 0) // If opening socket failed
			{
				fprintf(stderr, "Creating socket failed.\n");
				close(syslog_socket);
				exit(EXIT_FAILURE);
			}
			ip_version = AF_INET6;
		}



		hostname[255] = '\0';
		gethostname(hostname, 255);
	}

	char buffer[BUFFER_SIZE]; // Buffer for receiving data
	memset(buffer, 0, BUFFER_SIZE); // Null the buffer

	rr_table = malloc(sizeof(tHTable)); // Allocate memory for hash table
	htInit(rr_table); // Initiate hash table

	if (rr_table == NULL) // Hash table init crashed
	{
		close(syslog_socket);
		exit(EXIT_FAILURE);
	}

	if (rflag) // File processing
	{
		result = process_pcap_file(file_name, buffer, rr_table);

		if (sflag) // Send to syslog server
		{
			for(int i = 0; i < MAX_HTSIZE; i++)
			{
				tHTItem* processed_item = (*rr_table)[i];
				while (processed_item != NULL)
				{
					char string_time[80];
					memset(string_time, 0, 80);
					get_timestamp(string_time);
					sprintf(buffer, "<134>1 %s %s dns-export - - - %s %d", string_time, hostname, processed_item->key, processed_item->data);
					if (ip_version == AF_INET)
						sendto(syslog_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_address, sizeof(struct sockaddr_in));
					else if (ip_version == AF_INET6)
						sendto(syslog_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_address6, sizeof(struct sockaddr_in6));
					memset(buffer, 0, BUFFER_SIZE);
					processed_item = processed_item->ptrnext;
				}
			}
			htClearAll(rr_table);
			close(syslog_socket);
		}
		else // Print to stdout
		{
			ht_foreach(rr_table, ht_print_item);
			htClearAll(rr_table);
		}
	}

	if (iflag) // Capture on interface
	{
		signal(SIGUSR1, my_handler); // Handle SIGUSR1 signal, it will print hash table content

		int connection_socket; // Listening socket number

		connection_socket = open_raw_socket(); // Open raw listening socket
		if (connection_socket == -1) // If opening socket failed
		{
			fprintf(stderr, "Creating socket failed.\n");
			free(rr_table);
			close(connection_socket);
			exit(EXIT_FAILURE);
		}

		if (setsockopt(connection_socket, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)+1) == -1) // Bind socket to device
		{
			fprintf(stderr, "Binding socket failed.\n");
			free(rr_table);
			close(connection_socket);
			exit(EXIT_FAILURE);
		}

		int sockopt = 1;
		if (setsockopt(connection_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) // Allow reuse of socket
		{
			fprintf(stderr, "Reusing socket failed.\n");
			free(rr_table);
			close(connection_socket);
			exit(EXIT_FAILURE);
		}

		struct timeval recv_timeout; // Timeout struct for response
		recv_timeout.tv_sec = 4; // 4 seconds
		recv_timeout.tv_usec = 0;
		if (setsockopt(connection_socket, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(struct timeval)) == -1) // Timeout responses
		{
			fprintf(stderr, "Timing socket failed.\n");
			free(rr_table);
			close(connection_socket);
			exit(EXIT_FAILURE);
		}

		result = process_dns_packet(buffer, rr_table, connection_socket, syslog_socket, server_address, seconds, sflag, hostname,
				ip_version, server_address6);

		close(connection_socket);
	}
	free(rr_table);
	exit(result);
}