// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include "communication.h"

int main(int argc, char** argv)
{
	// Input parameters variables
	char* file_name = NULL;
	char* if_name = NULL;
	char* syslog_server = NULL;
	long seconds = 60;

	// Socket variables
	int connection_socket;

	// Open RAW socket to send on
	if ((connection_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0800))) == -1) {
		printf("CLIENT MESSAGE: Creating socket failed.\n");
		exit(SOCKET_ERR);
	}

	return 0;
}