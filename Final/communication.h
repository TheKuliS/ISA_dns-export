// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#ifndef ISA_COMMUNICATION_H
#define ISA_COMMUNICATION_H

#define BUFFER_SIZE 1500
#define TCP 6
#define UDP 17
#define SYSLOG_PORT 514

unsigned short checksum(unsigned short *buf, int nwords);
int open_raw_socket();
int open_udp_socket();
int get_interface_index(struct ifreq if_id, char* if_name, int connection_socket);
int get_interface_mac(struct ifreq if_id, char* if_name, int connection_socket);
unsigned long receive_packet(void* buffer, unsigned int packet_size, int connection_socket);
void print_ethernet_header(struct ether_header* ethernet_header);
void print_ip_header(struct iphdr* ip_header);
void print_udp_header(struct udphdr* udp_header);
void get_timestamp(char* string_time);

#endif //ISA_COMMUNICATION_H
