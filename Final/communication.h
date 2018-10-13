// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

#ifndef ISA_COMMUNICATION_H
#define ISA_COMMUNICATION_H

#define BUFFER_SIZE 1024


unsigned short checksum(unsigned short *buf, int nwords);
int open_raw_socket();
int get_interface_index(struct ifreq if_id, char* if_name, int connection_socket);
int get_interface_mac(struct ifreq if_id, char* if_name, int connection_socket);
unsigned long receive_packet(void* buffer, unsigned int packet_size, int connection_socket);

#endif //ISA_COMMUNICATION_H
