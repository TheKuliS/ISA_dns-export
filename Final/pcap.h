// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018

// pcap file format inspired by:
// 'https://wiki.wireshark.org/Development/LibpcapFileFormat'


#ifndef ISA_PCAP_H
#define ISA_PCAP_H

typedef struct pcap_hdr_s {
	guint32 magic_number;   /* magic number */
	guint16 version_major;  /* major version number */
	guint16 version_minor;  /* minor version number */
	gint32  thiszone;       /* GMT to local correction */
	guint32 sigfigs;        /* accuracy of timestamps */
	guint32 snaplen;        /* max length of captured packets, in octets */
	guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	guint32 ts_sec;         /* timestamp seconds */
	guint32 ts_usec;        /* timestamp microseconds */
	guint32 incl_len;       /* number of octets of packet saved in file */
	guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;



#endif //ISA_PCAP_H
