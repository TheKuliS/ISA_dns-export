//
// Created by KuliS on 8. 10. 2018.
//

#include "communication.h"

unsigned short csum(unsigned short *buf, int nwords) // Checksum
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}