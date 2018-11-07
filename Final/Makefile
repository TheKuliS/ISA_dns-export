# FIT VUT Brno - ISA project 2018 (dns-export)
# Author: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
# 6.11.2018

CC=gcc
CFLAGS= -std=c99 -Wall -Wextra -pedantic

all:
	make dns-export

dns-export: main.o dns.o communication.o hash_table.o pcap.o
	$(CC) $(CFLAGS) main.o dns.o communication.o hash_table.o pcap.o -o dns-export
	
main.o:
	$(CC) $(CFLAGS) main.c -c

dns.o:
	$(CC) $(CFLAGS) dns.c -c

communication.o:
	$(CC) $(CFLAGS) communication.c -c

hash_table.o:
	$(CC) $(CFLAGS) hash_table.c -c

pcap.o:
	$(CC) $(CFLAGS) pcap.c -c

clean:
	rm -f *.o dns-export
