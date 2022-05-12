#ifndef SNIFFER_H
#define SNIFFER_H

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

void print_ethernet_header(const u_char *, int);

void print_ip_header(const u_char *, int);

void process_ip_packet(const u_char *, int);

void read_ip_packet(const u_char *, int);

void read_tcp_packet(const u_char *, int);

void read_udp_packet(const u_char *, int);

void read_icmp_packet(const u_char *, int);

void write_data (const u_char *, int);

#endif