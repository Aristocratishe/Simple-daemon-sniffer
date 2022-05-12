#include "sniffer.h"

struct sockaddr_in source,dest;
FILE *logfile = fopen("log.txt","w");

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	struct iphdr *iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));
	switch (iph->protocol)
	{
		case 1:
			read_icmp_packet(buffer, size);
			break;
		case 2:
			break;
		case 6:
			read_tcp_packet(buffer, size);
			break;
		case 17:
			read_udp_packet(buffer, size);
			break;
		default:
			break;
	}
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *) Buffer;
	
	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(logfile, "   |-Protocol            : %u \n", (unsigned short) eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer, Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *) (Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |-IP Version        : %d\n", (unsigned int) iph->version);
	fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int) iph->ihl, ((unsigned int) (iph->ihl)) * 4);
	fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int) iph->tos);
	fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
	fprintf(logfile, "   |-TTL      : %d\n", (unsigned int) iph->ttl);
	fprintf(logfile, "   |-Protocol : %d\n", (unsigned int) iph->protocol);
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph->check));
	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void read_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *) (Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct tcphdr *tcph = (struct tcphdr*) (Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	
	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer, Size);
		
	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->source));
	fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->dest));
	fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int) tcph->doff, (unsigned int) tcph->doff * 4);
	fprintf(logfile, "   |-Urgent Flag          : %d\n", (unsigned int) tcph->urg);
	fprintf(logfile, "   |-Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
	fprintf(logfile, "   |-Push Flag            : %d\n", (unsigned int) tcph->psh);
	fprintf(logfile, "   |-Reset Flag           : %d\n", (unsigned int) tcph->rst);
	fprintf(logfile, "   |-Synchronise Flag     : %d\n", (unsigned int) tcph->syn);
	fprintf(logfile, "   |-Finish Flag          : %d\n", (unsigned int) tcph->fin);
	fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->window));
	fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->check));
	fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA Dump                         ");
	fprintf(logfile, "\n");
		
	fprintf(logfile, "IP Header\n");
	write_data(Buffer, iphdrlen);
		
	fprintf(logfile, "TCP Header\n");
	write_data(Buffer + iphdrlen,tcph->doff * 4);
		
	fprintf(logfile, "Data Payload\n");	
	write_data(Buffer + header_size , Size - header_size);
						
	fprintf(logfile, "\n--------------------------------------------------------------");
}

void read_udp_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *) (Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct udphdr *udph = (struct udphdr*) (Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
	
	print_ip_header(Buffer, Size);			
	
	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph->source));
	fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph->dest));
	fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph->len));
	fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph->check));
	
	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	write_data(Buffer, iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	write_data(Buffer + iphdrlen, sizeof udph);
		
	fprintf(logfile, "Data Payload\n");	
	
	write_data(Buffer + header_size, Size - header_size);
	
	fprintf(logfile, "\n--------------------------------------------------------------");
}

void read_icmp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *) (Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *) (Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer, Size);
			
	fprintf(logfile, "\n");
		
	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, "   |-Type : %d", (unsigned int) (icmph->type));
			
	if((unsigned int) (icmph->type) == 11)
	{
		fprintf(logfile, "  (TTL Expired)\n");
	}
	else if((unsigned int) (icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile, "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile, "   |-Code : %d\n", (unsigned int)(icmph->code));
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	write_data(Buffer, iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	write_data(Buffer + iphdrlen, sizeof icmph);
		
	fprintf(logfile, "Data Payload\n");	
	
	write_data(Buffer + header_size, (Size - header_size));
	
	fprintf(logfile , "\n--------------------------------------------------------------");
}

void write_data (const u_char *data , int Size)
{
	int i, j;
	for(i = 0; i < Size; ++i)
	{
		if( i != 0 && i % 16 == 0)
		{
			fprintf(logfile, "         ");
			for(j = i - 16; j < i; ++j)
			{
				if(data[j] >= 32 && data[j] <= 128) 
				{
					fprintf(logfile, "%c", (unsigned char) data[j]);
				}
				else
				{ 
					fprintf(logfile, ".");
				}
			}
			fprintf(logfile, "\n");
		} 
		
		if(i % 16 == 0) 
		{
			fprintf(logfile, "   ");
		}
		
		fprintf(logfile, " %02X", (unsigned int) data[i]);
				
		if(i == Size - 1)
		{
			for(j = 0; j < 15 - i % 16; ++j) 
			{
			  fprintf(logfile, "   ");
			}
			
			fprintf(logfile, "         ");
			
			for(j = i - i % 16; j <= i; ++j)
			{
				if(data[j] >=32 && data[j] <=128) 
				{
				  fprintf(logfile, "%c", (unsigned char) data[j]);
				}
				else 
				{
				  fprintf(logfile, ".");
				}
			}
			
			fprintf(logfile,  "\n" );
		}
	}
}