#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

typedef struct ethernet{
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
} ethernet;

typedef struct ip{
	unsigned char hdr_len:4;
	unsigned char version:4;
	unsigned char tos;
	unsigned short total_len;
	unsigned short id;
	unsigned char ip_frag_offset:5;
	unsigned char ip_more_fragment:1;
	unsigned char ip_dont_fragment:1;
	unsigned char ip_reserved_zero:1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
} ip;

typedef struct tcp{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns:1;
	unsigned char reserved_part1:3;
	unsigned char data_offset:4;
	unsigned char fin:1;
	unsigned char syn:1;
	unsigned char rst:1;
	unsigned char psh:1;
	unsigned char ack:1;
	unsigned char urg:1;
	unsigned char ecn:1;
	unsigned char cwr:1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
} tcp;

void getmac(const char *byte){
	int i;
	for(i = 0; i < 5; i++)
		printf("%02x:", byte[i] & 0xff);
	printf("%02x\n", byte[i] & 0xff);
}

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		ethernet *eth;
		ip *iph;
		tcp *tcph;
		char buf[17] = {0, };
		//const u_char *packet;		/* The actual packet */
		int res;
		int i;

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
				return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
				net = 0;
				mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
				return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
		}
		while(1){	/* Grab a packet */
			res = pcap_next_ex(handle, &header, (const u_char **)&eth);
			if(res == 0)
				continue;

			if (ntohs(eth->type) != ETHERTYPE_IP){
				printf("not ip type! %x\n", eth->type);
				continue;
			}

			printf("source mac : ");
			getmac(eth->src);

			printf("dest mac : ");
			getmac(eth->dest);

			iph = (ip *)((char *)eth + sizeof(ethernet));

			printf("source ip : %s\n", inet_ntoa(iph->ip_srcaddr));
			printf("dest ip : %s\n", inet_ntoa(iph->ip_destaddr));

			if (iph->ip_protocol != IPPROTO_TCP){
				    printf("not tcp protocol! %x\n", iph->ip_protocol);
				    continue;
			}

			tcph = (tcp *)((char *)iph + iph->hdr_len * 4);
			
			printf("source port : %d\n", ntohs(tcph->source_port));
			printf("dest port : %d\n", ntohs(tcph->dest_port));
		}
		pcap_close(handle);
		return(0);
}
