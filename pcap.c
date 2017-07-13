#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

typedef struct ethernet{
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t type;
} ethernet;

typedef struct ip{
	uint8_t hdr_len:4;
	uint8_t version:4;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint8_t ip_frag_offset:5;
	uint8_t ip_more_fragment:1;
	uint8_t ip_dont_fragment:1;
	uint8_t ip_reserved_zero:1;
	uint8_t ip_frag_offset1;
	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint16_t ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
} ip;

typedef struct tcp{
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence;
	uint32_t acknowledge;
	uint8_t ns:1;
	uint8_t reserved_part1:3;
	uint8_t data_offset:4;
	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t ecn:1;
	uint8_t cwr:1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} tcp;

void getmac(const char *byte){
	int i;
	for(i = 0; i < 5; i++)
		printf("%02x:", (int)*((uint8_t *)&byte[i]));
	printf("%02x\n", (int)*((uint8_t *)&byte[i]));
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
		char *buf = NULL;
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
			if(res <= 0)
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

			buf = (char *)((char *)tcph + tcph->data_offset * 4);
			for(i = 0; i < 16; i++){
				if(buf[i] >= ' ' && buf[i] <= '~')
					printf("%c", buf[i]);
				else
					printf(".");
			}
			puts("");
		}
		pcap_close(handle);
		return(0);
}
