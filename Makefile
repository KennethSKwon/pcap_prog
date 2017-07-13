all : pcap_prog

LIBS = pcap

pcap_prog : 
	gcc -o pcap pcap.c -l$(LIBS)

clean :
	rm -f pcap
