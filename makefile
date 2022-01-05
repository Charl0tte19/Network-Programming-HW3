.PHONY: clean
all: pcap_show
pcap_show: pcap_show.c pcap_show.h
	gcc -o pcap_show pcap_show.c -lpcap
clean:
	rm pcap_show
