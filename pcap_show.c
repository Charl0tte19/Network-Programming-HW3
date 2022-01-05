#include "pcap_show.h"

void print_usage(){
	
	printf("Usage: ");
	printf("\033[1;36mpcap_show\033[0m");
	printf("\033[1;32m -r FILENAME\033[0m");
	printf(" [");
	printf("\033[1;32m-h, show timestamp in human readable format\033[0m");
	printf("]\n");	
	 
}

int main(int argc, char* argv[]){
	
	// 記讀了幾個封包
	int cnt=0;	
	
	// open pcap file 時 失敗的話 錯誤訊息存在此
	// PCAP_ERRBUF_SIZE 在 pcap.h中
	char errbuf[PCAP_ERRBUF_SIZE];
	int c, human=0;
	char *pcapFile;
	
	opterr = 0; //不將錯誤訊息輸出到stderr
	while((c = getopt(argc, argv, "hr:")) != -1){
		switch(c){
			
			case 'h':
				//timestamp轉成較可讀的模式
				human = 1;
				break;
			case 'r':
				if(optarg == NULL || strcmp(optarg,"-h")==0){
					print_usage();
					exit(1);
				}
				else{
					pcapFile = optarg;
					break;
				}
			case '?':
				print_usage();
				exit(1);
		}
	}
	if(optind < 3){
		print_usage();
		exit(1);
	}
		
	// open pcap file (用的offline)
	pcap_t* handle = pcap_open_offline(pcapFile, errbuf);
	// 若開檔失敗
	if(handle == NULL){
		printf("%s\n", errbuf);
		exit(1);
	}


	// pcap packet header (紀錄每個封包的meta data: time stamp, caplen, len)
	struct pcap_pkthdr *header = NULL;
	// u_char* 大概是 unsigned char*，總之這裡是指向封包本體的開頭
	const u_char* packet = NULL;
	
	int ret;
	
	while(1){
		//pcap_next_ex能檢測EOF
		ret = pcap_next_ex(handle, &header, &packet);
		
		if(ret == PCAP_ERROR_BREAK)
			//到EOF
			break;
		else if(ret==1){
			cnt++;
			// time stamp
			// timeval內含tv_sec和tv_usec
			struct timeval *tv = &(header->ts);
			//localtime只精確到秒
			struct tm *time = localtime(&(tv->tv_sec));
			double timestamp;
			char strTime[64];
			
			strftime(strTime, 64, "%F %T", time);
			timestamp = tv->tv_sec + (double)(tv->tv_usec)/1000000;
			
			printf("No. %d\n",cnt);
			printf("{\n");
			if(human==0)
				printf("timestamp: %lf\n", timestamp);
			else
				printf("timestamp: %s\n", strTime);
			
			struct ether_header *eptr = (struct ether_header*)packet;
			char macSrcBuf[128];
			char macDstBuf[128];
			
			//將48bit mac addr轉成hex-digits-and-colons 的字串形式 (thread-safe version)
			ether_ntoa_r((struct ether_addr*) &(eptr->ether_shost), macSrcBuf);
			ether_ntoa_r((struct ether_addr*) &(eptr->ether_dhost), macDstBuf);
			printf("Source MAC address: %s\n", macSrcBuf);
			printf("Destination MAC address: %s\n", macDstBuf);
			
			if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
				printf("Ethernet Type: IPv4\n");
			
				struct iphdr *ip_htr = (struct iphdr*) (packet+14);
				
				char ipSrcBuf[64];
				char ipDstBuf[64];
				inet_ntop(AF_INET, &(ip_htr->saddr), ipSrcBuf, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(ip_htr->daddr), ipDstBuf, INET_ADDRSTRLEN);
				printf("Source IP address: %s\n", ipSrcBuf);
				printf("Destination IP address: %s\n", ipDstBuf);

				if(ip_htr->protocol == IPPROTO_UDP){
					printf("IP Protocol: UDP\n");
					struct udphdr *udp_htr = (struct udphdr*) (packet+14+(ip_htr->ihl)*4);
					printf("Source port: %d\n", ntohs(udp_htr->source));
					printf("Destination port: %d\n", ntohs(udp_htr->dest));
				}
				else if(ip_htr->protocol == IPPROTO_TCP){
					printf("IP Protocol: TCP\n");
					struct tcphdr *tcp_htr = (struct tcphdr*) (packet+14+(ip_htr->ihl)*4);
					printf("Source port: %d\n", ntohs(tcp_htr->source));
					printf("Destination port: %d\n", ntohs(tcp_htr->dest));					
				}
				else{
					printf("IP Protocol: Others\n");
				}
			}
			else if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6){
				printf("Ethernet Type: IPv6\n");
				struct ip6_hdr *ip6_htr = (struct ip6_hdr*) (packet+14);
				
				char ip6SrcBuf[128];
				char ip6DstBuf[128];
				inet_ntop(AF_INET6, &(ip6_htr->ip6_src), ip6SrcBuf, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &(ip6_htr->ip6_dst), ip6DstBuf, INET6_ADDRSTRLEN);
				printf("Source IP address: %s\n", ip6SrcBuf);
				printf("Destination IP address: %s\n", ip6DstBuf);
				if(ip6_htr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP){
					printf("Next Header: UDP\n");
					struct udphdr *udp_htr = (struct udphdr*) (packet+14+40);
					printf("Source port: %d\n", ntohs(udp_htr->source));
					printf("Destination port: %d\n", ntohs(udp_htr->dest));
				}
				else if(ip6_htr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
					printf("Next Header: TCP\n");
					struct tcphdr *tcp_htr = (struct tcphdr*) (packet+14+40);
					printf("Source port: %d\n", ntohs(tcp_htr->source));
					printf("Destination port: %d\n", ntohs(tcp_htr->dest));					
				}
				else{
					printf("IP Protocol: Others\n");
				}
			}
			else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
				printf("Ethernet Type: ARP\n");
			}
			else
				printf("Ethernet Type: Others\n");
		}
		// 讀packet時出錯
		else if(ret==PCAP_ERROR){
			printf("%s\n", pcap_geterr(handle));
		}
		printf("}\n\n");
	}
		
	pcap_close(handle);
	
	return 0;

}
	
	
