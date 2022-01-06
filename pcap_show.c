#include "pcap_show.h"

void print_help(){
	
	 printf("help: ");
     printf("\033[1;36mpcap_show\033[0m");
     printf("\033[1;32m -r FILENAME\n\033[0m");
     printf("       [");
     printf("\033[1;32m --help, show helping list\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --human, show timestamp in human readable format\033[0m");
     printf("]\n");	
     printf("       [");
     printf("\033[1;32m --ip_s IP_ADDRESS, searching by source IP address\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --ip_d IP_ADDRESS, searching by source IP address\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --mac_s MAC_ADDRESS, searching by source MAC address\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --mac_d MAC_ADDRESS, searching by source MAC address\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --port_s PORT, searching by source port\033[0m");
     printf("]\n");	 
     printf("       [");
     printf("\033[1;32m --port_d PORT, searching by source port\033[0m");
     printf("]\n");	
     printf("       [");
     printf("\033[1;32m -e ETHERNET_TYPE, searching by ethernet type\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m -p IP_PROTOCOL, searching by ip protocol\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --or, the preceding conditions are OR relation (can't use with -and)\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m --and, (default) the preceding conditions are AND relation (can't use with -or)\033[0m");
     printf("]\n");
     printf("       [");
     printf("\033[1;32m -n NUMBER_OF_PACKETS, showing the first n packets\033[0m");
     printf("]\n");		
     printf("\033[1;32m -a PACKET_NUMBER, showing the No.a packet\033[0m");
     printf("]\n");	
}
void print_usage(){
     
	 printf("Usage: ");
     printf("\033[1;36mpcap_show\033[0m");
     printf("\033[1;32m -r FILENAME\033[0m");
     printf("\n(use --help to see other options.)\n");
	 
}

int main(int argc, char* argv[]){
	
	// 記讀了幾個封包
	int cnt=0;	
	
	// open pcap file 時 失敗的話 錯誤訊息存在此
	// PCAP_ERRBUF_SIZE 在 pcap.h中
	char errbuf[PCAP_ERRBUF_SIZE];
	int c, human=0, found=0;
	int n=-1,a=-1, one=0, e_all=1,ip_all=1,IPV4=0,IPV6=0,ARP=0,UDP=0,TCP=0;
	char *search_ipAddr_SRC=NULL,*search_ipAddr_DST=NULL, *search_macAddr_SRC=NULL,*search_macAddr_DST=NULL;
	int search_port_SRC=-1, search_port_DST=-1;
	int cond=0, match=0, or_on=-1, and_on=-1, basic=0;
	char *pcapFile=NULL;
	
	int i=0;
	
	if(argc==1){
		print_usage();
		exit(1);		
	}
	
	for(i=1;i<argc;i++){
		
		if(strcmp(argv[i],"-r")==0){
			i++;
			if(i==argc){
				print_usage();
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				print_usage();
				exit(1);	
			}
			else{
				pcapFile = argv[i];
			}
            basic = 1;
			continue;
		}
		else if(strcmp(argv[i],"--help")==0){
			print_help();
			exit(1);
		}
		else if(strcmp(argv[i],"--human")==0){
			human = 1;
			continue;
		}
		else if(strcmp(argv[i],"--ip_s")==0){
			i++;
			if(i==argc){
				printf("please enter the ip address.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				printf("please enter the ip address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_ipAddr_SRC = argv[i];
			}
			continue;
		}
		else if(strcmp(argv[i],"--ip_d")==0){
			i++;
			if(i==argc){
				printf("please enter the ip address.\n");
				exit(1);				
			}
			if(argv[i][0] == '-'){
				printf("please enter the ip address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_ipAddr_DST = argv[i];
			}
			continue;
		}
		else if(strcmp(argv[i],"--mac_s")==0){
			i++;
			if(i==argc){
				printf("please enter the mac address.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				printf("please enter the mac address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_macAddr_SRC = argv[i];
			}
			continue;
		}
		else if(strcmp(argv[i],"--mac_d")==0){
			i++;
			if(i==argc){
				printf("please enter the mac address.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				printf("please enter the mac address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_macAddr_DST = argv[i];
			}
			continue;
		}
		else if(strcmp(argv[i],"--port_s")==0){
			i++;
			if(i==argc){
				printf("please enter the port address.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-' || !atoi(argv[i])){
				printf("please enter the port address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_port_SRC = atoi(argv[i]);
			}
			continue;
		}
		else if(strcmp(argv[i],"--port_d")==0){
			i++;
			if(i==argc){
				printf("please enter the port address.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-' || !atoi(argv[i])){
				printf("please enter the port address.\n");
				exit(1);	
			}
			else{
				cond++;
				search_port_DST = atoi(argv[i]);
			}
			continue;
		}
		else if(strcmp(argv[i],"-e")==0){
			i++;
			if(i==argc){
				printf("please enter the ethernet type.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				printf("please enter the ethernet type.\n");
				exit(1);	
			}
			else{
				cond++;
				if(strcmp("ipv4",argv[i])==0 || strcmp("IPv4",argv[i])==0){
					e_all=0;
					IPV4=1;
				}
				else if(strcmp("ipv6",argv[i])==0 || strcmp("IPv6",argv[i])==0){
					e_all=0;
					IPV6=1;
				}
				else if(strcmp("arp",argv[i])==0 || strcmp("ARP",argv[i])==0){
					e_all=0;
					ARP=1;
				}
				else{
					printf("Not support this ethernet type\n");
					exit(1);
				}
			}
			continue;
		}
		else if(strcmp(argv[i],"-p")==0){
			i++;
			if(i==argc){
				printf("please enter the ip protocol.\n");
				exit(1);				
			}
			else if(argv[i][0] == '-'){
				printf("please enter the ip protocol.\n");
				exit(1);	
			}
			else{
				cond++;
				if(strcmp("udp",argv[i])==0 || strcmp("UDP",argv[i])==0){
					ip_all=0;
					UDP=1;
				}
				else if(strcmp("tcp",argv[i])==0 || strcmp("TCP",argv[i])==0){
					ip_all=0;
					TCP=1;
				}
				else{
					printf("Not support this ip protocol\n");
					exit(1);
				}
			}
			continue;
		}
		else if(strcmp(argv[i],"--or")==0){
			if(and_on==1){
				printf("-or can't use with -and.\n");
				exit(1);
			}
			else{
				and_on=0;
				or_on=1;
			}
			continue;
		}
		else if(strcmp(argv[i],"--and")==0){
			if(and_on==1){
				printf("-and can't use with -or.\n");
				exit(1);
			}
			else{
				and_on=1;
			}
			continue;
		}
		else if(strcmp(argv[i],"-n")==0){
			i++;
			if(i==argc){
				printf("please enter the number of packets you want to show\n");
				exit(1);				
			}
			if(argv[i][0] == '-' || !atoi(argv[i])){
				printf("please enter the number of packets you want to show\n");
				exit(1);	
			}
			else{
				n = atoi(argv[i]);
			}
			continue;
		}
		else if(strcmp(argv[i],"-a")==0){
			i++;
			if(i==argc){
				printf("please enter the packet number\n");
				exit(1);				
			}
			if(argv[i][0] == '-' || !atoi(argv[i])){
				printf("please enter the packet number\n");
				exit(1);	
			}
			else{
				one = 1;
				a = atoi(argv[i]);
			}
			continue;
		}
        else{
            print_usage();
            exit(1);
        }

	}
	
    if(basic==0){
        print_usage();
        exit(1);
    }
	
	if(and_on==-1)
		and_on=1;
	
	if(e_all==1){
		IPV4=-1;
		IPV6=-1;
		ARP=-1;
	}
	
	if(ip_all==1){
		UDP=-1;
		TCP=-1;
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
	
	char num_print[64], time_print[64], macSRC_print[64], macDST_print[64];
	char eTYPE_print[64], ipSRC_print[64], ipDST_print[64], ipPro_print[64];
	char portSRC_print[64], portDST_print[64];
	
	while(1){
		match=0;
		num_print[0]='\0'; time_print[0]='\0'; macSRC_print[0]='\0'; macDST_print[0]='\0';
		eTYPE_print[0]='\0'; ipSRC_print[0]='\0'; ipDST_print[0]='\0';
		ipPro_print[0]='\0'; portSRC_print[0]='\0'; portDST_print[0]='\0';
		
		//pcap_next_ex能檢測EOF
		ret = pcap_next_ex(handle, &header, &packet);
		
		if(ret == PCAP_ERROR_BREAK)
			//到EOF
			break;
		else if(ret==1){
			cnt++;
			
			if(one==1){
				if(cnt<a)
					continue;
				else if (cnt==a)
					a = -2;
				else
					break;
			}
			
			// time stamp
			// timeval內含tv_sec和tv_usec
			struct timeval *tv = &(header->ts);
			//localtime只精確到秒
			struct tm *time = localtime(&(tv->tv_sec));
			double timestamp;
			char strTime[64];
			
			strftime(strTime, 64, "%F %T", time);
			timestamp = tv->tv_sec + (double)(tv->tv_usec)/1000000;
			
			sprintf(num_print,"No. %d\n{\n",cnt);
		
			if(human==0)
				sprintf(time_print,"timestamp: %lf\n", timestamp);
			else
				sprintf(time_print,"timestamp: %s\n", strTime);
			
			struct ether_header *eptr = (struct ether_header*)packet;
			char macSrcBuf[128];
			char macDstBuf[128];
			
			//將48bit mac addr轉成hex-digits-and-colons 的字串形式 (thread-safe version)
			ether_ntoa_r((struct ether_addr*) &(eptr->ether_shost), macSrcBuf);
			ether_ntoa_r((struct ether_addr*) &(eptr->ether_dhost), macDstBuf);
			
			if(search_macAddr_SRC==NULL)
				sprintf(macSRC_print,"Source MAC address: %s\n", macSrcBuf);
			else if(strcmp(search_macAddr_SRC,macSrcBuf)==0){
				match=1;
				sprintf(macSRC_print,"\033[1;33mSource MAC address: %s\n\033[0m", macSrcBuf);
			}
			else if(and_on==1)
				continue;
			
			if(search_macAddr_DST==NULL)
				sprintf(macDST_print,"Destination MAC address: %s\n", macDstBuf);
			else if(strcmp(search_macAddr_DST,macDstBuf)==0){
				match=1;
				sprintf(macDST_print,"\033[33mDestination MAC address: %s\n\033[0m", macDstBuf);
			}
			else if(and_on==1)
				continue;				
			
			if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
				if(IPV4==-1)
					sprintf(eTYPE_print,"Ethernet Type: IPv4\n");
				else if(IPV4==1){
					match=1;
					sprintf(eTYPE_print,"\033[1;32mEthernet Type: IPv4\n\033[0m");
				}else if(and_on==1)
					continue;
				
				struct iphdr *ip_htr = (struct iphdr*) (packet+14);
				
				char ipSrcBuf[64];
				char ipDstBuf[64];
				inet_ntop(AF_INET, &(ip_htr->saddr), ipSrcBuf, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(ip_htr->daddr), ipDstBuf, INET_ADDRSTRLEN);
				
				if(search_ipAddr_SRC==NULL)
					sprintf(ipSRC_print,"Source IP address: %s\n", ipSrcBuf);
				else if(strcmp(search_ipAddr_SRC,ipSrcBuf)==0){
					match=1;
					sprintf(ipSRC_print,"\033[31mSource IP address: %s\n\033[0m", ipSrcBuf);
				}else if(and_on==1)
					continue;

				if(search_ipAddr_DST==NULL)
					sprintf(ipDST_print,"Destination IP address: %s\n", ipDstBuf);
				else if(strcmp(search_ipAddr_DST,ipDstBuf)==0){
					match=1;
					sprintf(ipDST_print,"\033[1;31mDestination IP address: %s\n\033[0m", ipDstBuf);				
				}
				else if(and_on==1)
					continue;

				if(ip_htr->protocol == IPPROTO_UDP){
					
					if(UDP==-1)
						sprintf(ipPro_print,"IP Protocol: UDP\n");
					else if(UDP==1){
						match=1;
						sprintf(ipPro_print,"\033[1;35mIP Protocol: UDP\n\033[0m");
					}else if(and_on==1)
						continue;
					
					struct udphdr *udp_htr = (struct udphdr*) (packet+14+(ip_htr->ihl)*4);

					if(search_port_SRC==-1)
						sprintf(portSRC_print, "Source port: %d\n", ntohs(udp_htr->source));
					else if(search_port_SRC==ntohs(udp_htr->source)){
						match=1;
						sprintf(portSRC_print,"\033[36mSource port: %d\n\033[0m",  ntohs(udp_htr->source));
					}else if(and_on==1)
						continue;

					if(search_port_DST==-1)
						sprintf(portDST_print, "Destination port: %d\n", ntohs(udp_htr->dest));
					else if(search_port_DST==ntohs(udp_htr->dest)){
						match=1;
						sprintf(portDST_print,"\033[1;36mDestination port: %d\n\033[0m",  ntohs(udp_htr->dest));
					}
					else if(and_on==1)
						continue;
					
				}
				else if(ip_htr->protocol == IPPROTO_TCP){
					if(TCP==-1)
						sprintf(ipPro_print,"IP Protocol: TCP\n");
					else if(TCP==1){
						match=1;
						sprintf(ipPro_print,"\033[1;35mIP Protocol: TCP\n\033[0m");
					}else if(and_on==1)
						continue;
					
					struct tcphdr *tcp_htr = (struct tcphdr*) (packet+14+(ip_htr->ihl)*4);

						if(search_port_SRC==-1)
							sprintf(portSRC_print, "Source port: %d\n", ntohs(tcp_htr->source));
						else if(search_port_SRC==ntohs(tcp_htr->source)){
							match=1;
							sprintf(portSRC_print,"\033[36mSource port: %d\n\033[0m",  ntohs(tcp_htr->source));
						}else if(and_on==1)
							continue;

						if(search_port_DST==-1)
							sprintf(portDST_print, "Destination port: %d\n", ntohs(tcp_htr->dest));
						else if(search_port_DST==ntohs(tcp_htr->dest)){
							match=1;
							sprintf(portDST_print,"\033[1;36mDestination port: %d\n\033[0m",  ntohs(tcp_htr->dest));
						}
						else if(and_on==1)
							continue;					
				}
				else{
					sprintf(ipPro_print,"IP Protocol: Others\n");
				}
			}
			else if(ntohs(eptr->ether_type) == ETHERTYPE_IPV6){				
				if(IPV6==-1)
					sprintf(eTYPE_print,"Ethernet Type: IPv6\n");
				else if(IPV6==1){
					match=1;
					sprintf(eTYPE_print,"\033[1;32mEthernet Type: IPv6\n\033[0m");
				}else if(and_on==1)
					continue;

				struct ip6_hdr *ip6_htr = (struct ip6_hdr*) (packet+14);
				
				char ip6SrcBuf[128];
				char ip6DstBuf[128];
				inet_ntop(AF_INET6, &(ip6_htr->ip6_src), ip6SrcBuf, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &(ip6_htr->ip6_dst), ip6DstBuf, INET6_ADDRSTRLEN);

				if(search_ipAddr_SRC==NULL)
					sprintf(ipSRC_print,"Source IP address: %s\n", ip6SrcBuf);
				else if(strcmp(search_ipAddr_SRC,ip6SrcBuf)==0){
					match=1;
					sprintf(ipSRC_print,"\033[31mSource IP address: %s\n\033[0m", ip6SrcBuf);
				}else if(and_on==1)
					continue;

				if(search_ipAddr_DST==NULL)
					sprintf(ipDST_print,"Destination IP address: %s\n", ip6DstBuf);
				else if(strcmp(search_ipAddr_DST,ip6DstBuf)==0){
					match=1;
					sprintf(ipDST_print,"\033[1;31mDestination IP address: %s\n\033[0m", ip6DstBuf);
				}
				else if(and_on==1)
					continue;
				
				
				if(ip6_htr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP){
					if(UDP==-1)
						sprintf(ipPro_print,"Next Header: UDP\n");
					else if(UDP==1){
						match=1;
						sprintf(ipPro_print,"\033[1;35mNext Header: UDP\n\033[0m");
					}else if(and_on==1)
						continue;
					
					struct udphdr *udp_htr = (struct udphdr*) (packet+14+40);

					if(search_port_SRC==-1)
						sprintf(portSRC_print, "Source port: %d\n", ntohs(udp_htr->source));
					else if(search_port_SRC==ntohs(udp_htr->source)){
						match=1;
						sprintf(portSRC_print,"\033[36mSource port: %d\n\033[0m",  ntohs(udp_htr->source));
					}else if(and_on==1)
						continue;

					if(search_port_DST==-1)
						sprintf(portDST_print, "Destination port: %d\n", ntohs(udp_htr->dest));
					else if(search_port_DST==ntohs(udp_htr->dest)){
						match=1;
						sprintf(portDST_print,"\033[1;36mDestination port: %d\n\033[0m",  ntohs(udp_htr->dest));
					}
					else if(and_on==1)
						continue;
					
				}
				else if(ip6_htr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
					if(TCP==-1)
						sprintf(ipPro_print,"Next Header: TCP\n");
					else if(TCP==1){
						match=1;
						sprintf(ipPro_print,"\033[1;35mNext Header: TCP\n\033[0m");
					}else if(and_on==1)
						continue;
					
					struct tcphdr *tcp_htr = (struct tcphdr*) (packet+14+40);
					if(search_port_SRC==-1)
						sprintf(portSRC_print, "Source port: %d\n", ntohs(tcp_htr->source));
					else if(search_port_SRC==ntohs(tcp_htr->source)){
						match=1;
						sprintf(portSRC_print,"\033[36mSource port: %d\n\033[0m",  ntohs(tcp_htr->source));
					}else if(and_on==1)
						continue;

					if(search_port_DST==-1)
						sprintf(portDST_print, "Destination port: %d\n", ntohs(tcp_htr->dest));
					else if(search_port_DST==ntohs(tcp_htr->dest)){
						match=1;
						sprintf(portDST_print,"\033[1;36mDestination port: %d\n\033[0m",  ntohs(tcp_htr->dest));
					}
					else if(and_on==1)
						continue;

				}
				else{
					sprintf(ipPro_print,"Next Header: Others\n");
				}
			}
			else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
				if(ARP==-1)
					sprintf(eTYPE_print,"Ethernet Type: ARP\n");
				else if(ARP==1){
					match=1;
					sprintf(eTYPE_print,"\033[1;32mEthernet Type: ARP\n\033[0m");
				}else if(and_on==1)
					continue;
			}
			else
				sprintf(eTYPE_print,"Ethernet Type: Others\n");
		}
		// 讀packet時出錯
		else if(ret==PCAP_ERROR){
			printf("%s\n", pcap_geterr(handle));
		}
		
		if(cond==0 || match==1 || and_on==1){
		    found++;
			printf("%s",num_print);
			printf("%s",time_print);
			printf("%s",macSRC_print);
			printf("%s",macDST_print);
			printf("%s",eTYPE_print);
			printf("%s",ipSRC_print);
			printf("%s",ipDST_print);
			printf("%s",ipPro_print);
			printf("%s",portSRC_print);
			printf("%s",portDST_print);
			printf("}\n\n");
		}
		
		if(cond>0){
			if(found==n)
				break;
		}
		else{
			if(cnt==n)
				break;
		}
			
	}
	

	if(cond>0)
		printf("Found %d matched packet(s).\n", found);
		
	if(n>0)
		if(cond>0)
			if(found==n)
				printf("Showing the first %d packet(s).", n);
			else
				printf("The number of matched packet(s) is less than %d.\n", n); 
		else	
			if(cnt==n)
				printf("Showing the first %d packet(s).", n);
			else
				printf("The number of packet(s) is less than %d.\n", n);
		
	if(a>0)
		printf("Not found the No. %d packet.\n", a);
	
	pcap_close(handle);
	
	return 0;

}
	
	
