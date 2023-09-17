#include <pcap.h>
#include <bits/stdc++.h>
#include <stdlib.h>
#include <ctime>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

// const char* mainIP = "18.164.190.188";
// const char* mainIP = "23.198.138.230";
// const char* mainIP = "104.81.17.228";
const char* mainIP = "18.164.190.188";


void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_dump(user, header, packet);
}

int main() {
    const char* iface = "en0";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 100, errbuf); 
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return 1;
    }

    pcap_dumper_t* pcap_dumper = pcap_dump_open(handle, "/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap");
    if (pcap_dumper == nullptr) {
        fprintf(stderr, "Couldn't open PCAP dump file: %s\n", pcap_geterr(handle));
        return 1;
    }

    time_t startTime = time(nullptr);
    while (time(nullptr) - startTime < 40) {
        pcap_loop(handle, 1, packet_handler, (u_char*)pcap_dumper);
    }

    pcap_dump_close(pcap_dumper); 









    pcap_t* read_handle = pcap_open_offline("/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap", errbuf);
    if (read_handle == nullptr) {
        fprintf(stderr, "Couldn't open all_packets.pcap for reading: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char* packet;
    uint16_t sourcePort;
    while ((packet = pcap_next(read_handle, &header))) {
        struct ip* ip_header = (struct ip*)(packet + 14); // Assuming Ethernet header
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        char sourceIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sourceIpStr, INET_ADDRSTRLEN);

        if (strcmp(sourceIpStr, mainIP) == 0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
 
                sourcePort = ntohs(tcp_header->th_dport);
                break;
        }
    }
    pcap_close(read_handle);





    pcap_close(handle);
    
    pcap_t* handshake_handle = pcap_open_offline("/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap", errbuf);

    pcap_dumper_t* tcp_syn_dumper = pcap_dump_open(handshake_handle, "/Users/akhsinak/co/cn_lab/tut_3/dumps/tcp_open.pcap");
    pcap_dumper_t* only_tcp_dumper = pcap_dump_open(handshake_handle, "/Users/akhsinak/co/cn_lab/tut_3/dumps/tcp_packets.pcap");
    if (tcp_syn_dumper == nullptr) {
        fprintf(stderr, "Couldn't open PCAP dump file for TCP opening handshake packets: %s\n", pcap_geterr(handshake_handle));
        return 1;
    }

    bool syn = 1;
    bool synack = 0;
    bool ack = 0;
    while((packet = pcap_next(handshake_handle, &header))){

        struct ip* ip_header = (struct ip*)(packet + 14);

        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        char sourceIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sourceIpStr, INET_ADDRSTRLEN);

        char destIpstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), destIpstr, INET_ADDRSTRLEN);
        
        if (syn && strcmp(destIpstr, mainIP) == 0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && ntohs(tcp_header->th_sport) == sourcePort) {
                pcap_dump((u_char*)tcp_syn_dumper, &header, packet);
                pcap_dump((u_char*)only_tcp_dumper, &header, packet);
                syn = 0;
                synack = 1;
        }
        else if(synack && strcmp(sourceIpStr, mainIP) == 0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK) && ntohs(tcp_header->th_dport) == sourcePort){
            pcap_dump((u_char*)tcp_syn_dumper, &header, packet);
            pcap_dump((u_char*)only_tcp_dumper, &header, packet);
            synack = 0;
            ack = 1;
        }
        else if(ack && strcmp(destIpstr, mainIP) == 0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_ACK) && ntohs(tcp_header->th_sport) == sourcePort){
            pcap_dump((u_char*)tcp_syn_dumper, &header, packet);
            break;
        }
    }
    
    pcap_dump_close(tcp_syn_dumper);
    pcap_close(handshake_handle);
    
    pcap_t* closing = pcap_open_offline("/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap", errbuf);

    pcap_dumper_t* tcp_fin_dumper = pcap_dump_open(handshake_handle, "/Users/akhsinak/co/cn_lab/tut_3/dumps/tcp_close.pcap");
    if (tcp_fin_dumper == nullptr) {
        fprintf(stderr, "Couldn't open PCAP dump file for TCP opening handshake packets: %s\n", pcap_geterr(closing));
        return 1;
    }
    
    bool finack1 = 1;
    bool ack1 = 0;
    bool finack2 = 0;
    bool ack2 = 0;
    while((packet = pcap_next(closing, &header))){
    struct ip* ip_header = (struct ip*)(packet + 14);

        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        char sourceIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sourceIpStr, INET_ADDRSTRLEN);

        char destIpstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), destIpstr, INET_ADDRSTRLEN);
        if(finack1 && strcmp(destIpstr,mainIP)==0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_FIN) && (tcp_header->th_flags & TH_ACK) && (ntohs(tcp_header->th_dport) == sourcePort || ntohs(tcp_header->th_sport) == sourcePort))
        {
        	pcap_dump((u_char*)tcp_fin_dumper, &header, packet);
        	finack1 = 0;
        	ack1=1;
	}
	else if (ack1 && strcmp(sourceIpStr,mainIP)==0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_ACK) &&(ntohs(tcp_header->th_dport) == sourcePort || ntohs(tcp_header->th_sport) == sourcePort))
	{
		pcap_dump((u_char*)tcp_fin_dumper, &header, packet);
        	finack2 = 1;
        	ack1=0;
	}
	else if (finack2 && strcmp(sourceIpStr,mainIP)==0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_FIN) && (tcp_header->th_flags & TH_ACK) &&(ntohs(tcp_header->th_dport) == sourcePort || ntohs(tcp_header->th_sport) == sourcePort))
	{
		pcap_dump((u_char*)tcp_fin_dumper, &header, packet);
        	finack2 = 0;
        	ack2=1;
	}
	else if (ack2 && strcmp(destIpstr,mainIP)==0 && ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_flags & TH_ACK) &&(ntohs(tcp_header->th_dport) == sourcePort || ntohs(tcp_header->th_sport) == sourcePort))
	{
		pcap_dump((u_char*)tcp_fin_dumper, &header, packet);
 		break;
	}

    }
    pcap_dump_close(tcp_fin_dumper); 
    pcap_close(closing);
    




    pcap_t* udp_handle = pcap_open_offline("/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap", errbuf);

    pcap_dumper_t* udp_dumper = pcap_dump_open(handshake_handle, "/Users/akhsinak/co/cn_lab/tut_3/dumps/udp_packets.pcap");
    if (udp_dumper == nullptr) {
        fprintf(stderr, "Couldn't open PCAP dump file for TCP opening handshake packets: %s\n", pcap_geterr(udp_handle));
        return 1;
    }
       uint16_t firstudp;
     while((packet = pcap_next(udp_handle, &header))){
    struct ip* ip_header = (struct ip*)(packet + 14); 
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));
          struct udphdr *udp_header;
           udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        char sourceIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sourceIpStr, INET_ADDRSTRLEN);

        char destIpstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), destIpstr, INET_ADDRSTRLEN);

        if(ip_header->ip_p == IPPROTO_UDP)
        {
        	firstudp = ntohs(udp_header->uh_dport);
        	pcap_dump((u_char*)udp_dumper, &header, packet);
        	break;
        }
     }
    pcap_close(udp_handle);




    pcap_t* new_udp_handle = pcap_open_offline("/Users/akhsinak/co/cn_lab/tut_3/dumps/all_packets.pcap", errbuf);

          while((packet = pcap_next(new_udp_handle, &header))){
        struct ip* ip_header = (struct ip*)(packet + 14); 

          struct udphdr *udp_header;
           udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));

        char sourceIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sourceIpStr, INET_ADDRSTRLEN);

        char destIpstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), destIpstr, INET_ADDRSTRLEN);

        if(ip_header->ip_p == IPPROTO_UDP && ntohs(udp_header->uh_sport) == firstudp)
        {
        	pcap_dump((u_char*)udp_dumper, &header, packet);
        	break;
        }
     }
    pcap_dump_close(udp_dumper); 
    pcap_close(new_udp_handle);
    return 0;
}