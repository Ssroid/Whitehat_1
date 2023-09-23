#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  printf("Ethernet Header\n");  
  printf("\t    src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
  printf("\t    dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    printf("IP Header\n");
    printf("\t     src ip: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("\t   dst port: %s\n", inet_ntoa(ip->iph_destip));  
//    printf("\t        len: %d bytes\n", ip->iph_len); 

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("\t   Protocol: TCP\nTCP Header\n");
	    
	    struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
	    //struct tcpheader * tcp_struct_ipsize = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
	    printf("\t   Srt Port: %d\n", tcp->tcp_sport);
	    printf("\t   Dst Port: %d\n", tcp->tcp_dport);
 
	    //printf("\t s-Srt Port: %d\n", tcp_struct_ipsize->tcp_sport);
	    //printf("\t s-Dst Port: %d\n", tcp_struct_ipsize->tcp_dport);
	    printf("-------------Message-------------\n");
	    int tcp_len = tcp->tcp_offx2 * 4;
	    int tcp_data_len = header->len - sizeof(struct ethheader) - ip->iph_ihl * 4 - tcp_len;
	    if (tcp_data_len > 0 ) {
		const u_char *tcp_data = packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp_len;
  	    	printf("\n");
	    	for(int i=0; i<8; i++) {
	      		for(int j=0; j<8; j++) {
			    printf("%02x ", tcp_data[i*8+j]);
	      		}
	     	 printf("\n");
	    	}
	    }
	    printf("\n");
	    printf("=================================\n");
 	    return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


