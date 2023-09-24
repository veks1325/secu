#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
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


#define IP_HL(ip) (((ip)->iph_ihl) & 0x0f)
 void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    int payload_len;
    char *payload;
    u_int size_ip;
    u_int size_tcp;
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));
        printf(" mac   From:");
        for (int i = 0; i < 6; ++i)
            printf("%02x:", eth->ether_shost[i]);
        printf("\n");
        printf(" mac     To:");
        for (int i = 0; i < 6; ++i)
            printf("%02x:", eth->ether_dhost[i]);
        printf("\n");
        printf(" ip    From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf(" ip      To: %s\n", inet_ntoa(ip->iph_destip));
        struct tcpheader *tcp=(struct tcpheader*)(ip+sizeof(struct ipheader));
        printf(" port  From: %d\n",tcp->tcp_sport);
        printf(" port    To: %d\n",tcp->tcp_dport);
        payload = (u_char*) (packet + 14);
        payload_len=ntohs(ip->iph_len)-(size_ip+size_tcp);
        size_ip = IP_HL(ip)*4;
        size_tcp = TH_OFF(tcp)*4;
        if(payload_len==0){
          return;
        }
        for(int i=0;i<payload_len;i++){
                 printf("%02x", payload[i]);
                 if(i % 8 == 0) printf("  ");
                 if(i % 16 == 0) printf("\n");

        }
        printf("\n");
    }
}




int main() {
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    struct pcap_pkthdr;
    char filter_exp[]="tcp";
    const u_char *packet;
    bpf_u_int32 net;

    //1steps set dev
    dev="ens33";
    //2steps make session
    handle= pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    //3steps compile filter
    pcap_compile(handle,&fp,filter_exp,0,net);
    if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
    }
    //4steps start capture paket only tcp
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle

    return 0;
}
