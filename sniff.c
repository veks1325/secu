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

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));
        printf(" mac   From:");
        for (int i = 0; i < 6; ++i)
            printf("%02x:", eth->ether_shost[i]);
        printf("\n");
        printf(" mac     To:");
        for (int i = 0; i < 6; ++i)
            printf("%03x:", eth->ether_dhost[i]);
        printf("\n");
        printf(" ip    From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf(" ip      To: %s\n", inet_ntoa(ip->iph_destip));
        struct tcpheader *tcp=(struct tcpheader*)(ip+sizeof(struct ipheader));
        printf(" port  From: %d\n",tcp->tcp_sport);
        printf(" port    To: %d\n",tcp->tcp_dport);
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
