#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "pkt.h"

Ip local_ip;
Mac local_mac;
EthArpPacket request_packet;
EthArpPacket *reply_packet;

void GetLocalAddr(const char *dev, const char *hw){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, dev, IFNAMSIZ -1);

    if( !memcmp(hw, "mac", 3) ){
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        close(fd);
        //for(int i=0;i<6;i++) *(local_mac+i) = (u_char)ifr.ifr_hwaddr.sa_data[i];
        memcpy(&local_mac,ifr.ifr_hwaddr.sa_data,6);
    }
    if( !memcmp(hw, "ip", 2) ){
        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);
        local_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
}

void packet_setting(EthArpPacket &packet, Mac dmac, uint16_t op, Ip sip, Mac tmac, Ip tip){
    packet.eth_.dmac_ = dmac;
    //packet.eth_.smac_ = Mac(local_mac);
    packet.eth_.smac_ = local_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    //packet.arp_.smac_ = Mac(local_mac);
    packet.arp_.smac_ = local_mac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);
}

void send_packet(char *op, EthArpPacket packet, pcap_t* handle, int cnt){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("session_%d : send %s packet success !!\n", cnt, op);
}

int check_reply_packet(EthArpPacket reply_packet , EthArpPacket request_packet){
    return reply_packet.eth_.type_ == htons(EthHdr::Arp) &&
           reply_packet.arp_.op_ == htons(ArpHdr::Reply) &&
           request_packet.eth_.smac() == reply_packet.eth_.dmac() &&
           request_packet.arp_.sip() == reply_packet.arp_.tip();
}

void get_session_mac(Ip ip, Mac &mac, pcap_t* handle, int i){
    request_packet.arp_.tip_ = htonl(Ip(ip));           //set request_arp_tip = session_ip
    send_packet((char *)"request", request_packet, handle, i+1);                    //send request packet

    while(true) {                                              //for find arp reply packet
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        reply_packet = (EthArpPacket *)packet;
        if( check_reply_packet(*reply_packet, request_packet) ){   //find arp reply packet
            printf("session_%d : arp reply packet catch !! \n", i+1);

            mac = reply_packet->arp_.smac();            //get session's mac address
            break;
        }
        printf("Looking for a arp reply packet.. \n");
    }
}
