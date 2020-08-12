#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "pkt.h"

char local_ip[16];
Mac local_mac;

void GetLocalAddr(char *dev, const char *hw){
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
        sprintf(local_ip, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
}

void packet_setting(EthArpPacket &packet, uint8_t *dmac, uint16_t op, char *sip, uint8_t *tmac, char *tip){
    packet.eth_.dmac_ = Mac(dmac);
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
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));
}

void send_packet(EthArpPacket packet, pcap_t* handle){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("send packet success !!\n");
}

int check_reply_packet(EthArpPacket attack_packet , EthArpPacket request_packet){
    return attack_packet.eth_.type_ == htons(EthHdr::Arp) &&
           attack_packet.arp_.op_ == htons(ArpHdr::Reply) &&
           request_packet.eth_.smac() == attack_packet.eth_.dmac() &&
           request_packet.arp_.sip() == attack_packet.arp_.tip();
}
