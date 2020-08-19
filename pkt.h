#pragma once

#include <stdint.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <netinet/ip.h>

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    ip iph_;
};
#pragma pack(pop)

struct session {
    Ip sender_ip;
    Mac sender_mac;

    Ip target_ip;
    Mac target_mac;

    EthArpPacket attack_packet;
};

extern Ip local_ip;
extern Mac local_mac;
extern EthArpPacket request_packet;
extern EthArpPacket *reply_packet;

void GetLocalAddr(const char *dev, const char *hw);

void packet_setting(EthArpPacket &packet, Mac dmac, uint16_t op, Ip sip, Mac tmac, Ip tip);

void send_packet(char *op, EthArpPacket packet, pcap_t* handle, int cnt);

int check_reply_packet(EthArpPacket attack_packet , EthArpPacket request_packet);

void get_session_mac(Ip ip, Mac &mac, pcap_t* handle, int i);
