//
// Created by sasha on 10.04.2022.
//
#pragma once

#include <cstdint>
#include <string>

class PacketParser {

public:
    PacketParser();

    ~PacketParser();

private:
    enum packet_type_enum {
        TCP, UDP, ARP, ICMP
    };
    uint32_t src_mac_address;
    uint32_t dst_mac_address;
    packet_type_enum packet_type;

protected:
    std::string get_packet_data(packet_type_enum packet_type);

};

