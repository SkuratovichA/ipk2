//
// Created by sasha on 10.04.2022.
//

#include "PacketParser.h"

PacketParser::PacketParser() {

}

PacketParser::~PacketParser() {

}

std::string PacketParser::get_packet_data(PacketParser::packet_type_enum packet_type) {
    std::string information{};
    switch (packet_type) {
        case PacketParser::packet_type_enum::TCP:
            break;
        case PacketParser::packet_type_enum::UDP:
            break;
        case PacketParser::packet_type_enum::ICMP:
            break;
        case PacketParser::packet_type_enum::ARP:
            break;
        default:
            break;
    }
    return information;
}

