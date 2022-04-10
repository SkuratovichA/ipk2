//
// Created by sasha on 09.04.2022.
//

#include <cstdint>
#include <string>
#include "FilterCreator.h"
#include <iostream>
#include <cstdio>

namespace FilterOptions {
    std::string get_filter_string(const uint8_t flags, const uint32_t port, const bool port_set) {
        const std::string opts[] = {"tcp", "udp", "arp", "icmp or icmp6"};
        // all flags are set
        uint8_t i = flags == 0 ? 0b1111 : flags;
        int32_t j = 0;
        bool insert_or = false;
        bool enclose_in_braces;
        std::string opt_string;
        for (; i != 0b0000; i >>= 1) {
            if ((i & 1) == 1) {
                opt_string += insert_or ? std::string(" or ") + opts[j] : opts[j];
                insert_or = true; // here, we know we'll need to insert "or" for the filter
                j += 1;
            }
        }
        enclose_in_braces = j > 1;
        if (enclose_in_braces) {
            opt_string = std::string("(") + opt_string + std::string(")");
        }
        if (port_set) {
            opt_string += (std::string(" and port ") + std::to_string(port));
        }
        return opt_string;
    }
    const uint8_t TCP_FLAG = 0b0001;
    const uint8_t UDP_FLAG = 0b0010;
    const uint8_t ARP_FLAG = 0b0100;
    const uint8_t ICMP_FLAG = 0b1000;

}