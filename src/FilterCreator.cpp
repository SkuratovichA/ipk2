// File: FilterCreator.cpp
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#include <cstdint>
#include <string>
#include "FilterCreator.h"

namespace FilterOptions {
    const uint8_t TCP_FLAG = 0b0001;
    const uint8_t UDP_FLAG = 0b0010;
    const uint8_t ARP_FLAG = 0b0100;
    const uint8_t ICMP_FLAG = 0b1000;

    /** Create a pcap filter string.
     * For more information, see https://www.tcpdump.org/manpages/pcap-filter.7.html.
     * @param flags  bit string representing the combination of <>_FLAG
     * @param port port
     * @param port_set boolean. If not, all ports are considered.
     * @return string representing the filter configuration.
     */
    std::string get_filter_string(const uint8_t flags, const uint32_t port, const bool port_set) {
        const std::string opts[] = {
                "tcp", "udp", "arp", "icmp or icmp6"
        };
        // all flags options are set if no options provided.
        uint8_t i = flags == 0 ? 0b1111 : flags;
        int32_t j = 0;
        bool insert_or = false;
        bool enclose_in_braces;
        std::string opt_string;
        // bitwice tiktonik
        for (; i != 0b0000; i >>= 1, j++) {
            if ((i & 0b0001) == 1) {
                opt_string += insert_or ? std::string(" or ") + opts[j] : opts[j];
                insert_or = true; // here, we know we'll need to insert "or" for the filter
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
}