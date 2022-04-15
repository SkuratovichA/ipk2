// File: FileCreator.h
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#pragma once

namespace FilterOptions {
    extern const uint8_t TCP_FLAG  ;//= 0b0001;
    extern const uint8_t UDP_FLAG  ;//= 0b0010;
    extern const uint8_t ARP_FLAG  ;//= 0b0100;
    extern const uint8_t ICMP_FLAG ;//= 0b1000;

    std::string get_filter_string(uint8_t, uint32_t, bool);
}