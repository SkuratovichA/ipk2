// File: Argparser.h
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#pragma once

namespace Argparser {

    struct program_arguments_t {
        const uint8_t flags; // binary string representing flags have been set
        const uint32_t port;
        bool port_set;
        const int number_of_packets;
        const std::string interface;
    };

    struct program_arguments_t argparser(int, char **, int &);
}
