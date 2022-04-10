//
// Created by sasha on 09.04.2022.
//

#pragma once

namespace Argparser {
    struct program_arguments_t;
    struct program_arguments_t {
        const uint8_t flags;
        const uint32_t port;
        bool port_set;
        const int number_of_packets;
        const std::string interface;
    };

    struct program_arguments_t argparser(int, char **, int &);

}