// File: main.cpp
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#include <cstdlib>
#include <iostream>
#include <csignal>

#include "Argparser.h"
#include "FilterCreator.h"
#include "Sniffer.h"

static int verbose_flag;

void handler(int signum) {
    std::cerr << "CTRL+C key pressed. Exiting..." << std::endl;
    exit(0);
}

int main(int argc, char **argv) {
    // setting signal handler
    signal(SIGINT, handler);
    Argparser::program_arguments_t args = Argparser::argparser(argc, argv, verbose_flag);
    // prepare the sniffer
    Sniffer::Sniffer sniffer = Sniffer::Sniffer(
        FilterOptions::get_filter_string(args.flags, args.port, args.port_set),
        args.interface,
        args.number_of_packets
    );
    // sniff packets
    sniffer.sniff_packets(); // TODO: maybe it can return an array of strings ?
    return 0;
}
