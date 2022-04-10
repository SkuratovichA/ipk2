#include <pcap.h>
#include <cstdlib>
#include <cstdio>
#include <iostream>
//#include <libnet.h>
#include <csignal>
#include "Argparser.h"
#include "FilterCreator.h"
#include "Sniffer.h"
#include <pcap.h>

static int verbose_flag;

void handler(int signum) {
    std::cerr << "Do I need to free memory or resources?";
    exit(0);
}

int main(int argc, char **argv) {
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
