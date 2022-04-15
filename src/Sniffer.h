// File: Sniffer.h
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#pragma once
#include <pcap.h>

namespace Sniffer {
    class Sniffer {
        // variables
    private:
        pcap_t *handle;
        int number_of_packets;

        // functions
    public:
        Sniffer(const std::string&, const std::string&, int);
        ~Sniffer();
        void sniff_packets() const;
    private:
        static void print_all_devices_and_exit();
        static pcap_handler packet_callback_function(u_char *, const struct pcap_pkthdr *, const u_char *);
    };
}
