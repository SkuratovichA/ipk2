//
// Created by sasha on 09.04.2022.
//

#include <string>
#include "Sniffer.h"
#include <pcap.h>
#include <iostream>

namespace Sniffer {
    Sniffer::Sniffer(const std::string &filter_expression, const std::string &dev, const int number_of_packets) {
        if (dev.empty()) {
            this->print_all_devices_and_exit();
        }
        // https://engrsalmanshaikh.wordpress.com/2014/12/09/network-packet-sniffer-c/
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_program fp{}; // The compiled filter expression
        bpf_u_int32 mask; // The netmask of our sniffing device
        bpf_u_int32 net; // The IP of our shiffing device
        if (pcap_lookupnet(static_cast<const char *>(dev.c_str()), &net, &mask, errbuf) == -1) {
            std::cerr << "Can't get netmask for device " << dev << std::endl;
            net = net = 0;
            exit(-1);
        }
        this->handle = pcap_open_live(static_cast<const char *>(dev.c_str()), BUFSIZ, 1, 1000, errbuf);
        if (this->handle == nullptr) {
            std::cerr << "Couldn't open device " << dev << std::endl;
            exit(-1);
        }
        if (pcap_compile(this->handle, &fp, static_cast<const char *>(filter_expression.c_str()), 0, net) == -1) {
            std::cerr << "Couldn't parse filter `" << filter_expression << "`. " << pcap_geterr(this->handle);
            exit(-1);
        }
        if (pcap_setfilter(this->handle, &fp) == -1) {
            std::cerr << "Couldn't install filter " << filter_expression << std::endl;
            exit(-1);
        }

        // define number of packets
        this->number_of_packets = number_of_packets;
    }

    //  struct pcap_pkthdr {
    //      struct timeval ts;
    //      bpf_u_int32 caplen;
    //      bpf_u_int32 len;
    //  };
    pcap_handler Sniffer::packet_callback_function(
            u_char *packet_handler,
            const struct pcap_pkthdr *packet_header,
            const u_char *packet_data
    ) {
        std::cout << "fucking slave" << std::endl;
        return nullptr;
    }

    void Sniffer::sniff_packets() const {
        std::cout << "Sniffing packets..." << std::endl;
        std::cout << "number_of_packets: " << this->number_of_packets << std::endl;
        auto rv = pcap_loop(
                this->handle,
                this->number_of_packets,
                reinterpret_cast<pcap_handler>(packet_callback_function), nullptr
        );

        switch (rv) {
            case 0:
                std::cerr << "Cnt exhausted" << std::endl;
                break;
            case -1:
                std::cerr << "Error occurred while receiving packets." << std::endl;
                break;
            case -2:
                // ok
                break;
            default:
                std::cerr << "Something strange has happened." << std::endl;
        }
    }

    void Sniffer::print_all_devices_and_exit() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevsp;
        if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
            std::cerr << "Cannot find devices" << std::endl;
            exit(-1);
        }
        pcap_if_t *cur = alldevsp;
        if (cur == nullptr) {
            std::cerr << "Device list is empty. You probably have not enough privileges :)" << std::endl;
        }
        while (cur != nullptr) {
            std::cout << "Device: " << cur->name << (cur->description ? cur->description : "(no description)")
                      << std::endl;
            cur = cur->next;
        }
        exit(0);
    }
}