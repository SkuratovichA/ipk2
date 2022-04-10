//
// Created by sasha on 09.04.2022.
//

#include <chrono>
#include <format>
#include <type_traits>
#include <string>
#include "Sniffer.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "structures.h"
#include "PacketParser.h"

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

    inline void print_mac_address(uint8_t *ma, const char *type) {
        printf(
                "%s MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n",
                type,
                ma[0], ma[1], ma[2], ma[3], ma[4], ma[5]
        );
    }

    std::string get_timestamp(const timeval &ts) {
        char tmbuf[sizeof("YYYY-mm-ddTHH:MM:SS") + sizeof('\0')];
        // https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
        char zone[sizeof("+HH:HH") + sizeof('\0')];
        char timestamp_str[sizeof(zone) + sizeof(tmbuf) + sizeof(".msmsms")];
        std::string zone_tz{};
        time_t timestamp = ts.tv_sec;
        tm *tm_loc = localtime(&timestamp);
        strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%H:%M:%S", tm_loc);
        strftime(zone, sizeof(zone), "%z", tm_loc);
        zone_tz.insert(zone_tz.end(), {zone[0], zone[1], zone[2], ':', zone[3], zone[4]});
        zone_tz = strcmp("+0000", zone) == 0 ? "Z" : zone_tz;
        snprintf(timestamp_str, sizeof(timestamp_str), "%s.%06d%s", tmbuf, ts.tv_usec, zone_tz.c_str());
        return {timestamp_str};
    }

    void process_ipv4_packet(uint32_t hlen, uint32_t length, uint32_t len, Structures::my_ip const *ip) {
        if (hlen < 5) {
            std::cerr << "bad-hlen: " << hlen << std::endl;
            return;
        }
        /* see if we have as much packet as we should */
        if (length < len) {
            printf("\ntruncated IP - %d bytes missing\n", len - length);
            return;
        }
        auto off = ntohs(ip->ip_off);
        /* aka no 1's in first 13 bits*/
        if ((off & 0x1fff) == 0) {
            /* print source destination hlen version len offset*/
            printf("IP packet captured:\n");
            printf("\tSource: %s\n", inet_ntoa(ip->ip_src));
            printf("\tDestination: %s\n", inet_ntoa(ip->ip_dst));
            printf("\thlen: %d, length: %d, offset: %d\n", hlen, len, off);
        }
        // todo: print more information about the packet
    }

    // http://yuba.stanford.edu/~casado/pcap/disect2.c
    void handle_ip_packet(
            u_char *packet_handler,
            const struct pcap_pkthdr *packet_header,
            const u_char *packet_data
    ) {
        const Structures::my_ip *ip;
        uint32_t length = packet_header->len;
        uint32_t hlen, version;
        uint32_t i, len;

        /* jump pass the ethernet header */
        ip = (Structures::my_ip *) (packet_data + sizeof(ether_header));
        if (length < sizeof(Structures::my_ip)) {
            std::cerr << "truncated ip, length: " << length << std::endl;
            return;
        }
        len = ntohs(ip->ip_len);
        hlen = IP_HL(ip); /* header length */
        version = IP_V(ip); /* ip version */

        /* check version */
        switch (version) {
            case 4:
                process_ipv4_packet(hlen, length, len, ip);
            case 6:
                // TODO: implement me
                std::cerr << "IPV6 packet TODO" << std::endl;
                //exit(228);
                break;
            default:
                std::cerr << "Unknown ip packet version!: " << version << std::endl;
        }
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
        puts("+-------------------------------------------+");
        // timestamp
        std::string timestamp = get_timestamp(packet_header->ts);
        // getting data
        auto *ether = (Structures::ether_header *) packet_data;
        auto size = packet_header->len;
        auto caplen = packet_header->caplen;
        // src && dst mac addresses
        uint8_t *dst = ether->ether_dhost;
        uint8_t *src = ether->ether_shost;

        std::cout << "TIMESTAMP: " << timestamp << std::endl;
        print_mac_address(dst, "Destination");
        print_mac_address(src, "Source");
        std::cout << "EXPECTED SIZE: " << size << "B" << std::endl;
        std::cout << "TOTAL PACKET AVAILABLE: " << caplen << "B" << std::endl;

        uint16_t ether_type = ntohs(ether->ether_type);
        std::string type = "DONT KNOW THE TYPE";
        switch (ether_type) {
            case ETHERTYPE_IP:
                // ipv{4,6} packets
                handle_ip_packet(packet_handler, packet_header, packet_data);
                break;
            case ETHERTYPE_ARP:
                break;
            case ETHERTYPE_REVARP:
                break;
            case ETHERTYPE_PUP:
                break;
            default:
                break;
        }

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
            std::cout << "Device: " << cur->name << (cur->description ? cur->description : " (no description)")
                      << std::endl;
            cur = cur->next;
        }
        exit(0);
    }
}