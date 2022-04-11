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
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_icmp.h>


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
        std::cout << "filter string: " << filter_expression << std::endl;
    }

    inline void print_mac_address(uint8_t *ma, const char *type) {
        printf(
                "%s MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n",
                type,
                ma[0], ma[1], ma[2], ma[3], ma[4], ma[5]
        );
    }

    inline void print_ip_address(uint8_t *ip, const char *type) {
        printf(
                "%s IP Address: %d.%d.%d.%d\n",
                type,
                ip[0], ip[1], ip[2], ip[3]
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

    /*
     * print data in rows of 16 bytes: offset   hex   ascii
     *
     * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
     */
    // https://www.tcpdump.org/other/sniffex.c
    void print_hex_ascii_line(const u_char *payload, int len, int offset) {
        const u_char *ch;
        /* offset */
        printf("%05d   ", offset);
        /* hex */
        ch = payload;
        for (int i = 0; i < len; i++) {
            printf("%02x ", *ch);
            ch++;
            /* print extra space after 8th byte for visual aid */
            if (i == 7)
                printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
            printf(" ");

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
            for (int i = 0; i < 16 - len; i++) {
                printf("   ");
            }
        }
        printf("   ");
        /* ascii (if printable) */
        ch = payload;
        for (int i = 0; i < len; i++) {
            printf("%c", isprint(*ch) ? *ch : '.');
            ch++;
        }
        printf("\n");
        return;
    }

    /*
     * print packet payload data (avoid printing binary data)
     */
    // https://www.tcpdump.org/other/sniffex.c
    void print_payload(const u_char *payload, uint32_t len) {
        int len_rem = len;
        int line_width = 16; /* number of bytes per line */
        int line_len;
        int offset = 0; /* zero-based offset counter */
        const u_char *ch = payload;

        if (len == 0)
            return;

        /* data fits on one line */
        if (len <= line_width) {
            print_hex_ascii_line(ch, len, offset);
            return;
        }

        /* data spans multiple lines */
        while (true) {
            /* compute current line length */
            line_len = line_width % len_rem;
            /* print line */
            print_hex_ascii_line(ch, line_len, offset);
            /* compute total remaining */
            len_rem = len_rem - line_len;
            /* shift pointer to remaining bytes to print */
            ch = ch + line_len;
            /* add offset */
            offset = offset + line_width;
            /* check if we have line width chars or less */
            if (len_rem <= line_width) {
                /* print last line and get out */
                print_hex_ascii_line(ch, len_rem, offset);
                break;
            }
        }

        return;
    }

    void
    handle_ip6_packet(u_char *packet_handler, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
        std::cout << "Processing ipv6" << std::endl;
        auto ip = (struct ip6_hdr *) (packet_data + sizeof(ether_header) /*14*/);
        // https://stackoverflow.com/questions/66784119/getting-npcap-ipv6-source-and-destination-addresses?noredirect=1#comment118057497_66784119
        // get suorce address
        char str_saddr[INET6_ADDRSTRLEN];
        memset(str_saddr, 0, sizeof(str_saddr));
        inet_ntop(AF_INET6, &ip->ip6_src, str_saddr, INET6_ADDRSTRLEN);

        // get destination address
        char str_daddr[INET6_ADDRSTRLEN];
        memset(str_daddr, 0, sizeof(str_daddr));
        inet_ntop(AF_INET6, &ip->ip6_dst, str_daddr, INET6_ADDRSTRLEN);

        printf("IP6 packet captured:\n");
        printf("Source address: %s\n", str_saddr);
        printf("Destination address: %s\n", str_daddr);

        const udphdr *udp;
        const tcphdr *tcp;
        switch (ip->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
            case IPPROTO_TCP:
                tcp = (struct tcphdr *) (packet_data + ETHER_ADDR_LEN + 40);
                printf("Source port: %d\n", ntohs(tcp->th_sport));
                printf("Destination port: %d\n", ntohs(tcp->th_dport));
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr *) (packet_data + ETHER_ADDR_LEN + 40);
                printf("Source port: %d\n", ntohs(udp->uh_sport));
                printf("Destination port: %d\n", ntohs(udp->uh_dport));
                break;
            default: // ICMP has neither source nor destination port
                break;
        }
    }


    // http://yuba.stanford.edu/~casado/pcap/disect2.c
    void
    handle_ip4_packet(u_char *packet_handler, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
        uint32_t length = packet_header->len;

        const ip *ip = (struct ip *) (packet_data + sizeof(ether_header) /*14*/);
        /* jump pass the ethernet header */
        if (length < sizeof(Structures::my_ip)) {
            std::cerr << "truncated ip, length: " << length << std::endl;
            return;
        }
        const auto len = ntohs(ip->ip_len);
        const auto hlen = ip->ip_hl; /* header length */
        if (hlen < 5) {
            std::cerr << "bad-hlen: " << hlen << std::endl;
            return;
        }
        /* see if we have as much packet as we should */
        if (length < len) {
            printf("truncated IP - %d bytes missing\n", len - length);
            return;
        }
        auto off = ntohs(ip->ip_off);
        /* aka no 1's in first 13 bits*/
        if ((off & 0x1fff) == 0) {
            printf("IP4 packet captured:\n");
            printf("Source address: %s\n", inet_ntoa(ip->ip_src));
            printf("Destination address: %s\n", inet_ntoa(ip->ip_dst));
            //printf("hlen: %d, length: %d, offset: %d\n", hlen, len, off);
        }

        const udphdr *udp;
        const tcphdr *tcp;
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                tcp = (struct tcphdr *) (packet_data + ETHER_ADDR_LEN + hlen * 4);
                printf("Source port: %d\n", ntohs(tcp->th_sport));
                printf("Destination port: %d\n", ntohs(tcp->th_dport));
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr *) (packet_data + ETHER_ADDR_LEN + hlen * 4);
                printf("Source port: %d\n", ntohs(udp->uh_sport));
                printf("Destination port: %d\n", ntohs(udp->uh_dport));
                break;
            default: // ICMP has neither source nor destination port
                break;
        }
    }

//
//    // http://yuba.stanford.edu/~casado/pcap/disect2.c
//    void handle_ip4_packet(u_char *packet_handler, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
//        uint32_t length = packet_header->len;
//        uint32_t hlen;
//        uint32_t len;
//
//        const ip *ip = (struct ip *) (packet_data + sizeof(ether_header) /*14*/);
//        /* jump pass the ethernet header */
//        if (length < sizeof(Structures::my_ip)) {
//            std::cerr << "truncated ip, length: " << length << std::endl;
//            return;
//        }
//        len = ntohs(ip->ip_len);
//        hlen = ip->ip_hl; /* header length */
//        if (hlen < 5) {
//            std::cerr << "bad-hlen: " << hlen << std::endl;
//            return;
//        }
//        /* see if we have as much packet as we should */
//        if (length < len) {
//            printf("truncated IP - %d bytes missing\n", len - length);
//            return;
//        }
//        auto off = ntohs(ip->ip_off);
//        /* aka no 1's in first 13 bits*/
//        if ((off & 0x1fff) == 0) {
//            printf("IP4 packet captured:\n");
//            printf("Source: %s\n", inet_ntoa(ip->ip_src));
//            printf("Destination: %s\n", inet_ntoa(ip->ip_dst));
//            printf("hlen: %d, length: %d, offset: %d\n", hlen, len, off);
//        }
//
//        const struct udphdr *udphdr;
//        const struct tcphdr *tcphdr;
//        const struct icmphdr *icmphdr;
//        switch (ip->ip_p) {
//            case IPPROTO_TCP: printf("TCP\n"); break;
//            case IPPROTO_UDP:
//                udphdr = (struct udphdr *)(packet_data + ETHER_ADDR_LEN);
//
//                break;
//            case IPPROTO_ICMP:printf("ICMP\n"); break;
//            case IPPROTO_IPV6:printf("V6\n"); break;
//            case IPPROTO_IPV4:printf("v4\n"); break;
//        }
//    }

    void
    handle_arp_packet(u_char *packet_handler, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
        auto *arp = (ether_arp *) (packet_data + sizeof(ether_header) /*14*/);

        printf("ARP packet captured:");
        printf("Format of hardware address: %s\n", (ntohs(arp->ea_hdr.ar_hrd) == 1) ? "Ethernet" : "Unknown");
        printf("Format of protocol address type: %s\n", (ntohs(arp->ea_hdr.ar_pro) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: ARP %s\n", (ntohs(arp->ea_hdr.ar_op) == ARP_REQUEST) ? " Request" : " Reply");

        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arp->ea_hdr.ar_hrd) == 1 && ntohs(arp->ea_hdr.ar_pro) == 0x0800) {
            print_mac_address(arp->arp_sha, "Sender");
            print_ip_address(arp->arp_spa, "Sender");
            print_mac_address(arp->arp_tha, "Target");
            print_ip_address(arp->arp_tpa, "Target");
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
            case ETHERTYPE_IPV6: // ipv6
                handle_ip6_packet(packet_handler, packet_header, packet_data);
                break;
            case ETHERTYPE_IP: // ipv4
                handle_ip4_packet(packet_handler, packet_header, packet_data);
                break;
            case ETHERTYPE_ARP:
                std::cerr << "ARP _________________________________________--_-" << std::endl;
                handle_arp_packet(packet_handler, packet_header, packet_data);
                break;
            default:
                break;
        }

        print_payload(packet_data, packet_header->len);
        puts("\n");
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