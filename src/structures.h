// File: structures.h
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022

#pragma once

#include <cinttypes>

namespace Structures {
#define ETHERTYPE_PUP 0x0200 /* Xerox PUP */
#define ETHERTYPE_IPv4 0x0800 /* IPv4 */
#define ETHERTYPE_ARP 0x0806 /* Address resolution */
#define ETHERTYPE_REVARP 0x8035 /* Reverse ARP */
#define ETHER_HDRLEN 14

/* ARP Header, (assuming Ethernet+IPv4) */
// http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c
#define ARP_REQUEST 1   /* ARP Request */
#define ARP_REPLY 2     /* ARP Reply */

    /*https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html*/
    struct icmphdr {
        u_int8_t type; /* message type */
        u_int8_t code; /* type sub-code */
        u_int16_t checksum;
        union {
            struct {
                u_int16_t id;
                u_int16_t sequence;
            } echo; /* echo datagram */
            u_int32_t gateway; /* gateway address */
            struct {
                u_int16_t        __unused;
                u_int16_t mtu;
            } frag; /* path mtu discovery */
        } un;
    };
    //http://yuba.stanford.edu/~casado/pcap/section4.html
    struct my_ip {
        u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)    ((ip)->ip_vhl & 0x0f)
        u_int8_t ip_tos; /* type of service */
        u_int16_t ip_len; /* total length */
        u_int16_t ip_id; /* identification */
        u_int16_t ip_off; /* fragment offset field */
#define    IP_DF 0x4000 /* dont fragment flag */
#define    IP_MF 0x2000 /* more fragments flag */
#define    IP_OFFMASK 0x1fff /* mask for fragmenting bits */
        u_int8_t ip_ttl; /* time to live */
        u_int8_t ip_p; /* protocol */
        u_int16_t ip_sum; /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
    };

    // https://gauravsarma1992.medium.com/packet-sniffer-and-parser-in-c-c86070081c38
    struct ether_header {
        uint8_t ether_dhost[ETHER_ADDR_LEN];
        uint8_t ether_shost[ETHER_ADDR_LEN];
        uint16_t ether_type; // IP? ARP? ...
    }__attribute__ ((__packed__));;
}