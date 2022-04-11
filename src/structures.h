//
// Created by sasha on 10.04.2022.
//

#pragma once

#include <cinttypes>

namespace Structures {
#define ETHERTYPE_PUP 0x0200 /* Xerox PUP */
#define ETHERTYPE_IPv4 0x0800 /* IPv4 */
#define ETHERTYPE_ARP 0x0806 /* Address resolution */
#define ETHERTYPE_REVARP 0x8035 /* Reverse ARP */
#define ETHER_ADDR_LEN 6
#define ETHER_HDRLEN 14

/* ARP Header, (assuming Ethernet+IPv4) */
// http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c
#define ARP_REQUEST 1   /* ARP Request */
#define ARP_REPLY 2     /* ARP Reply */
    struct arphdr {
        u_int16_t ar_hrd; /* Hardware Type */
        u_int16_t ar_pro; /* Protocol Type */
        u_char hlen; /* Hardware Address Length */
        u_char plen; /* Protocol Address Length */
        u_int16_t ar_op; /* Operation Code */
        u_char sha[6]; /* Sender hardware address */
        u_char spa[4]; /* Sender IP address */
        u_char tha[6]; /* Target hardware address */
        u_char tpa[4]; /* Target IP address */
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

    /* This is a name for the 48 bit ethernet address available on many
   systems.  */
    struct ether_addr {
        u_int8_t ether_addr_octet[ETHER_ADDR_LEN];
    } __attribute__ ((__packed__));

    // https://gauravsarma1992.medium.com/packet-sniffer-and-parser-in-c-c86070081c38
    struct ether_header {
        uint8_t ether_dhost[ETHER_ADDR_LEN];
        uint8_t ether_shost[ETHER_ADDR_LEN];
        uint16_t ether_type; // IP? ARP? ...
    }__attribute__ ((__packed__));;

    // https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut6.html
    /* 4 bytes IP address */
    struct ip_address {
        uint8_t byte1;
        uint8_t byte2;
        uint8_t byte3;
        uint8_t byte4;
    };

    /* UDP header*/
    struct udp_header {
        uint16_t sport;          // Source port
        uint16_t dport;          // Destination port
        uint16_t len;            // Datagram length
        uint16_t crc;            // Checksum
    };

}