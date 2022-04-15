// File: Argparser.cpp
// Author: Skuratovich Aliaksandr <xskura01@vutbr.cz>
// Date: 12.4.2022
// Brief: Namespace providing tools for parsing commandline arguments

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <getopt.h>
#include "FilterCreator.h"
#include "Argparser.h"

namespace Argparser {
    void print_help_and_exit(const char *prg_name) {
        std::string name = std::string(prg_name);
        std::string hm = name + " opts\n"
                                "\topts:\n"
                                "\t ! {-i interface | --interface interface}\n"
                                "\t\t- only one interface packets will be sniffed on\n"
                                "\t\t- If not provided or is provided without a value, a list of active interfaces is printed\n"
                                "\t? [-p port]\n"
                                "\t\t- packets will be filtered on the interface w.r.t. port\n"
                                "\t\t- If not provided, all ports are used.\n"
                                "\t\t- If provided, ports are used both from src and dst.\n"
                                "\t? [\n"
                                "\t\t[--tcp|-t] TCP packets are shown.\n"
                                "\t\t[--udp|-u] UPD packets are shown.\n"
                                "\t\t[--arp] ARP packets are shown.\n"
                                "\t\t[--icmp] ICMP packets are shown.\n"
                                "\t\tIf no protocol option is provided, all packets are being captured.\n"
                                "\t]\n"
                                "\t? {-n num}\n"
                                "\t\t- number of sniffed packets.\n";
        std::cout << hm << std::endl;
        exit(0);
    }

    inline uint8_t get_int_carefully(char *val) {
        try {
            return std::stoi(optarg);
        } catch (const std::invalid_argument &e) {
            std::cerr << e.what() << std::endl;
            exit(-1);
        }
    }

    inline void set_flags_if_not_repeated(const char stropt[], uint8_t &flags, uint8_t val) {
        if ((flags & val) != 0) {
            std::cerr << stropt << " the same argument must not be provided twice.\nSee --help for more information.";
            exit(-1);
        }
        flags |= val;
    }

    struct program_arguments_t argparser(int argc, char **argv, int &verbose_flag) {
        if (argc == 1) {
            print_help_and_exit(argv[0]);
        }
        // 8 bytes used to represent all flags program supports.
        uint8_t flags = 0b0000;
        uint32_t port = 0;
        // port can be set only once
        bool port_set = false;
        std::string interface;
        int number_of_packets = 1;

        int getopt_option;
        static struct option long_options[] = {
                // these options set a flag
                {"verbose",   no_argument,       &verbose_flag, 1},
                // these options dont set a flag
                {"interface", required_argument, nullptr,       'E'},
                {"tcp",       no_argument,       nullptr,       'T'},
                {"udp",       no_argument,       nullptr,       'U'},
                {"arp",       no_argument,       nullptr,       'A'},
                {"icmp",      no_argument,       nullptr,       'I'},
                {"help",      no_argument,       nullptr,       'H'},
                {nullptr, 0,                     nullptr,       0}
        };
        static char const *short_options = ":i:p:n:thu";
        int option_index = 0;

        while (true) {
            getopt_option = getopt_long(argc, argv, short_options, long_options, &option_index);
            if (-1 == getopt_option) {
                break;
            }
            switch (getopt_option) {
                // unsupported option
                case 0:
                    if (nullptr != long_options[option_index].flag) {
                        break;
                    }
                    std::cerr << "Unsupported option: " << long_options[option_index].name;
                    if (optarg) {
                        std::cerr << ", with argument: " << optarg;
                    }
                    std::cerr << std::endl;
                    exit(-1);
                // port
                case 'p':
                    std::cout << "\t\tPORT " << optarg << std::endl;
                    port = get_int_carefully(optarg);
                    port_set = true;
                    break;
                // number of connections
                case 'n':
                    std::cout << "\t\tNUMBER OF CONNECTIONS: " << optarg << std::endl;
                    number_of_packets = get_int_carefully(optarg);
                    break;
                // help message
                case 'H':
                case 'h':
                    print_help_and_exit(argv[0]);
                    break;
                // interface
                case 'E':
                case 'i':
                    interface = std::string(optarg);
                    break;
                // tcp
                case 'T':
                case 't':
                    std::cout << "option TCP" << std::endl;
                    set_flags_if_not_repeated("TCP", flags, FilterOptions::TCP_FLAG);
                    break;
                // udp
                case 'U':
                case 'u':
                    std::cout << "option UDP" << std::endl;
                    set_flags_if_not_repeated("UDF", flags, FilterOptions::UDP_FLAG);
                    break;
                // arp
                case 'A':
                    std::cout << "option ARP" << std::endl;
                    set_flags_if_not_repeated("ARP", flags, FilterOptions::ARP_FLAG);
                    break;
                case 'I':
                    std::cout << "option ICMP" << std::endl;
                    set_flags_if_not_repeated("ICMP", flags, FilterOptions::ICMP_FLAG);
                    break;
                case '?':
                    std::cerr << "option:  " << long_options[option_index].name << std::endl;
                    std::cerr << "Testing? -h|--help for more information." << std::endl;
                    exit(-1);
                default:;
                    interface = "";
            }
        }

        if (optind < argc) {
            std::cerr << "ERROR: non-option ARGV-elements: ";
            while (optind < argc) {
                printf("%s ", argv[optind++]);
            }
            std::cerr << std::endl;
            exit(-1);
        }
        program_arguments_t args = {
                .flags = flags,
                .port = port,
                .port_set = port_set,
                .number_of_packets = number_of_packets,
                .interface = interface,
        };
        return args;
    }
}