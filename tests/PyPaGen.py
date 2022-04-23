# File: PyPaGen.py
# Author: Skuratovich Aliaksadr
# Date: 15.4.2022

import argparse
from scapy.all import *
import platform
import netifaces
import sys

# match statements were introduced in python 3.10.
if platform.python_version() <= "3.10":
    print("You need to use python version > 3.10 to run this script")
    sys.exit(-1)

# MacOS uses "en0" instead of "eth0". Therefore, make the script compatible.
match platform.system():
    case 'Darwin':
        INTERFACE = "en0"
    case 'Linux':
        INTERFACE = "eth0"
    case _ as win:
        raise ValueError(f"{win} is not supported. Please, use 'Darwin' or 'Linux'")


class Packet:
    r"""Creates a packet and sends it"""

    def __init__(self, protocol, port, interface, msg):
        r"""Create a packet.
        :param protocol: One of "arp, ipv4, ipv6, tcp, udp".
        :param port: Port.
        :param interface: Interface, e.g 'eth0', 'en0'
        :param msg: Message to add to the packet data.
        """
        self.interface = "".join(interface)
        self.port = int("".join(port))
        msg = "".join(msg)
        protocol = "".join(protocol)

        try:
            ip6addr = netifaces.ifaddresses(self.interface)[netifaces.AF_INET6][0]["addr"]
            ipaddr = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
            macaddr = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]
        except KeyError:
            raise KeyError(f"Provided interface '{self.interface}' is not supported.")
        self.ether = Ether(dst=macaddr, src="00:42:42:42:42:00")
        self.tcp_udp_ip = IP(dst=ipaddr, src=ipaddr)
        self.tcp_udp_msg = Raw(load=f"   \"{msg}\"   ")
        match protocol:
            case "arp":
                self.packet = Ether(dst=macaddr) / ARP(psrc=ipaddr, hwdst=macaddr, pdst=ipaddr)
            case "ipv4":
                self.packet = self.ether / IP(dst=ipaddr, src=ipaddr, proto='icmp') / ICMP(type="echo-request",
                                                                                           code=0) / msg
            case "ipv6":
                self.packet = self.ether / IPv6(dst=ip6addr, src=ip6addr) / ICMPv6EchoRequest(data=msg)
            case "tcp":
                self.packet = self.ether / self.tcp_udp_ip / TCP(dport=self.port, sport=self.port,
                                                                 flags="S") / self.tcp_udp_msg
            case "udp":
                self.packet = self.ether / self.tcp_udp_ip / UDP(dport=self.port, sport=self.port) / self.tcp_udp_msg
            case _ as dn:
                raise ValueError(f"Unsupported protocol: {dn}.")

    def send(self, count):
        r"""Sends given number of crafted packets.

        :param count: Number of packets to send.

        :return:
        """
        sendp(self.packet, count=count, iface=self.interface)


def psender(kwargs):
    count = int(kwargs["count"][0])
    del kwargs["count"]
    Packet(**kwargs).send(count)


def main():
    defproto = "ipv4"
    defport = "42690"
    defcount = "42"
    defmsg = "tristatriatricet stribrnych paketu preletelo pres tristatriatricet stribrnych rozhrani"
    args = {
        'protocol': ([defproto], f"Protocol string. One of arp, ipv{{4,6}}, udp, tcp, m&ms, KFC, H&M... If not specified, '{defproto}' is used."),
        'port': ([defport], f"Port number. If not specified, {defport} is used."),
        'interface': ([INTERFACE], f"Interface.If not specified, {INTERFACE} is used."),
        'count': ([defcount], f"Number of accepted packets. If not specified, {defcount} packets are sent."),
        'msg': ([defmsg], f"Message in packet data. If not specified, '{defmsg}' is added to the packet data.")
    }
    ap = argparse.ArgumentParser()

    for key, (_, hlp) in args.items():
        ap.add_argument(f"--{key}", nargs=1, help=hlp)

    usopts = vars(ap.parse_args())
    psender({key: usopts[key] if usopts[key] else val[0] for key, val in args.items()})


main()
