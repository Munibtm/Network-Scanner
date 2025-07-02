#! /usr/bin/env python

import scapy.all as scapy
import optparse

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="IP or range to scan")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("Enter a target")
    return options
def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # print("-----------------------------------------\nIP\t\t\tMAC address\n-----------------------------------------")
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "MAC": element[1].hwsrc}
        client_list.append(client_dict)
        return client_list

def print_result(result_list):
    print("-----------------------------------------\nIP\t\t\tMAC address\n-----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["MAC"])


options = get_argument()
result_scan = scan(options.ip)
# print(result_scan)
print_result(result_scan)
