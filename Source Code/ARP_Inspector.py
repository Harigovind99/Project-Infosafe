#!/usr/bin/python

from scapy.all import *
import scapy.all as scapy
import optparse
from termcolor import colored

def Get_Mac(ipadd):
	arp_request = scapy.ARP(pdst=ipadd)
	br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_req_br = br / arp_request
	list_1 = scapy.srp(arp_req_br, timeout=5, verbose=False)[0]
	return list_1[0][1].src

def sniff(interface):
	scapy.sniff(iface = interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try:
			originalmac = Get_Mac(packet[scapy.ARP].psrc)
			responsemac = packet[scapy.ARP].hwsrc
			if responsemac != originalmac:
				print(colored("[*] ALERT!!! You are under attack, ARP table is being poisoned.!", 'red'))
		except IndexError:
			pass

def main():
	parser = optparse.OptionParser('Usage of Program: ' + '-i <interface>')
	parser.add_option('-i','--interface', dest = 'Interface', type = 'string', help = 'Specify the network interface.')
	(options, args) = parser.parse_args()
	interface = options.Interface
	if interface == 'None':
		print (parser.usage)
		exit(0)

	sniff(interface)

if __name__ == '__main__':
	main()
