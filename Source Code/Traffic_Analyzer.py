#!usr/bin/python

import struct
import os, sys
import socket
import binascii
import logging

sock_created = False
sock = 0

def Analyze_TCP_Header(data_recv):
	tcp_header = struct.unpack('2H2I4H', data_recv[:20])
	src_port = tcp_header[0]
	dest_port = tcp_header[1]
	seq_no = tcp_header[2]
	ack_no = tcp_header[3]
	data_offset = tcp_header[4] >> 12
	reserved = (tcp_header[5] >> 6) & 0x03ff
	flags = tcp_header[4] & 0x003f
	window = tcp_header[5]
	checksum = tcp_header[6]
	urg_pointer = tcp_header[7]
	data = data_recv[20:]

	fin = bool(flags & 0x0001)
	syn = bool(flags & 0x0002)
	rst = bool(flags & 0x0004)
	psh = bool(flags & 0x0008)
	ack = bool(flags & 0x0010)
	urg = bool(flags & 0x0020)

	print ("________TCP HEADER________")
	logging.info ("________TCP HEADER________")
	print ("SOURCE PORT: " + str(src_port))
	logging.info ("SOURCE PORT: " + str(src_port))
	print ("DESTINATION PORT: " + str(dest_port))
	logging.info ("DESTINATION PORT: " + str(dest_port))
	print ("SEQUENCE NUMBER: " + str(seq_no))
	logging.info ("SEQUENCE NUMBER: " + str(seq_no))
	print ("ACKNOWLEDGEMENT NUMBER: " + str(ack_no))
	logging.info ("ACKNOWLEDGEMENT NUMBER: " + str(ack_no))
	print ("FLAGS:")
	logging.info ("FLAGS:")
	print ("URG: " + str(urg))
	logging.info ("URG: " + str(urg))
	print ("ACK: " + str(ack))
	logging.info ("ACK: " + str(ack))
	print ("PSH: " + str(psh))
	logging.info ("PSH: " + str(psh))
	print ("RST: " + str(rst))
	logging.info ("RST: " + str(rst))
	print ("SYN: " + str(syn))
	logging.info ("SYN: " + str(syn))
	print ("FIN: " + str(fin))
	logging.info ("FIN: " + str(fin))
	print ("WINDOW SIZE: " + str(window))
	logging.info ("WINDOW SIZE: " + str(window))
	print ("CHECKSUM: " + str(checksum))
	logging.info ("CHECKSUM: " + str(checksum))
	logging.info ("-----------------------------------------------------\n")

	return data

def Analyze_UDP_Header(data_recv):
	udp_header = struct.unpack('!4H', data_recv[:8])
	src_port = udp_header[0]
	dest_port = udp_header[1]
	length = udp_header [2]
	checksum = udp_header[3]
	data = data_recv[8:]

	print ("________UDP HEADER________")
	logging.info ("________UDP HEADER________")
	print ("SOURCE PORT: " + str(src_port))
	logging.info ("SOURCE PORT: " + str(src_port))
	print ("DESTINATION PORT: " + str(dest_port))
	logging.info ("DESTINATION PORT: " + str(dest_port))
	print ("LENGTH: " + str(length))
	logging.info ("LENGTH: " + str(length))
	print ("CHECKSUM: " + str(checksum))
	logging.info ("CHECKSUM: " + str(checksum))
	logging.info ("-----------------------------------------------------\n")

	return data

def Analyze_IP_Header(data_recv):
	tcp_udp = ""
	ip_header = struct.unpack('!6H4s4s', data_recv[:20])
	version = ip_header[0] >> 12
	header_len = (ip_header[0] >> 8) & 0x0f
	service_type = ip_header[0] & 0x00ff
	total_len = ip_header[1]
	ip_id = ip_header[2]
	flags = ip_header[3] >> 13
	frag_offset = ip_header[3] & 0x1fff
	ttl = ip_header[4] >> 8
	protocol = ip_header[4] &0x00ff
	checksum = ip_header[5]
	src_ip = socket.inet_ntoa(ip_header[6])
	dest_ip = socket.inet_ntoa(ip_header[7])
	data = data_recv[20:]

	print ("________IP HEADER_______")
	logging.info ("________IP HEADER_______")
	print ("SOURCE IP: " + src_ip)
	logging.info ("SOURCE IP: " + src_ip)
	print ("DESTINATION IP: " + dest_ip)
	logging.info ("DESTINATION IP: " + dest_ip)
	print ("VERSION: " + str(version))
	logging.info ("VERSION: " + str(version))
	print ("HEADER LENGTH: " + str(header_len))
	logging.info ("HEADER LENGTH: " + str(header_len))
	print ("SERVICE TYPE: " + str(service_type))
	logging.info ("SERVICE TYPE: " + str(service_type))
	print ("TOTAL LENGTH: " + str(total_len))
	logging.info ("TOTAL LENGTH: " + str(total_len))
	print ("IP IDENTIFICATION: " + str(ip_id))
	logging.info ("IP IDENTIFICATION: " + str(ip_id))
	print ("FLAGS: " + str(flags))
	logging.info ("IP IDENTIFICATION: " + str(ip_id))
	print ("FRAGMENT OFFSET: " + str(frag_offset))
	logging.info ("FRAGMENT OFFSET: " + str(frag_offset))
	print ("TIME TO LIVE: " + str(ttl))
	logging.info ("TIME TO LIVE: " + str(ttl))
	print ("PROTOCOL: " + str(protocol))
	logging.info ("PROTOCOL: " + str(protocol))
	print ("CHECKSUM: " + str(checksum))
	logging.info ("CHECKSUM: " + str(checksum))

	if protocol == 6:
		tcp_udp = "TCP"
	elif protocol == 17:
		tcp_udp = "UDP"
	else:
		logging.info ("-----------------------------------------------------\n")

	return data, tcp_udp

def Analyze_Ether_Header(data_recv):
	ip_bool = False
	eth_header = struct.unpack('!6s6sH', data_recv[:14])
	dest_mac = binascii.hexlify(eth_header[0]).decode('UTF-8')
	src_mac = binascii.hexlify(eth_header[1]).decode('UTF-8')
	protocol = eth_header[2] >> 8
	data = data_recv[14:]

	print ("________ETHERNET HEADER________")
	logging.info ("________ETHERNET HEADER________")
	print ("SOURCE MAC: %s:%s:%s:%s:%s:%s " % (src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]))
	logging.info ("SOURCE MAC: %s:%s:%s:%s:%s:%s " % (src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]))
	print ("DESTINATION MAC: %s:%s:%s:%s:%s:%s " % (dest_mac[0:2],dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12]))
	logging.info ("DESTINATION MAC: %s:%s:%s:%s:%s:%s " % (dest_mac[0:2],dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12]))
	print ("PROTOCOL: %hu " % protocol)
	logging.info ("PROTOCOL: %hu " % protocol)


	if protocol == 8:
		ip_bool = True
	else:
		logging.info ("-----------------------------------------------------\n")

	return data , ip_bool

def main():
	global sock_created
	global sock
	logging.basicConfig(filename = 'Report.txt', level = logging.INFO, format = '%(asctime)s:: %(message)s')
	if sock_created == False:
		sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
		sock_created = True
	data_recv = sock.recv(2048)
	os.system('clear')
	data_recv, ip_bool = Analyze_Ether_Header(data_recv)

	if ip_bool:
		data_recv, tcp_udp = Analyze_IP_Header(data_recv)
	else:
		return

	if tcp_udp == "TCP":
		data_recv = Analyze_TCP_Header(data_recv)
	elif tcp_udp == "UDP":
		data_recv = Analyze_UDP_Header(data_recv)
	else:
		return

while True:
	main()
