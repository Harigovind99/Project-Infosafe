#/usr/bin/python

import logging
from termcolor import colored
import socket
import binascii
import os, sys
import struct
import time

sock_created = False
sock = 0

def Analyze_IP(file):
	data_recv = sock.recv(2048)
	os.system('clear')
	data = data_recv[14:]
	ip_header = struct.unpack('!6H4s4s', data[:20])
	src_ip = str(socket.inet_ntoa(ip_header[6]))
	dest_ip = str(socket.inet_ntoa(ip_header[7]))
	print (src_ip, dest_ip)
	for ip in file:
		ip = str(ip.strip('\n'))
		if src_ip == ip:
			print(colored("Host " + dest_ip + " is using VPN or Proxy Server", 'red'))
			logging.info("Host " + dest_ip + " is using VPN or Proxy Server")
			time.sleep(2)
		elif dest_ip == ip:
			print(colored("Host " + src_ip + " is using VPN or Proxy Server", 'red'))
			logging.info("Host " + src_ip + " is using VPN or Proxy Server")
			time.sleep(5)
	#else:
		#	continue

def main():
	global sock_created
	global sock
	logging.basicConfig(filename = 'VPN_Report.txt', level = logging.INFO, format = '%(asctime)s :: %(message)s')
	if sock_created == False:
		sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
		sock_created = True
	while True:
		try:
			file = open("vpn_ipdb.txt", 'r')
			Analyze_IP(file)
		except KeyboardInterrupt:
			print (colored("\nExiting", 'red'))
			file.close()
			break


if __name__ == "__main__":
	main()
