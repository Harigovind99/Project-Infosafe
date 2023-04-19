#!/usr/bin/python

from scapy.all import *
from collections import Counter
from time import localtime, strftime
import threading
import logging


attack_flag = False
syn_count = Counter()
logging.basicConfig(filename='traffic_analysis.log', format='%(message)s', level=logging.INFO)



def run():
	global attack_flag
	while True:
		cur_time = strftime("%a, %d %b %Y %X", localtime())
		if not attack_flag or not syn_count:
			logging.info(cur_time + " Everything is normal")
		else:
			logging.info(cur_time + " SYN attack detected! IP: " + str(syn_count.most_common(1)[0][0]) + " No. of attempts: " + str(syn_count.most_common(1)[0][1]))
			print("[!] System under attack!!!")
			attack_flag = False
		syn_count.clear()
		time.sleep(3.5)


def flow_labels(pkt):

	global attack_flag
	if IP in pkt:
		ipsrc = str(pkt[IP].src)
		ipdst = str(pkt[IP].dst)
		try:
			sport = str(pkt[IP].sport)
			dport = str(pkt[IP].dport)
		except:
			sport = ""
			dport = ""
		prtcl = pkt.getlayer(2).name
		flow = '{:<4} | {:<16} | {:<6} | {:<16} | {:<6} | '.format(prtcl, ipsrc, sport, ipdst, dport)


	if TCP in pkt and pkt[TCP].flags & 2:
		src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
		syn_count[src] += 1
		if syn_count.most_common(1)[0][1] > 25 and pkt.ack == 0:
			attack_flag = True


t1 = threading.Thread(target = run)
t1.start()
sniff(prn=flow_labels, store=0)
