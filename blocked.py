#coding: utf-8
import os
import logging
import binascii
import re
import sys
import threading
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	# Delete scapy logging
from scapy.all import *

def send_fin(data):
	seq_num = data.seq
	payload = data[TCP].load
	length = len(payload)
	next_seq = seq_num+length
	sIP = data[IP].src
	dIP = data[IP].dst
	sPORT = data[Ether].sport
	dPORT = data[Ether].dport
	
	print "seq_num : " + str(next_seq)
	print "sIP : %s, dIP : %s" % (sIP, dIP)
	print "sPORT : %s, dPORT : %s" % (sPORT, dPORT)

def parse_get(data):
	ok = re.findall(".*GET.*?HTTP/(1.1|1.0).*", data)
	if ok: return 31337

def proc(packet):
	if packet.haslayer(IP):
		if packet.haslayer(TCP):
			if packet.haslayer(Raw):
				payload = packet[TCP].load
				if payload:
					if parse_get(payload) == 31337:
						send_fin(packet)

def main():
	while(True):
		sniff(prn=proc, count=1)

if __name__ == "__main__":
	main()
