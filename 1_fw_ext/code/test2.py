import scapy.contrib.openflow as of
import socket
import time
import sys
import scapy.all as scapy
import binascii as b
import os

def randomDPID():
	s = ""
	for x in range(8):
		s = s + chr(int(b.b2a_hex(os.urandom(1)), 16))
	return s

s = randomDPID()

print type(s)
print(s)