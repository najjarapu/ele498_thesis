#!/usr/bin/python
import socket
import time
from aenum import Enum

dIP="192.168.56.102"
dPort=6633
dPID='\x32\x45\xe5\xd5\x0a\x42'

class ofp_type(Enum):
	OFPT_HELLO = 				'\x00' # Symmetric message */
	OFPT_ERROR = 				'\x01' # Symmetric message */
	OFPT_ECHO_REQUEST = 		'\x02' # Symmetric message */
	OFPT_ECHO_REPLY = 			'\x03' # Symmetric message */
	OFPT_VENDOR = 				'\x04' # Symmetric message */
	# Switch configuration messages. */
	OFPT_FEATURES_REQUEST = 	'\x05' # Controller/switch message */
	OFPT_FEATURES_REPLY = 		'\x06' # Controller/switch message */
	OFPT_GET_CONFIG_REQUEST = 	'\x07' # Controller/switch message */
	OFPT_GET_CONFIG_REPLY = 	'\x08' # Controller/switch message */
	OFPT_SET_CONFIG = 			'\x09' # Controller/switch message */
	# Asynchronous messages. */
	OFPT_PACKET_IN = 			'\x0a' # Async message */
	OFPT_FLOW_REMOVED = 		'\x0b' # Async message */
	OFPT_PORT_STATUS = 			'\x0c' # Async message */
	# Controller command messages. */
	OFPT_PACKET_OUT = 			'\x0d' # Controller/switch message */
	OFPT_FLOW_MOD = 			'\x0e' # Controller/switch message */
	OFPT_PORT_MOD = 			'\x0f' # Controller/switch message */
	# Statistics messages. */
	OFPT_STATS_REQUEST = 		'\x10' # Controller/switch message */
	OFPT_STATS_REPLY = 			'\x11' # Controller/switch message */


print(repr(ofp_type.OFPT_HELLO.value))
print('\x00')
print(ofp_type.OFPT_HELLO.value)


bridge_id="s1"
port_id=bridge_id + ('\x00' * (16-len(bridge_id)))

#Create socket connection and get switch hello.
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((dIP,dPort))
print("Sent: connect")
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print('Received: ' + repr(resp))



#Reply to the hello. Controller sends the feature request next.
to_send = '\x01' + ofp_type.OFPT_HELLO.value + '\x00\x08' + resp[4:8]
sent = s.send(to_send)
print("Sent:     " + repr(to_send))

# get feature request
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))

# send feature reply
to_send = ('\x01' + ofp_type.OFPT_FEATURES_REPLY.value + '\x00\x50' + resp[4:8] + ('\x00'*2) + dPID +
	'\x00\x00\x01\x00\xff' + ('\x00'*6) + '\xc7\x00\x00\x0f\xff\xff\xfe' + dPID +
	port_id + ('\x00'*2) + '\x00\x01\x00\x00\x00\x01' + ('\x00' * 16))
sent = s.send(to_send)
if sent == 0:
	raise RuntimeError("socket connection broken")
print("Sent:     " + repr(to_send))

# get set_config
resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))


#Controller sends a couple of messages. Send Config reply and Stats reply.

# send get config reply
to_send = '\x01' + ofp_type.OFPT_GET_CONFIG_REPLY.value + '\x00\x0C' + ('\x00' * 6) + '\xff\xff'
sent = s.send(to_send)
print("Sent:     " + repr(to_send))
##=set packet size to max \xff\xff = 65535

# get reply
resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received: " + repr(resp))

# send get stats reply
to_send = ('\x01' + ofp_type.OFPT_STATS_REPLY.value + '\x04\x2c\x00\x00\x00\x01' + ('\x00' * 4) + 'Nicira, Inc' + 
	('\x00' * 244) + 'Open vSwitch' + ('\x00' * 244) + '1.9.3' + ('\x00' * 251) + 
	'None' + ('\x00' * 30) + 'None' + ('\x00' * 252))
sent = s.send(to_send)
print("Sent:     " + repr(to_send))

#controller response
resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Received: " + repr(resp))

# send echo request
to_send = '\x01\x02\x00\x08' + ('\x00' * 4)
sent = s.send(to_send)
print("Sent:     " + repr(to_send))


resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")
print("Received:" + repr(resp))
print(repr(resp))


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



s.close() 