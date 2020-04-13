#!/usr/bin/python
import socket
import time

dIP="192.168.56.102"
dPort=6633
dPID='\x26\x8c\x9a\xca\xef\x44'



bridge_id="s1"
port_id=bridge_id + ('\x00' * (16-len(bridge_id)))

#Create socket connection and get switch hello.
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((dIP,dPort))
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print('Received (hello):', repr(resp))
# '\\x01\\x00\\x00\\x08\\x00\\x00\\x00\\x00'
# 0x01 version number? 
# 0x01 hello
# 0x0008 len
# session id


#Reply to the hello. Controller sends the feature request next.
sent = s.send('\x01\x00\x00\x08' + resp[4:8])
resp=s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Sent switch hello (size: " + str(sent) + ") Received:" + repr(resp))

#\\x01\\x05\\x00\\x08\\x00\\x00\\x00\\x00
# 0x01 version number 
# 0x05 features request
# 0x08 len
# 0x00000000 id


#Header on all OpenFlow packets. */
#struct ofp_header {
#uint8_t version; /* OFP_VERSION. */ 0x01
#uint8_t type; /* One of the OFPT_ constants. */ enum OFPT_HELLO 0x00
#uint16_t length; /* Length including this ofp_header. */ 
#uint32_t xid; /* Transaction id associated with this packet. 0x0008 since 8 bytes total
#Replies use the same id as was in the request
#to facilitate pairing. */ supposedly resp[4:8]
#};
#OFP_ASSERT(sizeof(struct ofp_header) == 8);

#The controller respond to the feature request, and get controller replies.


# set port state not to link down 
sent = s.send('\x01\x06\x00\x50' + resp[4:8] + ('\x00'*2) + dPID + 
	'\x00\x00\x01\x00\xff' + ('\x00'*6) + '\xc7\x00\x00\x0f\xff\xff\xfe' + dPID + 
	port_id + ('\x00'*2) + '\x00\x01\x00\x00\x00\x00' + ('\x00' * 16))

if sent == 0:
	raise RuntimeError("socket connection broken")

resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Sent switch feature reply (size: " + str(sent) + ") Received:" + repr(resp))



#Controller sends a couple of messages. Send Config reply and Stats reply.
sent = s.send('\x01\x08\x00\x0C' + ('\x00' * 6) + '\xff\xff')

resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Sent message (size: " + str(sent) + ") Received:" + repr(resp))

sent = s.send('\x01\x11\x04\x2c\x00\x00\x00\x01' + ('\x00' * 4) + 'Nicira, Inc' + 
	('\x00' * 244) + 'Open vSwitch' + ('\x00' * 244) + '1.9.3' + ('\x00' * 251) + 
	'None' + ('\x00' * 30) + 'None' + ('\x00' * 252))

#controller response

resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Sent message (size: " + str(sent) + ") Received:" + repr(resp))


sent = s.send('\x01\x02\x00\x08' + ('\x00' * 4))
resp = s.recv(2048)
if resp ==b'':
	raise RuntimeError("socket connection broken")

print("Sent message (size: " + str(sent) + ") Received:" + repr(resp))
print(repr(resp))

s.close() 