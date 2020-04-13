#!/usr/bin/python
# Use of this script is restricted to research and testing purposes!
import socket
import struct

dIP="198.168.56.102"
dPort=6633
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((dIP,dPort))
resp=s.listen(1)
while 1:
	conn,addr = s.accept()
	# Receive switch hello
	conn.recv(2048)
	# Return the hello
	conn.send('\x01\x00\x00\x08\x00\x00\x00\x00')
	# Send the Feature request
	conn.send('\x01\x05\x00\x08\x00\x00\x00\x00')
	resp=conn.recv(2048)
 
 	# This response has the info we need.
	dpid=resp[8:16]
	brid=resp[40:56]
	print("=" * 20 + "\n")
	print("DPID: " + "%x:%x:%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBBBB",dpid) 
	+ "\n")
	print("BrID: " + brid + "\n")
	conn.close() 