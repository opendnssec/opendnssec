#!/usr/bin/env python

#
# simple python command line interface to the signer engine
#

import sys
import socket
import time


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 47806))

def send_msg(msg):
	tx = client_socket.send(msg)
	print "sent cmd: " + msg,
	msg = ''
	chunk = ''
	prevchunk = ''
	while not (chunk == '\n' and prevchunk == '\n'):
		prevchunk = chunk
		chunk = client_socket.recv(1)
		if chunk == '':
			raise RuntimeError, "socket connection broken"
		if chunk != '\n':
			msg = msg + chunk
		else:
			print msg
			msg = ""

print "cmd> ",
cmd = sys.stdin.readline()
while cmd:
	if cmd[:4] == "quit" or cmd[:4] == "exit":
		sys.exit(0)
	send_msg(cmd)
	print "cmd> ",
	cmd = sys.stdin.readline()

client_socket.shutdown(0)

#send_msg("zones\n")
#send_msg("zones\n")

