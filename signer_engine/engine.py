#!/usr/bin/env python
import os
import getopt
import sys
import socket

import Zone
import Util

MSGLEN = 1024

class EngineError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Engine:
	#
	# keeps zones signed
	# expects a signal if a zone has changed,
	# or if kasp information has changed.
	# In those cases, it will instantly issue a resign
	# operation. Otherwise it will schedule individual resign
	# operations based on the previous KASP resign interval
	#
	# upon startup, read all the zone files. if signed files exist,
	# base the next scheduled sign on its date (TODO), otherwise,
	# schedule signing operation immediately
	#
	def __init__(self):
		self.zones = {}
		self.locked = False
	
	def lock(self, caller=None):
		while (self.locked):
			Util.debug(4, caller + "waiting for lock on engine to be released")
			time.sleep(1)
		self.locked = True
	
	def release(self):
		Util.debug(4, "Releasing lock on engine")
		self.locked = False

	def add_zone(self, zone):
		self.zones[zone.zone_name] = zone
		Util.debug(2, "Zone " + zone.zone_name + " added")
		
	def delete_zone(self, zone_name):
		try:
			if self.zones[args[2]].scheduled:
				self.zones[args[2]].scheduled.cancel()
			del self.zones[args[2]]
		except KeyError:
			raise EngineError("Zone " + zone_name + " not found")
		
	def add_key(self, zone_name, key):
		try:
			self.zones[zone_name].add_key(key)
		except KeyError:
			raise EngineError("Zone " + zone_name + " not found")
		
	def set_interval(self, zone_name, interval):
		try:
			self.zones[zone_name].set_interval(interval)
		except KeyError:
			raise EngineError("Zone " + zone_name + " not found")
	
	def receive_command(self, client_socket):
		msg = ''
		chunk = ''
		while len(msg) < MSGLEN and chunk != '\n' and chunk != '\0':
			chunk = client_socket.recv(1)
			if chunk == '':
				raise RuntimeError, "socket connection broken"
			if chunk != '\n' and chunk != '\r':
				msg = msg + chunk
		return msg

	def send_response(self, msg, client_socket):
		totalsent = 0
		Util.debug(5, "Sending response: " + msg)
		while totalsent < MSGLEN and totalsent < len(msg):
			sent = client_socket.send(msg[totalsent:])
			if sent == 0:
				raise RuntimeError, "socket connection broken"
			totalsent = totalsent + sent

	def get_zones(self):
		zl = []
		for zn in self.zones.keys():
			zl.append(str(self.zones[zn]))
		return "".join(zl)
	
	def cancel_all(self):
		Util.debug(3, "Canceling all scheduled tasks")
		for zn in self.zones.keys():
			if self.zones[zn].scheduled:
				self.zones[zn].scheduled.cancel()

	def close_command_channel(self):
		Util.debug(3, "Closing command socket")
		self.command_socket.shutdown(0)
		self.command_socket.close()
		
	def stop(self):
		self.cancel_all()
		self.close_command_channel()

	# this need some cleaning up ;)
	def handle_command(self, command):
		# prevent different commands from interfering with the
		# scheduling, so lock the entire engine
		self.lock()
		args = command.split(" ")
		Util.debug(3, "got command: '" + command + "'")
		response = "unknown command"
		try:
			if command[:5] == "zones":
				response = self.get_zones()
			if command[:8] == "add zone":
				self.add_zone(Zone.Zone(args[2], args[3], args[4]))
				response = "Zone added"
			if command[:7] == "add key":
				self.add_key(args[2], args[3])
				response = "Key added"
			if command[:12] == "set interval":
				self.set_interval(args[2], int(args[3]))
				response = "Interval set"
			if command[:8] == "del zone":
				self.delete_zone(args[2])
				response = "Zone removed"
			if command[:9] == "sign zone":
				self.zones[args[2]].schedule_resign(0)
				response = "Zone scheduled for immediate resign"
			if command[:9] == "verbosity":
				Util.verbosity = int(args[1])
				response = "Verbosity set"
		except EngineError, e:
			response = str(e);
		except Exception, e:
			response = "Error handling command: " + str(e)
		self.release()
		return response

	def run(self):
		# create socket to listen for commands on
		# only listen on localhost atm

		self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.command_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.command_socket.bind(("localhost", 47806))
		self.command_socket.listen(5)
		while True:
			(client_socket, address) = self.command_socket.accept()
			try:
				while client_socket:
					command = self.receive_command(client_socket)
					response = self.handle_command(command)
					self.send_response(response + "\n\n", client_socket)
					Util.debug(5, "Done handling command")
			except socket.error, msg:
				Util.debug(5, "Connection closed by peer")
			except RuntimeError, msg:
				Util.debug(5, "Connection closed by peer")

def usage():
	print("usage:")

def main():
	#
	# option handling
	#
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hv", ["help", "output="])
	except getopt.GetoptError, err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)
	output = None
	verbose = False
	output_file = None
	pkcs11_module = None
	pkcs11_pin = None
	keys = []
	for o, a in opts:
		if o == "-v":
			verbose = True
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		else:
			assert False, "unhandled option"

	#
	# main loop
	#
	engine = Engine()
	try:
		engine.run()
	except KeyboardInterrupt:
		engine.stop()

# todo: if stuff breaks,, or sigint is given, cancel all scheduled tasks

if __name__ == '__main__':
	print("Python engine proof of concept, v 0.0001 alpha")
	main()
