#!/usr/bin/env python

#
# this is the heart of the signer engine
# currently, it is implemented with a task queue/worker threads model
# The basic unit of operation is the Zone class that contains all
# information needed by the workers to get it signed
# the engine schedules tasks to sign each zone
# tasks can be repeatable, which means that if they have run, they
# are scheduled again
#
# The engine opens a command channel to receive notifications
#
# TODO's:
# - xml parsing for zone configuration data
# - command channel expansion and cleanup
# - notification of a server to re-read zones (as a schedulable task?)

import os
import getopt
import sys
import socket
import time
import traceback
import threading
import Util
import Zone
from EngineConfig import EngineConfiguration
from Worker import Worker, TaskQueue, Task
from Zonelist import Zonelist

MSGLEN = 1024

class Engine:
	def __init__(self, config_file_name):
		# todo: read config etc
		self.config = EngineConfiguration(config_file_name)
		self.task_queue = TaskQueue()
		self.workers = []
		self.condition = threading.Condition()
		self.zones = {}
		self.zonelist = None
		self.locked = False

	def add_worker(self, name):
		worker = Worker(self.condition, self.task_queue)
		worker.name = name
		worker.start()
		self.workers.append(worker)

	# notify a worker that there might be something to do
	def notify(self):
		self.condition.acquire()
		self.condition.notify()
		self.condition.release()
	
	# notify all workers that there might be something to do
	def notify_all(self):
		self.condition.acquire()
		self.condition.notifyAll()
		self.condition.release()

	def run(self):
		self.add_worker("1")
		self.add_worker("2")
		self.add_worker("3")
		self.add_worker("4")

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

	# todo: clean this up ;)
	# zone config options will be moved to the signer-config xml part
	# reader. The rest will need better parsing and error handling, and
	# perhaps move it to a new option-handling class (or at the very
	# least other functions)
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
				z = Zone.Zone(args[2], self.config)
				z.read_config()
				self.add_zone(z)
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
				self.schedule_signing(args[2])
				response = "Zone scheduled for immediate resign"
			if command[:9] == "verbosity":
				Util.verbosity = int(args[1])
				response = "Verbosity set"
			if command[:5] == "queue":
				self.task_queue.lock()
				response = str(self.task_queue)
				self.task_queue.release()
			if command[:5] == "flush":
				self.task_queue.lock()
				self.task_queue.schedule_all_now()
				self.task_queue.release()
				response = "All tasks scheduled immediately"
				self.notify_all()
			if command[:6] == "update":
				self.read_zonelist()
				response = "zone list updated"
		except EngineError, e:
			response = str(e);
		except Exception, e:
			response = "Error handling command: " + str(e)
			response += traceback.format_exc()
		self.release()
		return response

	def lock(self, caller=None):
		while (self.locked):
			Util.debug(4, caller + "waiting for lock on engine to be released")
			time.sleep(1)
		self.locked = True
	
	def release(self):
		Util.debug(4, "Releasing lock on engine")
		self.locked = False

	def stop_workers(self):
		for worker in self.workers:
			Util.debug(3, "stop worker")
			worker.work = False
		self.notify_all()

	def read_zonelist(self):
		new_zonelist = Zonelist()
		new_zonelist.read_zonelist_file(self.config.zone_input_dir + os.sep + "zonelist.xml")
		# move this to caller?
		if not self.zonelist:
			removed_zones = []
			updated_zones = []
			added_zones = new_zonelist.get_all_zone_names()
			self.zonelist = new_zonelist
		else:
			(removed_zones, added_zones, updated_zones) = self.zonelist.merge(new_zonelist)
		for zone in removed_zones:
			self.remove_zone(zone)
		for zone in added_zones:
			self.add_zone(zone)
		for zone in updated_zones:
			self.update_zone(zone)

	# global zone management
	def add_zone(self, zone_name):
		self.zones[zone_name] = Zone.Zone(zone_name, self.config)
		self.update_zone(zone_name)
		self.schedule_signing(zone_name)
		Util.debug(2, "Zone " + zone_name + " added")
		
	def remove_zone(self, zone_name):
		try:
			if self.zones[args[2]].scheduled:
				self.zones[args[2]].scheduled.cancel()
			del self.zones[args[2]]
		except KeyError:
			raise EngineError("Zone " + zone_name + " not found")
	
	def update_zone(self, zone_name):
		zone = self.zones[zone_name]
		zone.lock()
		zone.read_config()
		# todo: reschedule? need 'config diff'
		self.schedule_signing(zone_name)
		zone.release()
		
	# return big multiline string with all current zone data
	def get_zones(self):
		result = []
		for z in self.zones.values():
			result.append(str(z))
		return "".join(result)
	
	# 'general' sign zone now function
	# todo: put only zone names in queue and let worker get the zone?
	# (probably not; the worker will need the full zone list then)
	def schedule_signing(self, zone_name):
		try:
			zone = self.zones[zone_name]
			self.task_queue.lock()
			self.task_queue.add_task(Task(time.time(), Task.SIGN_ZONE, zone, True, zone.signatures_resign_time))
			self.task_queue.release()
			self.notify()
		except KeyError:
			raise EngineError("Zone " + zone_name + " not found")

class EngineError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def main():
	#
	# option handling
	#
	try:
		opts, args = getopt.getopt(sys.argv[1:], "c:hv", ["--config=", "help", "output="])
	except getopt.GetoptError, err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)
	config_file = "/etc/engine.conf"
	output = None
	verbose = False
	output_file = None
	pkcs11_module = None
	pkcs11_pin = None
	keys = []
	for o, a in opts:
		if o == "-c":
			config_file = a
		elif o == "-v":
			verbose = True
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		else:
			assert False, "unhandled option: " + o

	#
	# main loop
	#
	engine = Engine(config_file)
	try:
		#now = time.time()
		#print "add test tasks"
		#engine.task_queue.add_task(Task(now+1, Task.DUMMY, "asdf.nl", False, 5))
		#engine.task_queue.add_task(Task(now+8, Task.DUMMY, "test.nl"))
		#print engine.task_queue
		engine.read_zonelist()
		engine.run()
		
	except KeyboardInterrupt:
		engine.stop_workers()

if __name__ == '__main__':
	Util.debug(1, "Python engine proof of concept, v 0.0002 alpha")
	main()
