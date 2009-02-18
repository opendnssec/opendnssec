#
# This class defines Zones, with all information needed to sign them
# 

import os
import time
import errno

import Util

# todo: move paths to general engine config
basedir = "../signer_tools";

class Zone:
	def __init__(self, _zone_name, _input_file, _output_file):
		self.zone_name = _zone_name
		self.input_file = _input_file
		self.output_file = _output_file
		self.locked = False
		self.scheduled = None
		
		# we need to be able to tell the parent engine to stop
		# if a fatal error or keyboard interrupt reaches one of
		# the signer threads
		#self.engine = None
		
		# information received from KASP
		self.keys = None
		self.resign_interval = 0
	
	# we define two zone objects the same if the zone names are equal
	def __eq__(self, other):
		return self.zone_name == other.zone_name
	
	# todo: make this already the xml format that is also used to
	# read zone information?
	# (will we have/need more data than that?)
	def __str__(self):
		result = ["name: " + self.zone_name]
		result = result + ["\tinput_file: " + self.input_file]
		result = result + ["\toutput_file: " + self.output_file]
		result = result + ["\tresign_interval: " + str(self.resign_interval)]
		if self.keys:
			result = result + ["\tkeys: " + str(self.keys) + "\n"]
		else:
			result = result + ["\tkeys: no keys"]
		
		return "\n".join(result)
	
	#
	# the set_() functions below are temporary to test the engine
	# before we add the zone-config.xml parser
	#
	def set_kasp_data(self, keys, resign_interval):
		self.keys = keys
		self.resign_interval = resign_interval
		
	def add_key(self, key):
		self.lock("add_key()")
		if self.keys:
			self.keys.append(key)
		else:
			self.keys = [key]
		self.release()
		#self.check_and_schedule()
		
	def set_interval(self, interval):
		self.lock("set_interval()")
		self.resign_interval = interval
		self.release()
	
	#
	# TODO: this should probably be moved to the worker class
	#
	def sign(self, output_file, keys, pkcs11_module=None, pkcs11_pin=None):
		self.lock("sign()")
		Util.debug(1, "Signing zone: " + self.zone_name)
		cmd = ["cat" , self.input_file]
		for k in self.keys:
			cmd.append(k + ".key")
		p0 = Util.run_tool(cmd)
		p1 = Util.run_tool([basedir + os.sep + "sorter"], p0.stdout)
		p2 = Util.run_tool([basedir + os.sep + "stripper", "-o", self.zone_name], p1.stdout)
		p3 = Util.run_tool([basedir + os.sep + "nseccer"], p2.stdout)

		if pkcs11_module:
			cmd = [basedir + os.sep + "signer_pkcs11",
			       "-o", self.zone_name,
			       "-m", pkcs11_module]
			if pkcs11_pin:
				cmd = cmd + ["-p", pkcs11_pin]
			cmd = cmd + keys
		else:
			cmd = [basedir + os.sep + "signer",
			       "-o", self.zone_name]
			cmd = cmd + keys
		p4 = Util.run_tool(cmd, p3.stdout)
		
		# this directly write the output to the final name, which
		# will mangle the signed zone file if anything goes wrong
		# TODO: write to tmp file, and move on success
		if output_file and output_file != "-":
			output = open(output_file, "w")
			output.write("; Zone signed at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
			for l in p4.stdout:
				output.write(l)
			output.close()
		else:
			for l in p4.stdout:
				print l,

		for l in p4.stderr:
			print l
		
		status = p4.wait()

		self.release()
		
	def lock(self, caller=None):
		msg = "waiting for lock on zone " + self.zone_name + " to be released";
		if caller:
			msg = str(caller) + ": " + msg
		while (self.locked):
			Util.debug(4, msg)
			time.sleep(1)
		self.locked = True
		msg = "Zone " + self.zone_name + " locked";
		if caller:
			msg = msg + " by " + str(caller)
		Util.debug(4, msg)
	
	def release(self):
		Util.debug(4, "Releasing lock on zone " + self.zone_name)
		self.locked = False

