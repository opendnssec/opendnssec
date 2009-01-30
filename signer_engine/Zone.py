import commands
import os
import thread
import threading
import time
import errno

import Util

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
		self.check_and_schedule()
		
	def set_interval(self, interval):
		self.lock("set_interval()")
		self.resign_interval = interval
		self.release()
		self.check_and_schedule()
		
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
		# automatically reschedule signing operation
		if status == 0:
			if self.resign_interval > 0:
				self.schedule_resign(self.resign_interval)
			else:
				Util.debug(1, "Zone " + self.zone_name + " has no resign interval, stopping resign scheduling")
		else:
			Util.debug(0, "Signer problem in zone " + self.zone_name + ", stopping resign scheduling")
		
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
		
	def schedule_resign(self, interval):
		Util.debug(3, "Scheduling resign of " + self.zone_name + " in " + str(interval) + " seconds")
		self.lock("schedule_resign()")
		if self.scheduled:
			self.scheduled.cancel()
			self.scheduled = None
		# check for keys
		if self.keys:
			self.scheduled = threading.Timer(interval, self.sign, [self.output_file, self.keys])
			self.scheduled.start()
			Util.debug(4, "Signing task for " + self.zone_name + " scheduled")
			self.release()
		else:
			Util.debug(1, "Error: no keys for zone " + self.zone_name + ", signing and resigning canceled")
			self.scheduled = None
	
	# if everything about the zone is known, this function is called
	# to immediately schedule automatically
	# does nothing if there is already a scheduled operation, or
	# if some values are missing
	# warning: does no locking, do not call from outside
	def check_and_schedule(self):
		self.lock("check_and_schedule()")

		if self.resign_interval == 0 or len(self.keys) == 0 or self.scheduled:
			self.release()
			return
		if self.output_file:
			# i don't think this will work on Windows
			try:
				oz_stat = os.stat(self.output_file);
				if oz_stat:
					last_modified = oz_stat.st_mtime;
					time_diff = int(time.time() - last_modified)
					Util.debug(3, "Zone " + self.zone_name + " last signed " + str(time_diff) + " seconds ago")
					time_to_sign = self.resign_interval - time_diff
					if time_to_sign < 0:
						Util.debug(3, "Interval for " + self.zone_name + " has expired, schedule immediate resign")
						self.release()
						self.schedule_resign(0)
					else:
						self.release()
						self.schedule_resign(time_to_sign)
			except OSError, e:
				if e.errno == errno.ENOENT:
					# no output file, sign now
					Util.debug(3, "No signed zone for " + self.zone_name + ", schedule immediate sign")
					self.release()
					self.schedule_resign(0);
				else:
					# other error, reraise
					self.release()
					raise

	#def set_engine(self, engine):
	#	self.engine = engine
	
	#def stop_all(self):
	#	if (self.engine):
	#		self.engine.stop()

