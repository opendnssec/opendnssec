#
# This class defines Zones, with all information needed to sign them
# 

import os
import time
import errno
from Ft.Xml.XPath import Evaluate
from xml.dom import minidom
import commands
import subprocess
from datetime import datetime
import traceback
import syslog

from EngineConfig import EngineConfiguration

import Util

# tmp for initial tests
import sys

# todo: move this path to general engine config too?
#tools_dir = "../signer_tools";

class Zone:
	def __init__(self, _zone_name, engine_config):
		self.zone_name = _zone_name
		self.engine_config = engine_config
		self.locked = False
		
		# information received from KASP through the xml file
		# the values assigned later are in seconds
		# the xml parsing code must translate the actual value set
		# with the unit set (what is the default unit? or is unit mandatory?)
		config_read = False
		# zone_name already above
		self.adapter = None
		self.signatures_resign_time = 0
		self.signatures_refresh_time = 0
		self.signatures_validity_default = 0
		self.signatures_validity_nsec = 0
		self.signatures_jitter = 0
		self.signatures_zsk_refs = []
		self.signatures_ksk_refs = []
		self.publish_keys = []
		self.denial_nsec = False
		self.denial_nsec3 = False
		self.denial_nsec3_opt_out = False
		self.denial_nsec3_hash_algorithm = None
		self.denial_nsec3_iterations = 0
		self.denial_nsec3_salt = None
		# i still think nsec TTL should not be configurable
		self.denial_nsec3_ttl = 0
		self.keys = {}
		self.signature_keys = []
		self.publish_keys = []

		self.soa_ttl = None
		self.soa_minimum = None
		self.soa_serial = None
		
		# last_update as specified in zonelist.xml, to see when
		# the config for this zone needs to be reread
		self.last_update = None
		# this isn't used atm
		self.last_read = None
	
	# we define two zone objects the same if the zone names are equal
	def __eq__(self, other):
		return self.zone_name == other.zone_name
	
	# todo: make this already the xml format that is also used to
	# read zone information?
	# (will we have/need more data than that?)
	def __str__(self):
		result = ["name: " + self.zone_name]
		result.append("last config file read: " + str(self.last_read))
		
		return "\n".join(result)

	def read_config(self):
		self.from_xml_file(self.engine_config.zone_config_dir + os.sep + self.zone_name + ".xml")
		self.last_read = datetime.now()
	
	def get_input_serial(self):
		file = self.engine_config.zone_input_dir + os.sep + self.zone_name;
		cmd = [ self.engine_config.tools_dir + os.sep + "get_serial",
		        "-f", file ]
		get_serial_c = Util.run_tool(cmd);
		result = 0
		for l in get_serial_c.stdout:
			result = int(l)
		status = get_serial_c.wait();
		if (status == 0):
			return result
		else:
			syslog.syslog(syslog.LOG_WARN, "Warning: get_serial returned " + str(status))
			return 0
	
	
	def get_output_serial(self):
		file = self.engine_config.zone_output_dir + os.sep + self.zone_name + ".signed";
		cmd = [ self.engine_config.tools_dir + os.sep + "get_serial",
		        "-f", file ]
		get_serial_c = Util.run_tool(cmd);
		result = 0
		for l in get_serial_c.stdout:
			result = int(l)
		status = get_serial_c.wait();
		if (status == 0):
			return result
		else:
			syslog.syslog(syslog.LOG_WARN, "Warning: get_serial returned " + str(status))
			return 0

	# this uses the locator value to find the right pkcs11 module
	# creates a DNSKEY string to add to the unsigned zone,
	# and calculates the correct tool_key_id
	# returns True if the key is found
	def find_key_details(self, key):
		syslog.syslog(syslog.LOG_DEBUG, "Generating DNSKEY rr for " + str(key["id"]))
		# just try all modules to generate the dnskey? first one is good?
		for token in self.engine_config.tokens:
			mpath = token["module_path"]
			mpin = token["pin"]
			tname = token["name"]
			syslog.syslog(syslog.LOG_DEBUG, "Try token " + tname)
			cmd = [ self.engine_config.tools_dir + os.sep + "create_dnskey_pkcs11",
					"-n", tname,
					"-m", mpath,
					"-p", mpin,
					"-o", self.zone_name,
					"-a", str(key["algorithm"]),
					"-f", str(key["flags"]),
					"-t", str(key["ttl"]),
					key["locator"]
				  ]
			create_p = Util.run_tool(cmd)
			for l in create_p.stdout:
				output = l
			status = create_p.wait()
			for l in create_p.stderr:
				syslog.syslog(syslog.LOG_ERR, "create_dnskey stderr: " + l)
			syslog.syslog(syslog.LOG_DEBUG, "create_dnskey status: " + str(status))
			syslog.syslog(syslog.LOG_DEBUG, "equality: " + str(status == 0))
			if status == 0:
				key["token_name"] = tname
				key["pkcs11_module"] = mpath
				key["pkcs11_pin"] = mpin
				key["tool_key_id"] = key["locator"] + "_" + str(key["algorithm"])
				key["dnskey"] = str(output)
				syslog.syslog(syslog.LOG_INFO, "Found key " + key["locator"] + " in token " + tname)
				return True
		# TODO: locator->id?
		return False

	#
	# TODO: this should probably be moved to the worker class
	#
	def sort(self):
		syslog.syslog(syslog.LOG_INFO, "Sorting zone: " + self.zone_name)
		unsorted_zone_file = open(self.engine_config.zone_input_dir + os.sep + self.zone_name, "r")
		cmd = [self.engine_config.tools_dir + os.sep + "sorter" ]
		if self.denial_nsec3:
			cmd.extend(["-o", self.zone_name,
			            "-n",
			            "-s", self.denial_nsec3_salt,
			            "-t", str(self.denial_nsec3_iterations),
			            "-a", str(self.denial_nsec3_algorithm)])
		sort_process = Util.run_tool(cmd, subprocess.PIPE)
		
		# sort published keys and zone data
		try:
			for k in self.publish_keys:
				if not k["dnskey"]:
					try:
						syslog.syslog(syslog.LOG_DEBUG, "No information yet for key " + k["locator"])
						if (self.find_key_details(k)):
							sort_process.stdin.write(k["dnskey"]+ "\n")
						else:
							syslog.syslog(syslog.LOG_ERR, "Error: could not find key " + k["locator"])
					except Exception, e:
						syslog.syslog(syslog.LOG_ERR, "Error: Unable to find key " + k["locator"])
						syslog.syslog(syslog.LOG_ERR, str(e))
						sort_process.stdin.write("; Unable to find key " + k["locator"])
				else:
					sort_process.stdin.write(k["dnskey"]+ "\n") 
			
			for line in unsorted_zone_file:
				sort_process.stdin.write(line)
			sort_process.stdin.close()
			
			unsorted_zone_file.close()
			sorted_zone_file = open(self.engine_config.zone_tmp_dir + os.sep + self.zone_name, "w")
			
			for line in sort_process.stderr:
				syslog.syslog(syslog.LOG_ERR, "stderr from sorter: " + line)
			
			for line in sort_process.stdout:
				sorted_zone_file.write(line)
			sorted_zone_file.close()
		except Exception, e:
			syslog.syslog(syslog.LOG_ERR, "Error sorting zone\n");
			syslog.syslog(syslog.LOG_WARNING, str(e));
			syslog.syslog(syslog.LOG_WARNING, "Command was: " + " ".join(cmd))
			for line in sort_process.stderr:
				syslog.syslog(syslog.LOG_WARNING, "sorter stderr: " + line)
			raise e
		syslog.syslog(syslog.LOG_INFO, "Done sorting")
		
	def sign(self):
		self.lock("sign()")
		try:
			# todo: only sort if necessary (depends on what has changed in
			#       the policy)
			self.sort()
			syslog.syslog(syslog.LOG_INFO, "Signing zone: " + self.zone_name)
			# hmz, todo: stripped records need to be re-added
			# and another todo: move strip and nsec to stored file too?
			# (so only signing needs to be redone at re-sign time)
			p2 = Util.run_tool([self.engine_config.tools_dir + os.sep + "stripper",
								"-o", self.zone_name,
								"-f", self.engine_config.zone_tmp_dir + os.sep + self.zone_name]
							   )
			
			if self.denial_nsec:
				p3 = Util.run_tool([self.engine_config.tools_dir + os.sep + "nseccer"], p2.stdout)
			elif self.denial_nsec3:
				p3 = Util.run_tool([self.engine_config.tools_dir + os.sep + "nsec3er",
									"-o", self.zone_name,
									"-s", self.denial_nsec3_salt,
									"-t", str(self.denial_nsec3_iterations),
									"-a", str(self.denial_nsec3_algorithm)],
									p2.stdout)
			# arg; TODO: pcks11 module per key for signer...
			cmd = [self.engine_config.tools_dir + os.sep + "signer_pkcs11" ]

			p4 = Util.run_tool(cmd)
			p4.stdin.write("\n")
			p4.stdin.write(":origin " + self.zone_name + "\n")
			syslog.syslog(syslog.LOG_DEBUG, "send to signer: " + ":origin " + self.zone_name)
			
			# optional SOA modification values
			if self.soa_ttl:
				p4.stdin.write(":soa_ttl " + str(self.soa_ttl) + "\n")
			if self.soa_minimum:
				p4.stdin.write(":soa_minimum " + str(self.soa_ttl) + "\n")
			if self.soa_serial:
				# there are a few options;
				# by default, plain copy the original soa serial
				# (which must have been read...)
				# for now, only support 'unixtime'
				soa_serial = "123"
				if self.soa_serial == "unixtime":
					soa_serial = int(time.time());
					syslog.syslog(syslog.LOG_DEBUG, "set serial to " + str(soa_serial));
					p4.stdin.write(":soa_serial " + str(soa_serial) + "\n")
				elif self.soa_serial == "counter":
					# try output serial first, if not found, use input
					prev_serial = self.get_output_serial()
					if not prev_serial:
						prev_serial = self.get_input_serial()
					if not prev_serial:
						prev_serial = 0
					soa_serial = prev_serial + 1
					syslog.syslog(syslog.LOG_DEBUG, "set serial to " + str(soa_serial));
					p4.stdin.write(":soa_serial " + str(soa_serial) + "\n")
				elif self.soa_serial == "datecounter":
					# if current output serial >= <date>00, just increment by one
					soa_serial = int(time.strftime("%Y%m%d")) * 100
					output_serial = self.get_output_serial()
					if output_serial >= soa_serial:
						soa_serial = output_serial + 1
					syslog.syslog(syslog.LOG_DEBUG, "set serial to " + str(soa_serial));
					p4.stdin.write(":soa_serial " + str(soa_serial) + "\n")
				else:
					syslog.syslog(syslog.LOG_WARNING, "warning: unknown serial type " + self.soa_serial);
			for k in self.signature_keys:
				syslog.syslog(syslog.LOG_DEBUG, "use signature key: " + k["locator"])
				if not k["dnskey"]:
					try:
						syslog.syslog(syslog.LOG_DEBUG, "No information yet for key " + k["locator"])
						self.find_key_details(k)
					except Exception, e:
						syslog.syslog(syslog.LOG_ERR, "Error: Unable to find key " + k["locator"])
				if k["token_name"]:
					scmd = [":add_module",
							k["token_name"],
							k["pkcs11_module"],
							k["pkcs11_pin"]
						   ]
					syslog.syslog(syslog.LOG_DEBUG, "send to signer " + " ".join(scmd))
					p4.stdin.write(" ".join(scmd) + "\n")
					scmd = [":add_key",
							k["token_name"],
							k["tool_key_id"],
							str(k["algorithm"]),
							str(k["flags"])
						   ]
					syslog.syslog(syslog.LOG_DEBUG, "send to signer " + " ".join(scmd))
					p4.stdin.write(" ".join(scmd) + "\n")
				else:
					syslog.syslog(syslog.LOG_WARNING, "warning: no token for key " + k["locator"])
			for l in p3.stdout:
				#syslog.syslog(syslog.LOG_DEBUG, "send to signer " + l)
				p4.stdin.write(l)
			p4.stdin.close()
			p4.wait()
			output = open(self.engine_config.zone_output_dir + os.sep + self.zone_name + ".signed", "w")
			for line in p4.stdout:
				#syslog.syslog(syslog.LOG_DEBUG, "read from signer " + line)
				output.write(line)
			for line in p4.stderr:
				syslog.syslog(syslog.LOG_WARNING, "signer stderr: line")
			output.close()
		except Exception:
			traceback.print_exc()
		syslog.syslog(syslog.LOG_INFO, "Done signing " + self.zone_name)
		#Util.debug(1, "signer result: " + str(status));
		self.release()
		
	def lock(self, caller=None):
		msg = "waiting for lock on zone " + self.zone_name + " to be released";
		if caller:
			msg = str(caller) + ": " + msg
		while (self.locked):
			syslog.syslog(syslog.LOG_DEBUG, msg)
			time.sleep(1)
		self.locked = True
		msg = "Zone " + self.zone_name + " locked";
		if caller:
			msg = msg + " by " + str(caller)
		syslog.syslog(syslog.LOG_DEBUG, msg)
	
	def release(self):
		syslog.syslog(syslog.LOG_DEBUG, "Releasing lock on zone " + self.zone_name)
		self.locked = False

	# not sure whether we will get the data from a file or not, so just wrap
	# around the general string case instead of using 'minidom.parse()'
	def from_xml_file(self, file):
		f = open(file, "r")
		s = f.read()
		f.close()
		x = minidom.parseString(s)
		self.from_xml(x)
		x.unlink()

	# check the output file, and calculate the number of seconds
	# until it should be signed again
	# (this can be negative!)
	# if the file is not found, 0 is returned (sign immediately)
	def calc_resign_from_output_file(self):
		output_file = self.engine_config.zone_output_dir + os.sep + self.zone_name + ".signed"
		try:
			statinfo = os.stat(output_file)
			return int(statinfo.st_mtime + self.signatures_resign_time - time.time())
		except OSError, e:
			return 0
	
	# signer_config is the xml blob described in
	# http://www.opendnssec.se/browser/docs/signconf.xml
	def from_xml(self, signer_config):
		# todo: check the zone name just to be sure?
		# and some general error checking might be nice

		keystore_keys = Evaluate("signconf/keystore/key", signer_config)
		for key_xml in keystore_keys:
			id = int(key_xml.attributes["id"].value)
			key = {}
			key["id"] = id
			key["name"] = Util.get_xml_data("name", key_xml)
			key["ttl"] = Util.parse_duration(Util.get_xml_data("ttl", key_xml))
			key["flags"] = int(Util.get_xml_data("flags", key_xml))
			key["protocol"] = int(Util.get_xml_data("protocol", key_xml))
			key["algorithm"] = int(Util.get_xml_data("algorithm", key_xml))
			key["locator"] = Util.get_xml_data("locator", key_xml)
			# calculate and cache this one later
			key["dnskey"] = None
			key["token_name"] = None
			key["pkcs11_module"] = None
			key["pkcs11_pin"] = None
			key["tool_key_id"] = None
			self.keys[id] = key

		self.signatures_resign_time = Util.parse_duration(Util.get_xml_data("signconf/signatures/resign", signer_config))
		self.signatures_refresh_time = Util.parse_duration(Util.get_xml_data("signconf/signatures/refresh", signer_config))
		self.signatures_validity_default = Util.parse_duration(Util.get_xml_data("signconf/signatures/validity/default", signer_config))
		self.signatures_validity_nsec = Util.parse_duration(Util.get_xml_data("signconf/signatures/validity/nsec", signer_config))
		self.signatures_jitter = Util.parse_duration(Util.get_xml_data("signconf/signatures/jitter", signer_config))
		self.signatures_clockskew = Util.parse_duration(Util.get_xml_data("signconf/signatures/clockskew", signer_config))
		self.denial_ttl = Util.parse_duration(Util.get_xml_data("signconf/denial/ttl", signer_config))
		xmlbs = Evaluate("signconf/signatures/zsk", signer_config)
		for xmlb in xmlbs:
			# todo catch keyerror
			# todo2: error if sep flag was not set?
			self.signature_keys.append(self.keys[int(xmlb.attributes["keyid"].value)])
		xmlbs = Evaluate("signconf/signatures/ksk", signer_config)
		for xmlb in xmlbs:
			# todo catch keyerror
			# todo2: error if sep flag was not set?
			self.signature_keys.append(self.keys[int(xmlb.attributes["keyid"].value)])

		xmlbs = Evaluate("signconf/publish", signer_config);
		for xmlb in xmlbs:
			# todo catch keyerror
			# todo2: error if sep flag was set?
			self.publish_keys.append(self.keys[int(xmlb.attributes["keyid"].value)])

		if Evaluate("signconf/denial/nsec", signer_config):
			self.denial_nsec = True

		nsec3_xmls = Evaluate("signconf/denial/nsec3", signer_config)
		for nsec3_xml in nsec3_xmls:
			self.denial_nsec3 = True
			if Evaluate("opt-out", nsec3_xml):
				self.denial_nsec3_optout = True
			self.denial_nsec3_algorithm = int(Util.get_xml_data("hash/algorithm", nsec3_xml))
			self.denial_nsec3_iterations = int(Util.get_xml_data("hash/iterations", nsec3_xml))
			self.denial_nsec3_salt = Util.get_xml_data("hash/salt", nsec3_xml)
			# calc and cache this later?
			self.nsec3_param_rr = None

		self.soa_ttl = Util.parse_duration(Util.get_xml_data("signconf/soa/ttl", signer_config, True))
		self.soa_minimum = Util.parse_duration(Util.get_xml_data("signconf/soa/min", signer_config, True))
		# todo: check for known values
		self.soa_serial = Util.get_xml_data("signconf/soa/serial", signer_config, True)
		


# quick test-as-we-go function
if __name__=="__main__":
	# this will of course be retrieved from the general zone config dir
	z = Zone("zone1.example", EngineConfiguration("/home/jelte/repos/opendnssec/signer_engine/engine.conf"))
	z.read_config()
	s = z.calc_resign_from_output_file()
	#z.sign()
