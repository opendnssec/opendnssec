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

from EngineConfig import EngineConfiguration

import Util

# tmp for initial tests
import sys

# todo: move this path to general engine config too?
tools_dir = "../signer_tools";

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
	
	# we define two zone objects the same if the zone names are equal
	def __eq__(self, other):
		return self.zone_name == other.zone_name
	
	# todo: make this already the xml format that is also used to
	# read zone information?
	# (will we have/need more data than that?)
	def __str__(self):
		result = ["name: " + self.zone_name]
		result = result + ["\tresign_interval: " + str(self.signatures_resign_time)]
		
		return "\n".join(result)

	def read_config(self):
		self.from_xml_file(self.engine_config.zone_config_dir + os.sep + self.zone_name + ".xml")
	
	# this uses the locator value to find the right pkcs11 module
	# creates a DNSKEY string to add to the unsigned zone,
	# and calculates the correct tool_key_id
	def find_key_details(self, key):
		Util.debug(1, "Generating DNSKEY rr for " + str(key["id"]))
		# just try all modules to generate the dnskey? first one is good?
		found = False
		for token in self.engine_config.tokens:
			mpath = token["module_path"]
			mpin = token["pin"]
			cmd = [ tools_dir + os.sep + "create_dnskey_pkcs11",
			        "-m", mpath,
			        "-p", mpin,
			        "-o", self.zone_name,
			        "-a", str(key["algorithm"]),
			        "-f", str(key["flags"]),
			        "-t", str(key["ttl"]),
			        key["locator"]
			      ]
			print " ".join(cmd)
			(status, output) = commands.getstatusoutput(" ".join(cmd))
			if status == 0:
				key["pkcs11_module"] = mpath
				key["pkcs11_pin"] = mpin
				key["tool_key_id"] = key["locator"] + "_" + str(key["algorithm"])
				key["dnskey"] = str(output)
				print key["dnskey"]
				found = True
		# TODO: locator->id?
		if not found:
			raise Exception("Unable to find key " + key["locator"])
	#
	# TODO: this should probably be moved to the worker class
	#
	def sort(self):
		Util.debug(1, "Sorting zone: " + self.zone_name)
		unsorted_zone_file = open(self.engine_config.zone_input_dir + os.sep + self.zone_name, "r")
		cmd = [tools_dir + os.sep + "sorter" ]
		if self.denial_nsec3:
			cmd.extend(["-n",
			            "-s", self.denial_nsec3_salt,
			            "-t", str(self.denial_nsec3_iterations),
			            "-a", str(self.denial_nsec3_algorithm)])
		sort_process = Util.run_tool(cmd, subprocess.PIPE)
		
		# sort published keys and zone data
		for k in self.keys.values():
			if not k["dnskey"]:
				find_key_details(k)
			sort_process.stdin.write(k["dnskey"]+ "\n") 
		
		for line in unsorted_zone_file:
			print line,
			sort_process.stdin.write(line)
		sort_process.stdin.close()
		
		unsorted_zone_file.close()
		sorted_zone_file = open(self.engine_config.zone_tmp_dir + os.sep + self.zone_name, "w")
		
		for line in sort_process.stderr:
			print "stderr: " + line,
		
		for line in sort_process.stdout:
			print line,
			sorted_zone_file.write(line)
		sorted_zone_file.close()
		
		Util.debug(1, "Done sorting")
		
	def sign(self):
		self.lock("sign()")

		# todo: only sort if necessary (depends on what has changed in
		#       the policy)
		self.sort()
		Util.debug(1, "Signing zone: " + self.zone_name)
		# hmz, todo: stripped records need to be re-added
		# and another todo: move strip and nsec to stored file too?
		# (so only signing needs to be redone at re-sign time)
		p2 = Util.run_tool([tools_dir + os.sep + "stripper",
		                    "-o", self.zone_name,
		                    "-f", self.engine_config.zone_tmp_dir + os.sep + self.zone_name]
		                   )
		
		if self.denial_nsec:
			p3 = Util.run_tool([tools_dir + os.sep + "nseccer"], p2.stdout)
		elif self.denial_nsec3:
			p3 = Util.run_tool([tools_dir + os.sep + "nsec3er",
			                    "-o", self.zone_name,
			                    "-s", self.denial_nsec3_salt,
			                    "-t", str(self.denial_nsec3_iterations),
			                    "-a", str(self.denial_nsec3_algorithm)],
			                    p2.stdout)
		# arg; TODO: pcks11 module per key for signer...
		cmd = [tools_dir + os.sep + "signer_pkcs11",
			   "-o", self.zone_name,
			   "-v", "5",
			   "-m", self.keys.values()[0]["pkcs11_module"]]
		cmd = cmd + ["-p", self.keys.values()[0]["pkcs11_pin"]]
		for k in self.keys.values():
			# TODO err, this should be ksks and zsks
			cmd.append(k["tool_key_id"])

		p4 = Util.run_tool(cmd, p3.stdout)
		
		# this directly write the output to the final name, which
		# will mangle the signed zone file if anything goes wrong
		# TODO: write to tmp file, and move on success
		output_file = self.engine_config.zone_output_dir + os.sep + self.zone_name + ".signed"
		output = open(output_file, "w")
		output.write("; Zone signed at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
		for l in p4.stdout:
			output.write(l)
		for l in p4.stderr:
			print l
		output.close()
		status = p4.wait()
		Util.debug(3, "signer result: " + str(status));
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

	# not sure whether we will get the data from a file or not, so just wrap
	# around the general string case instead of using 'minidom.parse()'
	def from_xml_file(self, file):
		f = open(file, "r")
		s = f.read()
		f.close()
		x = minidom.parseString(s)
		self.from_xml(x)
		x.unlink()

	# signer_config is the xml blob described in
	# http://www.opendnssec.se/browser/docs/signconf.xml
	def from_xml(self, signer_config):
		# todo: check the zone name just to be sure?
		# and some general error checking might be nice

		xmlbs = Evaluate("signconf/keystore/key", signer_config)
		for xmlb in xmlbs:
			key = {}
			id = int(xmlb.attributes["id"].value)
			key["id"] = id
			key["name"] = Evaluate("name", xmlb)[0].firstChild.data
			key["ttl"] = Util.parse_duration(Evaluate("ttl", xmlb)[0].firstChild.data)
			key["flags"] = int(Evaluate("flags", xmlb)[0].firstChild.data)
			key["protocol"] = int(Evaluate("protocol", xmlb)[0].firstChild.data)
			key["algorithm"] = int(Evaluate("algorithm", xmlb)[0].firstChild.data)
			key["locator"] = Evaluate("locator", xmlb)[0].firstChild.data
			# calculate and cache this one later
			key["dnskey"] = None
			# pkcs11_module and tool_key_id are filled in as they are needed
			# tool_key_id is the id of the key as it is needed by the signing
			# tools; (ie. <id>_<algo>)
			key["pkcs11_module"] = None
			key["pkcs11_pin"] = None
			key["tool_key_id"] = None
			# todo: remove here, do on demand?
			self.find_key_details(key)
			self.keys[id] = key

		xmlb = Evaluate("signconf/signatures/resign", signer_config)[0].firstChild
		self.signatures_resign_time = Util.parse_duration(xmlb.data)

		xmlb = Evaluate("signconf/signatures/refresh", signer_config)[0].firstChild
		self.signatures_refresh_time = Util.parse_duration(xmlb.data)
		
		xmlb = Evaluate("signconf/signatures/validity/default", signer_config)[0].firstChild
		self.signatures_validity_default = Util.parse_duration(xmlb.data)
		
		xmlb = Evaluate("signconf/signatures/validity/nsec", signer_config)[0].firstChild
		self.signatures_validity_nsec = Util.parse_duration(xmlb.data)
		
		xmlb = Evaluate("signconf/signatures/jitter", signer_config)[0].firstChild
		self.signatures_jitter = Util.parse_duration(xmlb.data)

		xmlb = Evaluate("signconf/signatures/clockskew", signer_config)[0].firstChild
		self.signatures_clockskew = Util.parse_duration(xmlb.data)

		xmlb = Evaluate("signconf/denial/ttl", signer_config)[0].firstChild
		self.denial_ttl = Util.parse_duration(xmlb.data)

		xmlb = Evaluate("signconf/denial/nsec", signer_config)[0].firstChild
		if xmlb:
			self.denial_nsec = True

		xmlb = Evaluate("signconf/denial/nsec3", signer_config)[0].firstChild
		if xmlb:
			self.denial_nsec3 = True
			xmlb = Evaluate("signconf/denial/nsec3/out-out", signer_config)[0].firstChild
			if xmlb:
				self.denial_nsec3_optout = True
			xmlb = Evaluate("signconf/denial/nsec3/hash/algorithm", signer_config)[0].firstChild
			self.denial_nsec3_algorithm = int(xmlb.data)
			xmlb = Evaluate("signconf/denial/nsec3/hash/iterations", signer_config)[0].firstChild
			self.denial_nsec3_iterations = int(xmlb.data)
			xmlb = Evaluate("signconf/denial/nsec3/hash/salt", signer_config)[0].firstChild
			self.denial_nsec3_salt = xmlb.data
			# calc and cache this later?
			self.nsec3_param_rr = None

# quick test-as-we-go function
if __name__=="__main__":
	# this will of course be retrieved from the general zone config dir
	z = Zone("zone1.example", EngineConfiguration("/home/jelte/repos/opendnssec/signer_engine/engine.conf"))
	z.from_xml_file(z.engine_config.zone_config_dir + os.sep + "zone1.example.xml")
	z.sign()
