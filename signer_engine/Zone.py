#
# This class defines Zones, with all information needed to sign them
# 

import os
import time
import errno
from xml.dom import minidom

import Util

# tmp for initial tests
import sys

# todo: move paths to general engine config
basedir = "../signer_tools";


# quick 'n dirty xml parsing against a moving target
def getChildByTagName(element, tag):
	for e in element.childNodes:
		if e.nodeName == tag:
			return e
	# raise exception instead of return none?
	return None

def getChildrenByTagName(element, tag):
	res = []
	for e in element.childNodes:
		if e.tagName == tag:
			res.append(e)
	return res

def getText(element):
	res = []
	for c in element.childNodes:
		if c.nodeType == c.TEXT_NODE:
			res.append(c.data)
	return "".join(res)

# returns time in seconds of 
# an <el unit="weeks">213</el> type tag
def getTimeVal(element):
	val = int(getText(element))
	# default to seconds?
	modifier = 1;
	if element.hasAttribute("unit"):
		unit = element.getAttribute("unit")
		if unit == "minutes":
			modifier = 60
		elif unit == "hours":
			modifier = 3600
		elif unit == "days":
			modifier = 86400
		elif unit == "weeks":
			modifier = 604800
		else:
			# TODO: raise exception etc
			print "Error, unknown unit " + resign_unit
	return val * modifier



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
		
		# information received from KASP through the xml file
		# old
		self.keys = None
		self.resign_interval = 0
		
		# new
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
		self.denial_nsec3 = False
		self.denial_nsec3_opt_out = False
		self.denial_nsec3_hash_algorithm = None
		self.denial_nsec3_iterations = 0
		self.denial_nsec3_salt = None
		# i still think nsec TTL should not be configurable
		self.denial_nsec3_ttl = 0
	
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

	# not sure whether we will get the data from a file or not, so just wrap
	# around the general string case instead of using 'minidom.parse()'
	def from_xml_file(self, file):
		f = open(file, "r")
		s = f.read()
		f.close()
		self.from_xml(s)

	def getText(self,nodelist):
		rc = ""
		for node in nodelist:
			if node.nodeType == node.TEXT_NODE:
				rc = rc + node.data
		return rc

	def from_xml_zone_nodes(self, nodes):
		for node in nodes:
			if node.nodeName == "name":
				print "name!"
		

	# quick 'n dirty xml parsing against a moving target
	# this should probably only be on the <zone/> element, not on all
	def from_xml(self, string):
		print "read"
		dom = minidom.parseString(string)
		#dom.writexml(sys.stdout)
		sc_node = getChildByTagName(dom, "signer-config")
		z_node = getChildByTagName(sc_node, "zone")
		z_name = getChildByTagName(z_node, "name")
		if self.zone_name != getText(z_name):
			print "Error: zone configuration for different zone (" + self.zone_name + " != " + getText(z_name) + ")"
			# todo: raise some cool exception thing
		sigs_node = getChildByTagName(z_node, "signatures")
		self.signatures_resign_time = getTimeVal(getChildByTagName(sigs_node, "resign"))
		self.signatures_refresh_time = getTimeVal(getChildByTagName(sigs_node, "refresh"))
		validity_node = getChildByTagName(sigs_node, "validity")
		self.signatures_validity_default = getTimeVal(getChildByTagName(validity_node, "default"))
		self.signatures_validity_nsec = getTimeVal(getChildByTagName(validity_node, "nsec"))
		self.signatures_jitter = getTimeVal(getChildByTagName(sigs_node, "jitter"))
		

		#self.signatures_resign_time = 0
		#self.signatures_refresh_time = 0
		#self.signatures_validity_default = 0
		#self.signatures_validity_nsec = 0
		#self.signatures_jitter = 0
		#self.signatures_zsk_refs = []
		#self.signatures_ksk_refs = []
		#self.publish_keys = []
		#self.denial_nsec3 = False
		#self.denial_nsec3_opt_out = False
		#self.denial_nsec3_hash_algorithm = None
		#self.denial_nsec3_iterations = 0
		#self.denial_nsec3_salt = None
		## i still think nsec TTL should not be configurable
		#self.denial_nsec3_ttl = 0

		print "resign interval: " + str(self.resign_interval) + " seconds"
		#print dom.toxml()
		dom.unlink()

if __name__=="__main__":
	print "yoyo"
	z = Zone("zone1.example", "/tmp/zone1.example", "/tmp/zone1.example.signed")
	z.from_xml_file("/tmp/zone1.example-config.xml");
	
