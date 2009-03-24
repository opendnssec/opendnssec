"""Configuration of a Zone, as specified in the xml file"""

from xml.dom import minidom
from Ft.Xml.XPath import Evaluate

import Util

class ZoneConfig:
    """Configuration of a Zone, as specified in the xml file"""
    NO_CHANGE   = 0
    NO_SCHEDULE = 1
    RESCHEDULE  = 2
    RESORT      = 3
    RENSEC      = 4
    RESIGN      = 5
    
    def __init__(self, xml_file=None):
        self.signatures_resign_time = 0
        self.signatures_refresh_time = 0
        self.signatures_validity_default = 0
        self.signatures_validity_nsec = 0
        self.signatures_jitter = 0
        self.signatures_clockskew = 0
        #self.signatures_zsk_refs = []
        #self.signatures_ksk_refs = []
        self.publish_keys = []
        self.denial_nsec = False
        self.denial_nsec3 = False
        self.denial_nsec3_optout = False
        self.denial_nsec3_algorithm = None
        self.denial_nsec3_iterations = 0
        self.denial_nsec3_salt = None
        self.nsec3_param_rr = None
        # i still think nsec TTL should not be configurable
        self.denial_nsec3_ttl = 0
        self.keys = {}
        self.signature_keys = []
        self.publish_keys = []

        self.denial_ttl = None

        self.soa_ttl = None
        self.soa_minimum = None
        self.soa_serial = None

        if file:
            self.from_xml_file(xml_file)

    # we don't override __cmp__ because we use self-defined results
    # from low to high: every results implies the above ones
    # (is that a correct assumption?)
    # NO_CHANGE   0
    # NO_SCHEDULE 1
    # RESCHEDULE  2
    # RESORT      3
    # RENSEC      4
    # RESIGN      5
    # 
    def compare_config(self, ocfg):
        """Compares this configuration to another one. The result value
        will specify what to do with the zone according to the changes
        in the configuration."""
        # seperate if's will probably be usefule for debugging this
        # The if statements are ordered by result
        result = self.NO_CHANGE

        if self.publish_keys != ocfg.publish_keys:
            result = self.RESORT
        elif self.denial_nsec != ocfg.denial_nsec:
            result = self.RESORT
        elif self.denial_nsec3 != ocfg.denial_nsec3:
            result = self.RESORT
        elif self.publish_keys != ocfg.publish_keys:
            result = self.RESORT
        elif self.nsec3_param_rr != ocfg.nsec3_param_rr:
            result = self.RESORT

        elif self.denial_nsec3_optout != ocfg.denial_nsec3_optout:
            result = self.RENSEC
        elif self.denial_nsec3_algorithm != ocfg.denial_nsec3_algorithm:
            result = self.RENSEC
        elif self.denial_nsec3_iterations != ocfg.denial_nsec3_iterations:
            result = self.RENSEC
        elif self.denial_nsec3_salt != ocfg.denial_nsec3_salt:
            result = self.RENSEC
        # i still think nsec TTL should not be configurable
        elif self.denial_nsec3_ttl != ocfg.denial_nsec3_ttl:
            result = self.RENSEC
        elif self.denial_ttl != ocfg.denial_ttl:
            result = self.RENSEC

        elif self.signature_keys != ocfg.signature_keys:
            result = self.RESIGN
        elif self.soa_ttl != ocfg.soa_ttl:
            result = self.RESIGN
        elif self.soa_minimum != ocfg.soa_minimum:
            result = self.RESIGN
        elif self.soa_serial != ocfg.soa_serial:
            result = self.RESIGN

        elif self.signatures_resign_time != ocfg.signatures_resign_time:
            result = self.RESCHEDULE
        elif self.signatures_refresh_time != ocfg.signatures_refresh_time:
            result = self.RESCHEDULE

        elif self.signatures_validity_default != \
           ocfg.signatures_validity_default:
            result = self.NO_SCHEDULE
        elif self.signatures_validity_nsec != \
           ocfg.signatures_validity_nsec:
            result = self.NO_SCHEDULE
        elif self.signatures_jitter != ocfg.signatures_jitter:
            result = self.NO_SCHEDULE
        elif self.signatures_clockskew != ocfg.signatures_clockskew:
            result = self.NO_SCHEDULE
        
        # todo: lists cannot be ==/!='d can they? loop?
        elif self.keys != ocfg.keys:
            result = self.NO_SCHEDULE
        return result

    def from_xml_file(self, xml_file_name):
        """Read xml from from xml_file_name to a string,
        and parse the xml"""
        xml_file = open(xml_file_name, "r")
        xml_string = xml_file.read()
        xml_file.close()
        xml_blob = minidom.parseString(xml_string)
        self.from_xml(xml_blob)
        xml_blob.unlink()

    # signer_config is the xml blob described in
    # http://www.opendnssec.se/browser/docs/signconf.xml
    def from_xml(self, signer_config):
        """Read the configuration from the xml blob in signer_config.
        signer_config should be created by minidom.parseString"""
        # todo: check the zone name just to be sure?

        keystore_keys = Evaluate("signconf/keystore/key", signer_config)
        for key_xml in keystore_keys:
            key_id = int(key_xml.attributes["id"].value)
            key = {}
            key["id"] = key_id
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
            self.keys[key_id] = key

        self.signatures_resign_time = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/resign",
                              signer_config))
        self.signatures_refresh_time = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/refresh",
                              signer_config))
        self.signatures_validity_default = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/validity/default",
                              signer_config))
        self.signatures_validity_nsec = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/validity/nsec",
                              signer_config))
        self.signatures_jitter = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/jitter",
                              signer_config))
        self.signatures_clockskew = Util.parse_duration(
            Util.get_xml_data("signconf/signatures/clockskew",
                              signer_config))
        self.denial_ttl = Util.parse_duration(
            Util.get_xml_data("signconf/denial/ttl",
                              signer_config))
        xmlbs = Evaluate("signconf/signatures/zsk", signer_config)
        for xmlb in xmlbs:
            # todo catch keyerror
            # todo2: error if sep flag was not set?
            self.signature_keys.append(
                self.keys[int(xmlb.attributes["keyid"].value)])
        xmlbs = Evaluate("signconf/signatures/ksk", signer_config)
        for xmlb in xmlbs:
            # todo catch keyerror
            # todo2: error if sep flag was not set?
            self.signature_keys.append(
                self.keys[int(xmlb.attributes["keyid"].value)])

        xmlbs = Evaluate("signconf/publish", signer_config)
        for xmlb in xmlbs:
            # todo catch keyerror
            # todo2: error if sep flag was set?
            self.publish_keys.append(
                self.keys[int(xmlb.attributes["keyid"].value)])

        if Evaluate("signconf/denial/nsec", signer_config):
            self.denial_nsec = True

        nsec3_xmls = Evaluate("signconf/denial/nsec3", signer_config)
        for nsec3_xml in nsec3_xmls:
            self.denial_nsec3 = True
            if Evaluate("opt-out", nsec3_xml):
                self.denial_nsec3_optout = True
            self.denial_nsec3_algorithm = \
                int(Util.get_xml_data("hash/algorithm", nsec3_xml))
            self.denial_nsec3_iterations = \
                int(Util.get_xml_data("hash/iterations", nsec3_xml))
            self.denial_nsec3_salt = \
                Util.get_xml_data("hash/salt", nsec3_xml)

        self.soa_ttl = Util.parse_duration(
            Util.get_xml_data("signconf/soa/ttl", signer_config, True))
        self.soa_minimum = Util.parse_duration(
            Util.get_xml_data("signconf/soa/min", signer_config, True))
        # todo: check for known values
        self.soa_serial = Util.get_xml_data("signconf/soa/serial",
                                            signer_config, True)
        


