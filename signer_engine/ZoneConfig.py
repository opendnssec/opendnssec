#
# Configuratin of a Zone, as specified in the xml file
#

from xml.dom import minidom
from Ft.Xml.XPath import Evaluate

import Util

class ZoneConfig:
    def __init__(self, xml_file=None):
        self.signatures_resign_time = 0
        self.signatures_refresh_time = 0
        self.signatures_validity_default = 0
        self.signatures_validity_nsec = 0
        self.signatures_jitter = 0
        self.signatures_clockskew = 0
        self.signatures_zsk_refs = []
        self.signatures_ksk_refs = []
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
        self.nsec3_param_rr = None

        self.soa_ttl = None
        self.soa_minimum = None
        self.soa_serial = None

        if file:
            self.from_xml_file(xml_file)

    # not sure whether we will get the data from a file or not, so just wrap
    # around the general string case instead of using 'minidom.parse()'
    def from_xml_file(self, xml_file_name):
        xml_file = open(xml_file_name, "r")
        xml_string = xml_file.read()
        xml_file.close()
        xml_blob = minidom.parseString(xml_string)
        self.from_xml(xml_blob)
        xml_blob.unlink()

    # signer_config is the xml blob described in
    # http://www.opendnssec.se/browser/docs/signconf.xml
    def from_xml(self, signer_config):
        # todo: check the zone name just to be sure?
        # and some general error checking might be nice

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
        


