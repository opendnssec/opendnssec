# $Id$
#
# Copyright (c) 2009 NLNet Labs. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""Configuration of a Zone, as specified in the xml file"""

import os
from xml.dom import minidom
from Ft.Xml.XPath import Evaluate
from xml.parsers.expat import ExpatError

import Util

class ZoneConfigError(Exception):
    """Raised if the zone config xml file cannot be parsed"""
    pass

class ZoneConfig:
    """Configuration of a Zone, as specified in the xml file"""
    NO_CHANGE   = 0
    NO_SCHEDULE = 1
    RESCHEDULE  = 2
    RESORT      = 3
    REREAD      = 4
    RENSEC      = 5
    RESIGN      = 6
    
    def __init__(self, xml_file=None):
        self.signatures_resign_time = 0
        self.signatures_refresh_time = 0
        self.signatures_validity_default = 0
        self.signatures_validity_denial = 0
        self.signatures_validity_keys = 0
        self.signatures_jitter = 0
        self.signatures_inception_offset = 0
        #self.signatures_zsk_refs = []
        #self.signatures_ksk_refs = []
        self.denial_nsec = False
        self.denial_nsec3 = False
        self.denial_nsec3_optout = False
        self.denial_nsec3_algorithm = None
        self.denial_nsec3_iterations = 0
        self.denial_nsec3_salt = None
        self.nsec3_param_rr = None
        self.dnskey_ttl = None
        self.keys = {}
        self.signature_keys = []
        self.publish_keys = []

        self.soa_ttl = None
        self.soa_minimum = None
        self.soa_serial = None
        
        self.audit = True

        self.last_modified = None
        self.xml_file = xml_file
        if file:
            self.from_xml_file(xml_file)

    # we don't override __cmp__ because we use self-defined results
    # from low to high: every results implies the above ones
    # (is that a correct assumption?)
    def compare_config(self, ocfg):
        """Compares this configuration to another one. The result value
        will specify what to do with the zone according to the changes
        in the configuration."""
        # seperate if's will probably be usefule for debugging this
        # The if statements are ordered by result
        result = self.NO_CHANGE

        if self.publish_keys != ocfg.publish_keys or \
           self.denial_nsec != ocfg.denial_nsec or \
           self.denial_nsec3 != ocfg.denial_nsec3 or \
           self.publish_keys != ocfg.publish_keys or \
           self.denial_nsec3_algorithm != \
                 ocfg.denial_nsec3_algorithm  or \
           self.denial_nsec3_iterations != \
                 ocfg.denial_nsec3_iterations or \
           self.denial_nsec3_salt != ocfg.denial_nsec3_salt or \
           self.nsec3_param_rr != ocfg.nsec3_param_rr:
            result = self.RESORT

        elif self.denial_nsec3_optout != ocfg.denial_nsec3_optout:
            result = self.RENSEC

        elif self.signature_keys != ocfg.signature_keys or \
             self.soa_ttl != ocfg.soa_ttl or \
             self.soa_minimum != ocfg.soa_minimum or \
             self.soa_serial != ocfg.soa_serial:
            result = self.RESIGN

        elif self.signatures_resign_time != \
                 ocfg.signatures_resign_time or \
             self.signatures_refresh_time != \
                 ocfg.signatures_refresh_time:
            result = self.RESCHEDULE

        elif self.signatures_validity_default != \
                 ocfg.signatures_validity_default or \
             self.signatures_validity_denial != \
                 ocfg.signatures_validity_denial or \
             self.signatures_validity_keys != \
                 ocfg.signatures_validity_keys or \
             self.signatures_jitter != ocfg.signatures_jitter or \
             self.signatures_inception_offset != \
                ocfg.signatures_inception_offset:
            result = self.NO_SCHEDULE
        
        # todo: lists cannot be ==/!='d can they? loop?
        elif self.keys != ocfg.keys:
            result = self.NO_SCHEDULE
        return result

    def check_config_file_update(self):
        """Returns true if the configured config file has a
        last-modified time that is more recent than the one found when
        we read the configuration for this zone. Returns true if the
        configuration file hasn't been read at all."""
        return not self.last_modified or \
               os.stat(self.xml_file).st_mtime \
               > self.last_modified        

    def from_xml_file(self, xml_file_name):
        """Read xml from from xml_file_name to a string,
        and parse the xml"""
        try:
            xml_file = open(xml_file_name, "r")
            xml_string = xml_file.read()
            xml_file.close()
            xml_blob = minidom.parseString(xml_string)
            self.from_xml(xml_blob)
            xml_blob.unlink()
            self.last_modified = os.stat(xml_file_name).st_mtime
        except ExpatError, exe:
            raise ZoneConfigError(str(exe))
        except IOError, ioe:
            raise ZoneConfigError(str(ioe))

    # signer_config is the xml blob described in
    # http://www.opendnssec.se/browser/docs/signconf.xml
    def from_xml(self, signer_config):
        """Read the configuration from the xml blob in signer_config.
        signer_config should be created by minidom.parseString"""
        # todo: check the zone name just to be sure?

        keystore_keys = Evaluate("SignerConfiguration/Zone/Keys/Key",
                                 signer_config)
        for key_xml in keystore_keys:
            #key_id = int(key_xml.attributes["id"].value)
            key = {}
            key["locator"] = Util.get_xml_data("Locator", key_xml)
            key["ttl"] = Util.parse_duration(
                Util.get_xml_data("SignerConfiguration/Zone/Keys/TTL",
                                  signer_config))
            key["flags"] = int(Util.get_xml_data("Flags", key_xml))
            key["protocol"] = 3
            key["algorithm"] = int(Util.get_xml_data("Algorithm",
                                                     key_xml))
            if Evaluate("ZSK", key_xml):
                key["zsk"] = True
            else:
                key["zsk"] = False
            if Evaluate("KSK", key_xml):
                key["ksk"] = True
            else:
                key["ksk"] = False
            if key["ksk"] or key["zsk"]:
                self.signature_keys.append(key)

            # calculate and cache these values later
            key["dnskey"] = None
            key["token_label"] = None
            key["pkcs11_module"] = None
            key["pkcs11_pin"] = None
            key["tool_key_id"] = None
            self.keys[key["locator"]] = key
            if Evaluate("Publish", key_xml):
                self.publish_keys.append(key)

        self.signatures_resign_time = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Resign",
                signer_config))
        self.signatures_refresh_time = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Refresh",
                signer_config))
        self.signatures_validity_default = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Validity/Default",
                signer_config))
        self.signatures_validity_denial = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Validity/Denial",
                signer_config))
        self.signatures_validity_keys = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Validity/Keys",
                signer_config))
        if self.signatures_validity_denial == 0:
            self.signatures_validity_denial = self.signatures_validity_default
        if self.signatures_validity_keys == 0:
            self.signatures_validity_keys = self.signatures_validity_default
        self.signatures_jitter = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/Jitter",
                signer_config))
        self.signatures_inception_offset = Util.parse_duration(
            Util.get_xml_data(
                "SignerConfiguration/Zone/Signatures/InceptionOffset",
                signer_config))
        xmlbs = Evaluate("SignerConfiguration/Zone/Signatures/zsk",
                         signer_config)
        for xmlb in xmlbs:
            # todo catch keyerror
            self.signature_keys.append(
                self.keys[int(xmlb.attributes["keyid"].value)])
        xmlbs = Evaluate("SignerConfiguration/Zone/Signatures/ksk",
                         signer_config)
        for xmlb in xmlbs:
            # todo catch keyerror
            # todo2: error if sep flag was not set?
            self.signature_keys.append(
                self.keys[int(xmlb.attributes["keyid"].value)])

        if Evaluate("SignerConfiguration/Zone/Denial/NSEC",
                    signer_config):
            self.denial_nsec = True
            self.denial_nsec3 = False

        nsec3_xmls = Evaluate("SignerConfiguration/Zone/Denial/NSEC3",
                              signer_config)
        for nsec3_xml in nsec3_xmls:
            self.denial_nsec3 = True
            self.denial_nsec = False
            if Evaluate("OptOut", nsec3_xml):
                self.denial_nsec3_optout = True
            self.denial_nsec3_algorithm = \
                int(Util.get_xml_data("Hash/Algorithm", nsec3_xml))
            self.denial_nsec3_iterations = \
                int(Util.get_xml_data("Hash/Iterations", nsec3_xml))
            self.denial_nsec3_salt = \
                Util.get_xml_data("Hash/Salt", nsec3_xml, 1)

        self.dnskey_ttl = Util.parse_duration(
            Util.get_xml_data("SignerConfiguration/Zone/Keys/TTL",
                              signer_config, True))

        self.soa_ttl = Util.parse_duration(
            Util.get_xml_data("SignerConfiguration/Zone/SOA/TTL",
                              signer_config, True))
        self.soa_minimum = Util.parse_duration(
            Util.get_xml_data("SignerConfiguration/Zone/SOA/Minimum",
                              signer_config, True))
		
        # todo: check for known values
        self.soa_serial = Util.get_xml_data(
            "SignerConfiguration/Zone/SOA/Serial", signer_config, True)
        if self.soa_serial not in ["keep", "unixtime", "datecounter", "counter" ]:
            raise ZoneConfigError("Serial option should be one of: " +
                                 "keep, unixtime, datecounter, counter")
        if Evaluate("SignerConfiguration/Zone/Audit", signer_config):
            self.audit = True
        else:
            self.audit = False

