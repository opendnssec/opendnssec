"""
This class keeps track of engine configuration options
There is an example config file in <repos>/signer_engine/engine.conf
"""
# todo: allow for spaces in dir?

import os
import re
import Util
from xml.dom import minidom
from xml.parsers.expat import ExpatError
from Ft.Xml.XPath import Evaluate

COMMENT_LINE = re.compile("\s*([#;].*)?$")
PKCS_LINE = re.compile(\
 "pkcs11_token: (?P<name>\w+)\s+(?P<module_path>\S+)\s*(?P<pin>\d+)?\s*$")

class EngineConfigurationError(Exception):
    """This exception is thrown when the engine configuration file
    cannot be parsed, or contains another error."""
    pass
#    def __init__(self, value):
#        self.parameter = value
#    def __str__(self):
#        return repr(self.parameter)

class EngineConfiguration:
    """Engine Configuration options"""
    def __init__(self, config_file_name=None):
        self.tokens = []
        self.zonelist_file = None
        self.zone_tmp_dir = None
        self.tools_dir = None
        self.notify_script = None
        if config_file_name:
            self.read_config_file(config_file_name)
        
    def read_config_file(self, input_file):
        """Read a configuration file"""
        try:
            conff = open(input_file, "r")
            xstr = conff.read()
            conff.close()
            xmlb = minidom.parseString(xstr)
            self.from_xml(xmlb)
            xmlb.unlink()
        except ExpatError, exe:
            raise EngineConfigurationError(str(exe))
        except IOError, ioe:
            raise EngineConfigurationError(str(ioe))

    def from_xml(self, xml_blob):
        """Searches the xml blob for the configuration values"""
        xmlbs = Evaluate("OpenDNSSEC/HSM/Repository", xml_blob)
        for xmlb in xmlbs:
            token = {}
            token["name"] = Util.get_xml_data("Name", xmlb)
            token["module_path"] = Util.get_xml_data("Module", xmlb)
            token["pin"] = Util.get_xml_data("PIN", xmlb, True)
            if not token["pin"]:
                token["pin"] = Util.query_pin(token)
            self.tokens.append(token)

        self.zonelist_file = \
             Util.get_xml_data("OpenDNSSEC/Signer/ZoneListFile",
                               xml_blob, True)
        self.zone_tmp_dir = \
             Util.get_xml_data("OpenDNSSEC/Signer/WorkingDirectory",
                               xml_blob, True)
        self.tools_dir = \
             Util.get_xml_data("OpenDNSSEC/Signer/ToolsDirectory",
                               xml_blob, True)
        self.notify_command = \
             Util.get_xml_data("OpenDNSSEC/Signer/NotifyCommand",
                               xml_blob, True)
        # TODO: defaults! (for which we need some ./configure etc)

    def check_config(self):
        """Verifies whether the configuration is correct for the
        signer. Raises an EngineConfigurationError when there
        seems to be a problem"""
        if len(self.tokens) < 1:
            raise EngineConfigurationError("No tokens configured")
        # do we need to check the zonelist file too?
        # there is the possibility that the kasp hasn't created it
        # yet
        if not os.path.exists(self.zone_tmp_dir):
            raise EngineConfigurationError(\
                "WorkingDirectory does not exist")
        if not os.path.exists(self.tools_dir):
            raise EngineConfigurationError(\
                "tools does not exist")
        if not os.path.exists(self.tools_dir + os.sep + "signer_pkcs11"):
            raise EngineConfigurationError(\
                "signer tools appear missing")
