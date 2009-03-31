"""
This class keeps track of engine configuration options
There is an example config file in <repos>/signer_engine/engine.conf
"""
# todo: allow for spaces in dir?

import re
import getpass

COMMENT_LINE = re.compile("\s*([#;].*)?$")
PKCS_LINE = re.compile(\
 "pkcs11_token: (?P<name>\w+)\s+(?P<module_path>.+)\s+(?P<pin>\d+)?\s*$")

class EngineConfiguration:
    """Engine Configuration options"""
    def __init__(self, config_file_name=None):
        self.tokens = []
        self.zone_input_dir = None
        self.zone_tmp_dir = None
        self.zone_output_dir = None
        self.zone_config_dir = None
        self.tools_dir = None
        if config_file_name:
            self.read_config_file(config_file_name)
        
    def read_config_file(self, config_file_name):
        """Read a configuration file"""
        config_file = open(config_file_name, "r")
        for line in config_file:
            if not COMMENT_LINE.match(line):
                pkcs_line = PKCS_LINE.match(line)
                if pkcs_line:
                    token = {}
                    token["name"] = pkcs_line.group("name")
                    token["module_path"] = \
                        pkcs_line.group("module_path")
                    if pkcs_line.group("pin"):
                        token["pin"] = pkcs_line.group("pin")
                    else:
                        token["pin"] = self.query_pin(token)
                    self.tokens.append(token)
                elif line[:15] == "zone_input_dir:":
                    self.zone_input_dir = line[15:].strip()
                elif line[:16] == "zone_output_dir:":
                    self.zone_output_dir = line[16:].strip()
                elif line[:16] == "zone_config_dir:":
                    self.zone_config_dir = line[16:].strip()
                elif line[:13] == "zone_tmp_dir:":
                    self.zone_tmp_dir = line[13:].strip()
                elif line[:10] == "tools_dir:":
                    # this one should not be necessary later
                    self.tools_dir = line[10:].strip()
                else:
                    raise Exception(
                            "Error parsing configuration line: " + line)

    def query_pin(self, token):
        """Queries for the PIN, which isn't checked further (erroneous
        PIN will simply result in errors later. Token is the associative
        array as created in EngineConfiguration.read_config_file()"""
        pin = getpass.getpass("Please enter the PIN for token " + token["name"] + ": ")
        return pin
    
