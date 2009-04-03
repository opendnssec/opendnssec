"""Some general utility functions"""

import subprocess
import re
from datetime import datetime
import syslog
from Ft.Xml.XPath import Evaluate
import getpass
import shutil

class ToolException(Exception):
    """General exception class for exceptions when running external
    programs, like the signer tools"""
    pass

def run_tool(command, input_fd=None):
    """Run a system command with Popen(), if input_fd is not given,
       it will be set to PIPE. The subprocess is returned."""
    syslog.syslog(syslog.LOG_DEBUG, "Run command: '"+" ".join(command)+"'")
    if (input_fd):
        subp = subprocess.Popen(command, stdin=input_fd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    else:
        subp = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    return subp

# for a single xml durection object, with only 1 path
# for more elaborate paths, diy
def get_xml_data(xpath, xml, optional=False):
    """Get the element data of the first element specified by the xpath
       that is found in the xml blob. If optional is true, None is
       returned if it cannot be found. Otherwise an exception will be
       raised."""
    try:
        xmlb = Evaluate(xpath, xml)
        if xmlb and len(xmlb) > 0 and xmlb[0].firstChild:
            return xmlb[0].firstChild.data
        elif optional:
            return None
        else:
            raise Exception("Mandatory XML element not found: " + xpath)
    except IndexError:
        if optional:
            return None
        else:
            raise Exception("Mandatory XML element not found: " + xpath)

# months default to 31 days
# does not account for leap-seconds etc
# 3 ways to specify duration
DURATION_REGEX = re.compile("^(?P<negative>-)?P"
                            "(?:(?P<years>[0-9]+)Y)?"
                            "(?:(?P<months>[0-9]+)M)?"
                            "(?:(?P<weeks>[0-9]+)W)?"
                            "(?:(?P<days>[0-9]+)D)?"
                            "(?:T"
                            "(?:(?P<hours>[0-9]+)H)?"
                            "(?:(?P<minutes>[0-9]+)M)?"
                            "(?:(?P<seconds>[0-9]+)S)?"
                            ")?$"
                           )
DURATION_REGEX_ALT = re.compile("^(?P<negative>-)?P"
                                "(?P<years>[0-9]{4})"
                                "(?P<months>[0-9]{2})"
                                "(?P<weeks>)"
                                "(?P<days>[0-9]{2})"
                                "T"
                                "(?P<hours>[0-9]{2})"
                                "(?P<minutes>[0-9]{2})"
                                "(?P<seconds>[0-9]{2})"
                               )
DURATION_REGEX_ALT2 = re.compile("^(?P<negative>-)?P"
                                "(?P<years>[0-9]{4})"
                                "-(?P<months>[0-9]{2})"
                                "(?P<weeks>)"
                                "-(?P<days>[0-9]{2})"
                                "T"
                                "(?P<hours>[0-9]{2})"
                                ":(?P<minutes>[0-9]{2})"
                                ":(?P<seconds>[0-9]{2})"
                               )

def write_p(subp, val, prefix):
    """If val is not None, write prefix + str(val) + "\n" to the stdin
    of subp"""
    if subp.stdin and val:
        syslog.syslog(syslog.LOG_DEBUG,
                      "write to subp: " +\
                      prefix + str(val))
        subp.stdin.write(prefix)
        subp.stdin.write(str(val))
        subp.stdin.write("\n")

def datestamp(timestamp):
    """Returns the date (YYYYMMddhhmmss) representation of the given
    timestamp (seconds since epoch)"""
    return datetime.utcfromtimestamp(timestamp).strftime("%Y%m%d%H%M%S")

def parse_duration(duration_string):
    """Parse an XML duration string. The number of seconds represented
       by the string is returned"""
    if not duration_string:
        return None
    match = DURATION_REGEX.match(duration_string)
    result = 0
    if not match:
        # raise error
        match = DURATION_REGEX_ALT.match(duration_string)
        if not match:
            match = DURATION_REGEX_ALT2.match(duration_string)
            if not match:
                raise Exception("Bad duration format: " +duration_string)

    grp = match.group("years")
    if grp:
        result += 31556926 * int(grp)
    grp = match.group("months")
    if grp:
        result += 2678400 * int(grp)
    grp = match.group("weeks")
    if grp:
        result += 604800 * int(grp)
    grp = match.group("days")
    if grp:
        result += 86400 * int(grp)
    grp = match.group("hours")
    if grp:
        result += 3600 * int(grp)
    grp = match.group("minutes")
    if grp:
        result += 60 * int(grp)
    grp = match.group("seconds")
    if grp:
        result += int(grp)

    if match.group("negative"):
        return -result
    else:
        return result

def query_pin(token):
    """Queries for the PIN, which isn't checked further (erroneous
    PIN will simply result in errors later. Token is the associative
    array as created in EngineConfiguration.read_config_file()"""
    pin = getpass.getpass("Please enter the PIN for token " +\
                          token["name"] + ": ")
    return pin

def move_file(source, target):
    """Moves a file; if the target file exists it is deleted"""
    shutil.move(source, target)
