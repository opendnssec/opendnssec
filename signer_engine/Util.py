#
# some generaly utility functions
#

import subprocess
import Util
import re
import syslog
from datetime import timedelta
from Ft.Xml.XPath import Evaluate

verbosity = 2;

def debug(level, message):
    if level <= verbosity:
        print(message)

def run_tool(command, input=None):
    syslog.syslog(syslog.LOG_DEBUG, "Run command: '"+" ".join(command)+"'")
    if (input):
        p = subprocess.Popen(command, stdin=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p

# for a single xml durection object, with only 1 path
# for more elaborate paths, diy
def get_xml_data(xpath, xml, optional=False):
    try:
        xmlb = Evaluate(xpath, xml)
        if xmlb and len(xmlb) > 0 and xmlb[0].firstChild:
            return xmlb[0].firstChild.data
        elif optional:
            return None
        else:
            raise Exception("Mandatory XML element not found: " + xpath)
    except IndexError, e:
        if optional:
            return None
        else:
            raise Exception("Mandatory XML element not found: " + xpath)

# months default to 31 days
# does not account for leap-seconds etc
# 3 ways to specify duration
DURATION_REGEX = re.compile("^P"
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
DURATION_REGEX_ALT = re.compile("^P"
                                "(?P<years>[0-9]{4})"
                                "(?P<months>[0-9]{2})"
                                "(?P<weeks>)"
                                "(?P<days>[0-9]{2})"
                                "T"
                                "(?P<hours>[0-9]{2})"
                                "(?P<minutes>[0-9]{2})"
                                "(?P<seconds>[0-9]{2})"
                               )
DURATION_REGEX_ALT2 = re.compile("^P"
                                "(?P<years>[0-9]{4})"
                                "-(?P<months>[0-9]{2})"
                                "(?P<weeks>)"
                                "-(?P<days>[0-9]{2})"
                                "T"
                                "(?P<hours>[0-9]{2})"
                                ":(?P<minutes>[0-9]{2})"
                                ":(?P<seconds>[0-9]{2})"
                               )

def parse_duration(duration_string):
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

    g = match.group("years")
    if g:
        result += 31556926 * int(g)
    g = match.group("months")
    if g:
        result += 2678400 * int(g)
    g = match.group("weeks")
    if g:
        result += 604800 * int(g)
    g = match.group("days")
    if g:
        result += 86400 * int(g)
    g = match.group("hours")
    if g:
        result += 3600 * int(g)
    g = match.group("minutes")
    if g:
        result += 60 * int(g)
    g = match.group("seconds")
    if g:
        result += int(g)
    return result

