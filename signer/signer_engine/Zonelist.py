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

"""
This class is used by the engine to store the current list of zones,
as read from zonelist.xml

It is implemented as an associative array where the key is the zone
name, and the value is the datetime of the last update of the zone's
config xml file
"""

from Ft.Xml.XPath import Evaluate
from xml.dom import minidom
from xml.parsers.expat import ExpatError
import Util

class ZonelistError(Exception):
    """General error when parsing the zonelist.xml file"""
    pass

class ZonelistEntry:
    """An entry in a zone list, contains:
    - Zone configuration file name
    - input adapter type (currently only file)
    - input adapter data (depends on type)
    - output adapter type (currently only file)
    - output adapter data (depends on type)
    """

    def __init__(self, zone_name, configuration_file, input_adapter,
                 input_adapter_data, output_adapter,
                 output_adapter_data):
        self.zone_name = zone_name
        self.configuration_file = configuration_file
        self.input_adapter = input_adapter
        self.input_adapter_data = input_adapter_data
        self.output_adapter = output_adapter
        self.output_adapter_data = output_adapter_data

    def is_same(self, other):
        """Returns True if there is no difference between this
           entry and 'other'"""
        return self.zone_name == other.zone_name and \
               self.configuration_file == other.configuration_file and \
               self.input_adapter == other.input_adapter and \
               self.input_adapter_data == other.input_adapter_data and \
               self.output_adapter == other.output_adapter and \
               self.output_adapter_data == other.output_adapter_data

class Zonelist:
    """List of current Zones"""
    ADAPTER_FILE = 1
    
    def __init__(self):
        self.entries = {}
    
    def get_zonelist_entry(self, zone_name):
        """Return the time of the last update of the zone zone_name"""
        try:
            return self.entries[zone_name]
        except KeyError:
            # raise? or just return None?
            return None
    
    def get_all_zone_names(self):
        """Returns a List of all current zone names"""
        return self.entries.keys()
    
    def read_zonelist_file(self, input_file):
        """Read the list of zones from input_file"""
        try:
            zonef = open(input_file, "r")
            xstr = zonef.read()
            zonef.close()
            xmlb = minidom.parseString(xstr)
            self.from_xml(xmlb)
            xmlb.unlink()
        except ExpatError, exe:
            raise ZonelistError(str(exe))
        except IOError, ioe:
            raise ZonelistError(str(ioe))
    
    def from_xml(self, xml_blob):
        """Reads the list of zones from xml_blob"""
        xmlbs = Evaluate("Zonelist/Zone", xml_blob)
        if not xmlbs:
            raise ZonelistError("No Zonelist/Zone entries "+
                                "in zone list file")
        for xmlb in xmlbs:
            zone_name = xmlb.attributes["name"].value
            configuration_file = Util.get_xml_data(
                                      "SignerConfiguration", xmlb)
            input_adapter_data = Util.get_xml_data(
                                      "Adapters/Input/File", xmlb, True)
            if input_adapter_data:
                input_adapter = self.ADAPTER_FILE
            else:
                raise ZonelistError("Unknown input adapter")
            output_adapter_data = Util.get_xml_data(
                                     "Adapters/Output/File", xmlb, True)
            if output_adapter_data:
                output_adapter = self.ADAPTER_FILE
            else:
                raise ZonelistError("Unknown output adapter")
            self.entries[zone_name] = ZonelistEntry(zone_name,
                                                    configuration_file,
                                                    input_adapter,
                                                    input_adapter_data,
                                                    output_adapter,
                                                    output_adapter_data)

    def merge(self, new_zonelist):
        """'Merges' two zone lists.
        returns a tuple: (removed, added, updated)
        which are lists of ZonelistEntry objects
        """
        removed = []
        added = []
        updated = []
        for key in self.get_all_zone_names():
            if not key in new_zonelist.entries.keys():
                removed.append(key)
                del self.entries[key]
            else:
                if not self.entries[key].\
                    is_same(new_zonelist.entries[key]):
                    self.entries[key] = new_zonelist.entries[key]
                    updated.append(key)
                del new_zonelist.entries[key]
        for key in new_zonelist.entries.keys():
            added.append(key)
            self.entries[key] = new_zonelist.entries[key]
        return (removed, added, updated)
