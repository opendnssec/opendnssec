"""
This class is used by the engine to store the current list of zones,
as read from zonelist.xml

It is implemented as an associative array where the key is the zone
name, and the value is the datetime of the last update of the zone's
config xml file
"""

from Ft.Xml.XPath import Evaluate
from xml.dom import minidom
from datetime import datetime

class Zonelist:
    """List of current Zones"""
    
    def __init__(self):
        self.zone_updates = {}
    
    def get_last_update(self, zone_name):
        """Return the time of the last update of the zone zone_name"""
        try:
            return self.zone_updates[zone_name]
        except KeyError:
            # raise? or just return None?
            return None
    
    def get_all_zone_names(self):
        """Returns a List of all current zone names"""
        return self.zone_updates.keys()
    
    def read_zonelist_file(self, input_file):
        """Read the list of zones from input_file"""
        zonef = open(input_file, "r")
        xstr = zonef.read()
        zonef.close()
        xmlb = minidom.parseString(xstr)
        self.from_xml(xmlb)
        xmlb.unlink()
    
    def from_xml(self, xml_blob):
        """Reads the list of zones from xml_blob"""
        xmlbs = Evaluate("zonelist/zone", xml_blob)
        for xmlb in xmlbs:
            zone_name = xmlb.attributes["name"].value
            xmlb = Evaluate("lastUpdate", xmlb)[0].firstChild
            if xmlb:
                last_update_str = xmlb.data
                last_update = datetime.strptime(last_update_str,
                                                "%Y-%m-%dT%H:%M:%SZ")
                self.zone_updates[zone_name] = last_update
            else:
                raise Exception("no last update element in zone")

    def merge(self, new_zonelist):
        """'Merges' two zone lists.
        returns a tuple: (removed, added, updated)
        which are lists of zone names
        new_zonelist will be mangled after this
        (it will only contain actual new zone names)
        """
        removed = []
        added = []
        updated = []
        for key in self.get_all_zone_names():
            if key in new_zonelist.zone_updates:
                if self.zone_updates[key] < new_zonelist.zone_updates[key]:
                    updated.append(key)
                del new_zonelist.zone_updates[key]
            else:
                removed.append(key)
        added = new_zonelist.get_all_zone_names()
        return (removed, added, updated)
