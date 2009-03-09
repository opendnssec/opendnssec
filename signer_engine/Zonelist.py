#
# This class is used by the engine to store the current list of zones
#
# It is implemented as an associative array where the key is the zone
# name, and the value is the datetime of the last update of the zone's
# config xml file
from Ft.Xml.XPath import Evaluate
from xml.dom import minidom
from datetime import datetime

# only for __main__ testing
from EngineConfig import EngineConfiguration

class Zonelist:
    
    def __init__(self):
        self.zone_updates = {}
    
    def get_last_update(self, zone_name):
        try:
            return self.zone_updates[zone_name]
        except KeyError:
            # raise? or just return None?
            return None
    
    def get_all_zone_names(self):
        return self.zone_updates.keys()
    
    def read_zonelist_file(self, file):
        f = open(file, "r")
        s = f.read()
        f.close()
        x = minidom.parseString(s)
        self.from_xml(x)
        x.unlink()
    
    def from_xml(self, xml_blob):
        xmlbs = Evaluate("zonelist/zone", xml_blob)
        for xmlb in xmlbs:
            zone_name = xmlb.attributes["name"].value
            xmlb = Evaluate("lastUpdate", xmlb)[0].firstChild
            if xmlb:
                last_update_str = xmlb.data
                last_update = datetime.strptime(last_update_str, "%Y-%m-%dT%H:%M:%SZ")
                self.zone_updates[zone_name] = last_update
            else:
                raise Exception("no last update element in zone")

    def merge(self, new_zonelist):
        # returns a tuple: (removed, added, updated)
        # which are lists of zone names
        # new_zonelist will be mangled after this
        # (it will only contain actual new zone names)
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

if __name__=="__main__":
    zl = Zonelist()
    zl.read_zonelist_file("/home/jelte/tmp/engine_in/zonelist.xml")
            
