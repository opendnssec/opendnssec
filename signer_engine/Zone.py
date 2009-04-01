"""This class defines Zones, with all information needed to sign them"""

import os
import time
import subprocess
from datetime import datetime
#import traceback
import syslog

from ZoneConfig import ZoneConfig

import Util

# todo: move this path to general engine config too?
#tools_dir = "../signer_tools";

class Zone:
    """Zone representation, with all information needed to sign them"""
    def __init__(self, _zone_name, engine_config):
        self.zone_name = _zone_name
        self.engine_config = engine_config
        self.locked = False
        
        # information received from KASP through the xml file
        self.zone_config = None
        
        # last_update as specified in zonelist.xml, to see when
        # the config for this zone needs to be reread
        self.last_update = None
        # this isn't used atm
        self.last_read = None

        # this should be set with the result from ZoneConfig.compare()
        self.action = ZoneConfig.NO_CHANGE
    
    # we define two zone objects the same if the zone names are equal
    def __eq__(self, other):
        return self.zone_name == other.zone_name
    
    # todo: make this already the xml format that is also used to
    # read zone information?
    # (will we have/need more data than that?)
    def __str__(self):
        result = ["name: " + self.zone_name]
        result.append("last config file read: " + str(self.last_read))
        return "\n".join(result)

    def get_zone_input_filename(self):
        """Returns the file name of the source zone file"""
        return self.engine_config.zone_input_dir + os.sep \
            + self.zone_name
        
    def get_zone_output_filename(self):
        """Returns the file name of the final signed output file"""
        return self.engine_config.zone_output_dir + os.sep \
            + self.zone_name
        
    def get_zone_config_filename(self):
        """Returns the file name of the zone configuration xml file"""
        return self.engine_config.zone_config_dir \
            + os.sep + self.zone_name + ".xml"

    def get_zone_tmp_filename(self, ext=""):
        """Returns the file name of the temporary zone file"""
        return self.engine_config.zone_tmp_dir + os.sep + \
            self.zone_name + ext

    def get_tool_filename(self, tool_name):
        """Returns the complete path to the tool file tool_name"""
        return self.engine_config.tools_dir + os.sep + tool_name
        
    def read_config(self):
        """Read the zone xml configuration from the standard location"""
        self.zone_config = ZoneConfig(self.get_zone_config_filename())
        self.last_read = datetime.now()
    
    def get_input_serial(self):
        """Returns the serial number from the SOA record in the input
        zone file"""
        zone_file = self.get_zone_input_filename()
        cmd = [ self.get_tool_filename("get_serial"),
                "-f", zone_file ]
        get_serial_c = Util.run_tool(cmd)
        result = 0
        for line in get_serial_c.stdout:
            result = int(line)
        status = get_serial_c.wait()
        if (status == 0):
            return result
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "Warning: get_serial returned " + str(status))
            return 0

    def get_output_serial(self):
        """Returns the serial number from the SOA record in the signed
        output file"""
        zone_file = self.get_zone_output_filename()
        cmd = [ self.get_tool_filename("get_serial"),
                "-f", zone_file ]
        get_serial_c = Util.run_tool(cmd)
        result = 0
        for line in get_serial_c.stdout:
            result = int(line)
        status = get_serial_c.wait()
        if (status == 0):
            return result
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "Warning: get_serial returned " + str(status))
            return 0

    # this uses the locator value to find the right pkcs11 module
    # creates a DNSKEY string to add to the unsigned zone,
    # and calculates the correct tool_key_id
    # returns True if the key is found
    def find_key_details(self, key):
        """Fills in the details about the key by querying all configured
        HSM tokens for the key (by its locator value)."""
        syslog.syslog(syslog.LOG_DEBUG,
                      "Generating DNSKEY rr for " + str(key["id"]))
        # just try all modules to generate the dnskey?
        # first one to return anything is good?
        for token in self.engine_config.tokens:
            mpath = token["module_path"]
            mpin = token["pin"]
            tname = token["name"]
            syslog.syslog(syslog.LOG_DEBUG, "Try token " + tname)
            cmd = [ self.get_tool_filename("create_dnskey_pkcs11"),
                    "-n", tname,
                    "-m", mpath,
                    "-p", mpin,
                    "-o", self.zone_name,
                    "-a", str(key["algorithm"]),
                    "-f", str(key["flags"]),
                    "-t", str(key["ttl"]),
                    key["locator"]
                  ]
            create_p = Util.run_tool(cmd)
            for line in create_p.stdout:
                output = line
            status = create_p.wait()
            for line in create_p.stderr:
                syslog.syslog(syslog.LOG_ERR,
                            "create_dnskey stderr: " + line)
            syslog.syslog(syslog.LOG_DEBUG,
                          "create_dnskey status: " + str(status))
            syslog.syslog(syslog.LOG_DEBUG,
                          "equality: " + str(status == 0))
            if status == 0:
                key["token_name"] = tname
                key["pkcs11_module"] = mpath
                key["pkcs11_pin"] = mpin
                key["tool_key_id"] = key["locator"] + \
                                     "_" + str(key["algorithm"])
                key["dnskey"] = str(output)
                syslog.syslog(syslog.LOG_INFO,
                              "Found key " + key["locator"] +\
                              " in token " + tname)
                return True
        return False

    def sort(self):
        """Sort the zone according to the relevant signing details
        (either in 'normal' or 'NSEC3' space). The zone is read from
        the input file, and the result is stored in the temp dir,
        without an extension. If key data is not filled in with
        find_key_details, this is done now."""
        syslog.syslog(syslog.LOG_INFO,
                      "Sorting zone: " + self.zone_name)
        unsorted_zone_file = open(self.get_zone_input_filename(), "r")
        cmd = [ self.get_tool_filename("sorter"),
                "-o", self.zone_name
              ]
        if self.zone_config.denial_nsec3:
            cmd.extend([
                        "-n",
                        "-s", self.zone_config.denial_nsec3_salt,
                        "-t",
                        str(self.zone_config.denial_nsec3_iterations),
                        "-a",
                        str(self.zone_config.denial_nsec3_algorithm)])
        sort_process = Util.run_tool(cmd, subprocess.PIPE)
        
        # sort published keys and zone data
        try:
            for k in self.zone_config.publish_keys:
                if not k["dnskey"]:
                    try:
                        syslog.syslog(syslog.LOG_DEBUG,
                                      "No information yet for key " +\
                                      k["locator"])
                        if (self.find_key_details(k)):
                            sort_process.stdin.write(k["dnskey"]+ "\n")
                        else:
                            syslog.syslog(syslog.LOG_ERR,
                                          "Error: could not find key "+\
                                          k["locator"])
                    except Exception, exc:
                        syslog.syslog(syslog.LOG_ERR,
                                      "Error: Unable to find key " +\
                                      k["locator"])
                        syslog.syslog(syslog.LOG_ERR, str(exc))
                        sort_process.stdin.write(
                            "; Unable to find key " + k["locator"])
                else:
                    sort_process.stdin.write(k["dnskey"]+ "\n") 
            
            for line in unsorted_zone_file:
                sort_process.stdin.write(line)
            sort_process.stdin.close()
            
            unsorted_zone_file.close()
            sorted_zone_file = open(self.get_zone_tmp_filename(".sorted"), "w")
            
            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_ERR,
                              "stderr from sorter: " + line)
            
            for line in sort_process.stdout:
                sorted_zone_file.write(line)
            sorted_zone_file.close()
        except Exception, exc:
            syslog.syslog(syslog.LOG_ERR, "Error sorting zone\n")
            syslog.syslog(syslog.LOG_WARNING, str(exc))
            syslog.syslog(syslog.LOG_WARNING,
                          "Command was: " + " ".join(cmd))
            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_WARNING,
                              "sorter stderr: " + line)
            raise exc
        syslog.syslog(syslog.LOG_INFO, "Done sorting")

    def nsecify(self):
        """Takes the sorted zone file created with sort(), strips
           the glue from it, and adds nsec(3) records. The output
           is written to a new file (.nsecced), ready to
           be signed."""
        syslog.syslog(syslog.LOG_INFO,
                      "NSEC(3)ing zone: " + self.zone_name)
        # hmz, todo: stripped records need to be re-added
        # and another todo: move strip to right after sorter?
        if self.zone_config.denial_nsec:
            nsec_p = Util.run_tool(
                              [self.get_tool_filename("nseccer"),
                               "-f",
                               self.get_zone_tmp_filename(".sorted")])
        elif self.zone_config.denial_nsec3:
            cmd = [
                self.get_tool_filename("nsec3er"),
                "-o", self.zone_name,
                "-s",
                self.zone_config.denial_nsec3_salt,
                "-t",
                str(self.zone_config.denial_nsec3_iterations),
                "-a",
                str(self.zone_config.denial_nsec3_algorithm),
                "-i",
                self.get_zone_tmp_filename(".sorted"),
            ]
            if self.zone_config.denial_nsec3_ttl:
                cmd.append("-m")
                cmd.append(str(self.zone_config.denial_nsec3_ttl))
            if self.zone_config.denial_nsec3_optout:
                cmd.append("-p")
            nsec_p = Util.run_tool(cmd)
        nsecced_zone_file = open(self.get_zone_tmp_filename(".nsecced"), "w")
        
        for line in nsec_p.stderr:
            syslog.syslog(syslog.LOG_ERR,
                          "stderr from nseccer: " + line)
        
        for line in nsec_p.stdout:
            nsecced_zone_file.write(line)
        nsecced_zone_file.close()
        

    def perform_action(self):
        """Depending on the value set to zone.action, this method
           will sort, nsecify and/or sign the zone"""
        if self.action == ZoneConfig.RESORT:
            self.sort()
            self.nsecify()
            self.sign()
            self.finalize()
        if self.action == ZoneConfig.RENSEC:
            self.nsecify()
            self.sign()
            self.finalize()
        if self.action == ZoneConfig.RESIGN:
            self.sign()
            self.finalize()
        # if nothing in the config changes, the next action will always
        # be to just resign
        self.action = ZoneConfig.RESIGN

    def find_serial(self):
        """Finds the serial number as specified in the xml file.
           By default, the serial from the input file will simply be
           copied. Options are 'unixtime', 'counter', and 'datecounter'
        """
        soa_serial = None
        if self.zone_config.soa_serial == "unixtime":
            soa_serial = int(time.time())
        elif self.zone_config.soa_serial == "counter":
            # try output serial first, if not found, use input
            prev_serial = self.get_output_serial()
            if not prev_serial:
                prev_serial = self.get_input_serial()
            if not prev_serial:
                prev_serial = 0
            soa_serial = prev_serial + 1
        elif self.zone_config.soa_serial == "datecounter":
            # if current output serial >= <date>00,
            # just increment by one
            soa_serial = int(time.strftime("%Y%m%d")) * 100
            output_serial = self.get_output_serial()
            if output_serial >= soa_serial:
                soa_serial = output_serial + 1
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "warning: unknown serial type " +\
                          self.zone_config.soa_serial)
        return soa_serial
        
    def sign(self):
        """Takes the file created by nsecify(), and signs the zone"""
        cmd = [self.get_tool_filename("signer_pkcs11"),
              ]

        sign_p = Util.run_tool(cmd)
        sign_p.stdin.write("\n")
        sign_p.stdin.write(":origin " + self.zone_name + "\n")
        syslog.syslog(syslog.LOG_DEBUG,
                      "send to signer: " +\
                      ":origin " + self.zone_name)
        
        # optional SOA modification values
        Util.write_p(sign_p, self.zone_config.soa_ttl, ":soa_ttl ")
        Util.write_p(sign_p, self.zone_config.soa_minimum,
                     ":soa_minimum ")
        if self.zone_config.soa_serial:
            soa_serial = self.find_serial()
            if soa_serial:
                syslog.syslog(syslog.LOG_DEBUG,
                              "set serial to " + str(soa_serial))
                sign_p.stdin.write(":soa_serial " +\
                                   str(soa_serial) + "\n")
        # TODO move time to engine?
        sign_time = int(time.time())
        Util.write_p(sign_p,
                     Util.datestamp(self.get_expiration_timestamp(sign_time)),
                     ":expiration ")
        Util.write_p(sign_p,
                     Util.datestamp(self.get_inception_timestamp(sign_time)),
                     ":inception ")
        Util.write_p(sign_p,
                     Util.datestamp(self.get_refresh_timestamp(sign_time)),
                     ":refresh ")
                     

        for k in self.zone_config.signature_keys:
            syslog.syslog(syslog.LOG_DEBUG,
                          "use signature key: " + k["locator"])
            if not k["dnskey"]:
                try:
                    syslog.syslog(syslog.LOG_DEBUG,
                                  "No information yet for key " +\
                                  k["locator"])
                    self.find_key_details(k)
                except Exception:
                    syslog.syslog(syslog.LOG_ERR,
                                  "Error: Unable to find key " +\
                                  k["locator"])
            if k["token_name"]:
                scmd = [":add_module",
                        k["token_name"],
                        k["pkcs11_module"],
                        k["pkcs11_pin"]
                       ]
                syslog.syslog(syslog.LOG_DEBUG,
                              "send to signer " + " ".join(scmd))
                sign_p.stdin.write(" ".join(scmd) + "\n")
                scmd = [":add_key",
                        k["token_name"],
                        k["tool_key_id"],
                        str(k["algorithm"]),
                        str(k["flags"])
                       ]
                syslog.syslog(syslog.LOG_DEBUG,
                              "send to signer " + " ".join(scmd))
                sign_p.stdin.write(" ".join(scmd) + "\n")
            else:
                syslog.syslog(syslog.LOG_WARNING,
                              "warning: no token for key " +\
                              k["locator"])
        nsecced_f = open(self.get_zone_tmp_filename(".nsecced"))
        for line in nsecced_f:
            #syslog.syslog(syslog.LOG_DEBUG, "send to signer " + l)
            sign_p.stdin.write(line)
        nsecced_f.close()
        sign_p.stdin.close()
        sign_p.wait()
        output = open(self.get_zone_tmp_filename(".signed"), "w")
        for line in sign_p.stdout:
            output.write(line)
        for line in sign_p.stderr:
            syslog.syslog(syslog.LOG_WARNING, "signer stderr: line")
        output.close()

    def finalize(self):
        cmd = [self.get_tool_filename("finalizer"),
               "-f", self.get_zone_tmp_filename(".signed")
              ]
        finalize_p = Util.run_tool(cmd)
        output = open(self.get_zone_output_filename(), "w")
        for line in finalize_p.stdout:
            output.write(line)
        for line in finalize_p.stderr:
            output.write(line)
        output.close()
    
    def lock(self, caller=None):
        """Lock the zone with a simple spinlock"""
        msg = "waiting for lock on zone " +\
              self.zone_name + " to be released"
        if caller:
            msg = str(caller) + ": " + msg
        while (self.locked):
            syslog.syslog(syslog.LOG_DEBUG, msg)
            time.sleep(1)
        self.locked = True
        msg = "Zone " + self.zone_name + " locked"
        if caller:
            msg = msg + " by " + str(caller)
        syslog.syslog(syslog.LOG_DEBUG, msg)
    
    def release(self):
        """Release the lock on this zone"""
        syslog.syslog(syslog.LOG_DEBUG,
                      "Releasing lock on zone " + self.zone_name)
        self.locked = False

    def calc_resign_from_output_file(self):
        """Checks the output file, and calculates the number of seconds
        until it should be signed again. This can be negative!
        If the file is not found, 0 is returned (and signing should be
        scheduled immediately"""
        output_file = self.get_zone_output_filename()
        try:
            statinfo = os.stat(output_file)
            return int(statinfo.st_mtime +\
                       self.zone_config.signatures_resign_time -\
                       time.time())
        except OSError:
            return 0

    def get_expiration_timestamp(self, time_offset):
        """Returns the absolute expiration date compared to the
           time_offset given."""
        return time_offset +\
               self.zone_config.signatures_validity_default

    def get_inception_timestamp(self, time_offset):
        """Returns the absolute inception date compared to the
           time_offset given."""
        return time_offset - self.zone_config.signatures_clockskew

    def get_refresh_timestamp(self, time_offset):
        """Returns the absolute time at which signatures should be
        replaced, compared to the time_offset given. The return
        value of this function is used by the signer tool to
        determine 'old' signatures. If the inception date of the
        signature is before this time, the signature will be
        replaced."""
        return self.get_inception_timestamp(time_offset) +\
               self.zone_config.signatures_refresh_time

# quick test-as-we-go function
# use this for unit testing?
# otherwise remove it.
if __name__ == "__main__":
    # this will of course be retrieved from the general zone config dir
    #CONFFILE = "/home/jelte/repos/opendnssec/signer_engine/engine.conf"
    #TZONE = Zone("zone1.example", EngineConfiguration(CONFFILE))
    #TZONE.read_config()
    #s = TZONE.calc_resign_from_output_file()
    #z.sign()
    print "nothing atm"
