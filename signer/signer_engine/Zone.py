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

"""This class defines Zones, with all information needed to sign them"""

import os
import time
import subprocess
import commands
from datetime import datetime
#import traceback
import syslog
import shutil

from ZoneConfig import ZoneConfig, ZoneConfigError
from Util import ToolException
import Util

# todo: move this path to general engine config too?
#tools_dir = "../signer_tools";

class Zone:
    """Zone representation, with all information needed to sign them"""
    def __init__(self, _zone_name, zonelist_entry, engine_config):
        self.zone_name = _zone_name
        self.engine_config = engine_config
        self.locked = False
        self.scheduled = None
        self.in_progress = False
        self.schedule_now = False

        # information received from KASP through the xml file
        self.zone_config = None
        
        # last_update as specified in zonelist.xml, to see when
        # the config for this zone needs to be reread
        self.last_update = None
        # this isn't used atm
        self.last_read = None
        # keep track of when we last performed sign()
        self.last_signed = None

        self.zonelist_entry = zonelist_entry

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
        return self.zonelist_entry.input_adapter_data
        
    def get_zone_output_filename(self):
        """Returns the file name of the final signed output file"""
        return self.zonelist_entry.output_adapter_data
        
    def get_zone_axfr_filename(self):
        """Returns the file name of the stored AXFR file"""
        zone_input_filename = self.get_zone_input_filename()
        return zone_input_filename + ".axfr"

    def get_zone_config_filename(self):
        """Returns the file name of the zone configuration xml file"""
        return self.zonelist_entry.configuration_file

    def get_zone_tmp_filename(self, ext=""):
        """Returns the file name of the temporary zone file"""
        return self.engine_config.zone_tmp_dir + os.sep + \
            self.zone_name + ext

    def get_tool_filename(self, tool_name):
        """Returns the complete path to the tool file tool_name"""
        return self.engine_config.tools_dir + os.sep + tool_name
        
    def read_config(self):
        """Read the zone xml configuration from the standard location"""
        try:
            self.zone_config = ZoneConfig(self.get_zone_config_filename())
            self.last_read = datetime.now()
        except Exception, e:
            # treat every exception as a configuration error
            raise ZoneConfigError(str(e))

    def get_input_serial(self):
        """Returns the serial number from the SOA record in the input
        zone file"""
        result = 0
        zone_file = self.get_zone_input_filename()
        cmd = [ self.get_tool_filename("get_serial"),
                "-f", zone_file ]
        get_serial_c = Util.run_tool(cmd)
        if not get_serial_c:
            return result
        for line in get_serial_c.stdout:
            result = int(line)
        status = get_serial_c.wait()
        if (status == 0):
            return result
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "Warning: get_serial returned " + str(status))
            return 0

    def get_finalized_serial(self):
        """Returns the serial number from the SOA record in the signed
        finalized file"""
        result = 0
        zone_file = self.get_zone_tmp_filename(".finalized")
        if not os.path.exists(zone_file):
            return 0
        cmd = [ self.get_tool_filename("get_serial"),
                "-f", zone_file ]
        get_serial_c = Util.run_tool(cmd)
        if not get_serial_c:
            return result
        for line in get_serial_c.stdout:
            result = int(line)
        status = get_serial_c.wait()
        if (status == 0):
            return result
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "Warning: get_serial returned " + str(status))
            return 0

    def write_output_serial(self):
        """Writes the serial file using the finalized zonefile"""
        result = self.get_finalized_serial()
        serial_file = self.get_zone_tmp_filename(".serial")
        try:
            f = open(serial_file, 'w')
            f.write(str(result))
            f.close()
            syslog.syslog(syslog.LOG_INFO,
                      "Stored output serial: " + str(result))
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading serial file")
            syslog.syslog(syslog.LOG_ERR, str(ioe))

    def get_output_serial(self):
        """Returns the serial number from the .serial file"""
        result = 0
        serial_file = self.get_zone_tmp_filename(".serial")
        if not os.path.exists(serial_file):
            return 0

        try:
            f = open(serial_file, 'r')
            result = int(f.readline())
            f.close()
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading serial file")
            syslog.syslog(syslog.LOG_ERR, str(ioe))
        return result

    def get_class(self):
        """Returns the class of the SOA record in the input
        zone file"""
        result = 0
        cmd = [ self.get_tool_filename("get_class"),
                "-f", self.get_zone_tmp_filename(".sorted") ]
        get_class_c = Util.run_tool(cmd)
        if not get_class_c:
            return result
        for line in get_class_c.stdout:
            result = int(line)
        status = get_class_c.wait()
        if (status == 0):
            return str(result)
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "Warning: get_class returned " + str(status))
            return str(1)


    # this uses the locator value to find the right pkcs11 module
    # creates a DNSKEY string to add to the unsigned zone,
    # and calculates the correct tool_key_id
    # returns True if the key is found
    def find_key_details(self, key):
        """Fills in the details about the key by querying all configured
        HSM tokens for the key (by its locator value)."""
        syslog.syslog(syslog.LOG_INFO,
                      "Generating DNSKEY RR for " + str(key["locator"]))
        # just try all modules to generate the dnskey?
        # first one to return anything is good?
        cmd = [ self.get_tool_filename("create_dnskey"),
                "-c", self.engine_config.config_file_name,
                "-k", self.get_class(),
                "-o", self.zone_name,
                "-a", str(key["algorithm"]),
                "-f", str(key["flags"]),
                "-t", str(key["ttl"]),
                key["locator"]
              ]
        #create_p = Util.run_tool(cmd)
        create_p = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, close_fds=True)
        if not create_p:
            syslog.syslog(syslog.LOG_ERR, "Error running create_dnskey")
            return False
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
        if status == 0 and output:
            key["tool_key_id"] = key["locator"]
            key["dnskey"] = str(output)
            syslog.syslog(syslog.LOG_INFO,
                          "Found key " + key["locator"])
            return True
        return False

    def check_key_values(self, k):
        """Checks whether some derivable key attributes have been
        stored yet (i.e. the DNSKEY string)"""
        if not k["dnskey"]:
            try:
                syslog.syslog(syslog.LOG_INFO,
                              "No information yet for key " +\
                              k["locator"])
                if not self.find_key_details(k):
                    syslog.syslog(syslog.LOG_ERR,
                                  "Error: could not find key "+\
                                  k["locator"])
            except ToolException, exc:
                syslog.syslog(syslog.LOG_ERR,
                              "Error: Unable to find key " +\
                              k["locator"])
                syslog.syslog(syslog.LOG_ERR, str(exc))

    def fetch_axfr(self):
        """Retrieve the zone through AXFR. If use_axfr is false, do
        nothing. Otherwise, move the transferred file to the input
        adapter file."""
        if self.use_axfr:
            syslog.syslog(syslog.LOG_INFO, "Fetch zone: " + self.get_zone_axfr_filename())
            if os.path.exists(self.get_zone_axfr_filename()):
                Util.move_file(self.get_zone_axfr_filename(),
                       self.get_zone_input_filename())
        return True

    def sort_input(self):
        """Sort the zone canonically. The zone is read from
        the input file, and the result is stored in the temp dir,
        .sorted".Returns True if the operation succeeded, False
         if it failed."""
        syslog.syslog(syslog.LOG_INFO,
                      "Sorting zone: " + self.zone_name)
        succeeded = False

        shutil.copy(self.get_zone_input_filename(),
            self.get_zone_tmp_filename(".unsorted"))

        cmd = [ self.get_tool_filename("sorter"),
                "-o", self.zone_name,
                "-f", self.get_zone_input_filename(),
                "-w", self.get_zone_tmp_filename(".sorted")
              ]
        if self.zone_config.soa_minimum >= 0:
            cmd.append("-m")
            cmd.append(str(self.zone_config.soa_minimum))
        sort_process = Util.run_tool(cmd, subprocess.PIPE)
        
        try:
            if not sort_process:
                raise OSError("Sorter not found")

            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_ERR,
                              "stderr from sorter: " + line)

            if sort_process.wait() == 0:
                succeeded = True
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading input zone")
            syslog.syslog(syslog.LOG_ERR, str(ioe))
        except OSError, exc:
            syslog.syslog(syslog.LOG_ERR, "Error sorting zone")
            syslog.syslog(syslog.LOG_ERR, str(exc))
            syslog.syslog(syslog.LOG_ERR,
                          "Command was: " + " ".join(cmd))
            if sort_process:
                for line in sort_process.stderr:
                    syslog.syslog(syslog.LOG_ERR,
                                  "sorter stderr: " + line)
            #raise exc
        if succeeded:
            syslog.syslog(syslog.LOG_DEBUG, "Done sorting")
        else:
            syslog.syslog(syslog.LOG_ERR, "Sorting failed")
        return succeeded


    def preprocess(self):
        """Sort the zone according to the relevant signing details
        (either in 'normal' or 'NSEC3' space). The zone is read from
        the .sorted file, and the result is stored in the tmp dir,
        with the .processed extension. If key data is not filled in with
        find_key_details, this is done now. Returns True if the
        operation succeeded, False if it failed."""
        syslog.syslog(syslog.LOG_INFO,
                      "Preprocessing zone: " + self.zone_name)
        succeeded = False

        for k in self.zone_config.publish_keys:
            self.check_key_values(k)

        cmd = [ self.get_tool_filename("zone_reader"),
                "-k", self.get_class(),
                "-o", self.zone_name,
                "-w", self.get_zone_tmp_filename(".processed")
              ]
        if self.zone_config.denial_nsec3:
            cmd.extend([
                        "-n",
                        "-t",
                        str(self.zone_config.denial_nsec3_iterations),
                        "-a",
                        str(self.zone_config.denial_nsec3_algorithm)])
            if self.zone_config.denial_nsec3_salt and self.zone_config.denial_nsec3_salt != "-":
                cmd.extend(["-s", self.zone_config.denial_nsec3_salt])

            # tell the reader not to append the NSEC3PARAM record
            # if we are not going to add signatures
            if len(self.zone_config.signature_keys) <= 0:
                cmd.append("-p")
        sort_process = Util.run_tool(cmd, subprocess.PIPE)
        
        # sort published keys and zone data
        try:
            if not sort_process:
                raise OSError("Preprocesser not found")
            for k in self.zone_config.publish_keys:
                if k["dnskey"]:
                    sort_process.stdin.write(k["dnskey"])

            unprocessed_zone_file = open(self.get_zone_tmp_filename(".sorted"), "r")
            if not unprocessed_zone_file:
                syslog.syslog(syslog.LOG_ERR,
                              "Error opening sorted zone file: " +
                              self.get_zone_tmp_filename(".sorted"))
            else:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Writing file to zone_reader: " +
                              self.get_zone_tmp_filename(".sorted"))
            for line in unprocessed_zone_file:
                sort_process.stdin.write(line)
            sort_process.stdin.close()
            unprocessed_zone_file.close()
            #sorted_zone_file = open(self.get_zone_tmp_filename(".sorted"), "w")

            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_ERR,
                              "stderr from zone_reader: " + line)

            if sort_process.wait() == 0:
                succeeded = True
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading sorted zone")
            syslog.syslog(syslog.LOG_ERR, str(ioe))
        except OSError, exc:
            syslog.syslog(syslog.LOG_ERR, "Error preprocessing zone")
            syslog.syslog(syslog.LOG_ERR, str(exc))
            syslog.syslog(syslog.LOG_ERR,
                          "Command was: " + " ".join(cmd))
            if sort_process:
                for line in sort_process.stderr:
                    syslog.syslog(syslog.LOG_ERR,
                                  "zone_reader stderr: " + line)
            #raise exc
        if succeeded:
            syslog.syslog(syslog.LOG_DEBUG, "Done preprocessing")
        else:
            syslog.syslog(syslog.LOG_ERR, "Preprocessing failed")
        return succeeded

    def sort_signed(self):
        """Sorts the output we created earlier according to the new
           nsec(3) configuration"""
        syslog.syslog(syslog.LOG_INFO,
                      "Resorting signed zone: " + self.zone_name)
        succeeded = False

        # if we have no signed zone yet, simply return ok
        if not os.path.exists(self.get_zone_tmp_filename(".signed")):
            syslog.syslog(syslog.LOG_WARNING, "No signed zone yet")
            return True
        
        cmd = [ self.get_tool_filename("sorter"),
                "-o", self.zone_name,
                "-w", self.get_zone_tmp_filename(".signed.sorted")
              ]
        if self.zone_config.soa_minimum >= 0:
            cmd.append("-m")
            cmd.append(str(self.zone_config.soa_minimum))
        sort_process = Util.run_tool(cmd, subprocess.PIPE)
        
        # sort published keys and zone data
        try:
            if not sort_process:
                raise OSError("Sorter not found")

            unsorted_zone_file = open(
                             self.get_zone_tmp_filename(".signed"), "r")
            if not unsorted_zone_file:
                syslog.syslog(syslog.LOG_ERR,
                              "Error opening zone input file: " +
                              self.get_zone_tmp_filename(".signed"))
            else:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Writing file to sorter: " +
                              self.get_zone_tmp_filename(".signed"))
            for line in unsorted_zone_file:
                sort_process.stdin.write(line)
            sort_process.stdin.close()
            unsorted_zone_file.close()
            #sorted_zone_file = open(self.get_zone_tmp_filename(".sorted"), "w")

            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_ERR,
                              "stderr from sorter: " + line)

            if sort_process.wait() == 0:
                succeeded = True
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading input zone")
            syslog.syslog(syslog.LOG_ERR, str(ioe))
        except OSError, exc:
            syslog.syslog(syslog.LOG_ERR, "Error sorting zone")
            syslog.syslog(syslog.LOG_ERR, str(exc))
            syslog.syslog(syslog.LOG_ERR,
                          "Command was: " + " ".join(cmd))
            if sort_process:
                for line in sort_process.stderr:
                    syslog.syslog(syslog.LOG_ERR,
                                  "sorter stderr: " + line)
            #raise exc
        if succeeded:
            syslog.syslog(syslog.LOG_DEBUG, "Done sorting")
        else:
            syslog.syslog(syslog.LOG_ERR, "Sorting failed")
        return succeeded

    def preprocess_signed(self):
        """Preprocess the output we created earlier according to the new
           nsec(3) configuration"""
        syslog.syslog(syslog.LOG_INFO,
                      "Preprocessing signed zone: " + self.zone_name)
        succeeded = False

        # if we have no signed, preprocessed zone yet, simply return ok
        if not os.path.exists(self.get_zone_tmp_filename(".signed.processed")):
            syslog.syslog(syslog.LOG_WARNING, "No signed zone yet")
            return True
        
        cmd = [ self.get_tool_filename("zone_reader"),
                "-k", self.get_class(),
                "-o", self.zone_name,
                "-w", self.get_zone_tmp_filename(".signed.processed")
              ]
        if self.zone_config.denial_nsec3:
            cmd.extend([
                        "-n",
                        "-t",
                        str(self.zone_config.denial_nsec3_iterations),
                        "-a",
                        str(self.zone_config.denial_nsec3_algorithm)])
            if self.zone_config.denial_nsec3_salt and self.zone_config.denial_nsec3_salt != "-":
                cmd.extend(["-s", self.zone_config.denial_nsec3_salt])
            # tell the reader not to append the NSEC3PARAM record
            # if we are not going to add signatures
            if len(self.zone_config.signature_keys) <= 0:
                cmd.append("-p")
        sort_process = Util.run_tool(cmd, subprocess.PIPE)
        
        # sort published keys and zone data
        try:
            if not sort_process:
                raise OSError("Preprocessor not found")

            unprocessed_zone_file = open(
                             self.get_zone_tmp_filename(".signed.sorted"), "r")
            if not unprocessed_zone_file:
                syslog.syslog(syslog.LOG_ERR,
                              "Error opening sorted zone file: " +
                              self.get_zone_tmp_filename(".signed.sorted"))
            else:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Writing file to zone_reader: " +
                              self.get_zone_tmp_filename(".signed.sorted"))
            for line in unprocessed_zone_file:
                sort_process.stdin.write(line)
            sort_process.stdin.close()
            unprocessed_zone_file.close()
            #sorted_zone_file = open(self.get_zone_tmp_filename(".sorted"), "w")

            for line in sort_process.stderr:
                syslog.syslog(syslog.LOG_ERR,
                              "stderr from preprocessor: " + line)

            if sort_process.wait() == 0:
                succeeded = True
        except IOError, ioe:
            syslog.syslog(syslog.LOG_ERR, "Error reading sorted zone")
            syslog.syslog(syslog.LOG_ERR, str(ioe))
        except OSError, exc:
            syslog.syslog(syslog.LOG_ERR, "Error processing zone")
            syslog.syslog(syslog.LOG_ERR, str(exc))
            syslog.syslog(syslog.LOG_ERR,
                          "Command was: " + " ".join(cmd))
            if sort_process:
                for line in sort_process.stderr:
                    syslog.syslog(syslog.LOG_ERR,
                                  "zone_reader stderr: " + line)
            #raise exc
        if succeeded:
            shutil.copy(self.get_zone_tmp_filename(".signed.processed"),
                        "/tmp/myzone")
            Util.move_file(self.get_zone_tmp_filename(".signed.processed"),
                           self.get_zone_tmp_filename(".signed"))
            syslog.syslog(syslog.LOG_DEBUG, "Done preprocessing")
        else:
            syslog.syslog(syslog.LOG_ERR, "Preprocessing failed")
        return succeeded

    def nsecify(self):
        """Takes the sorted zone file created with sort(), strips
           the glue from it, and adds nsec(3) records. The output
           is written to a new file (.signed), ready to
           actually be signed. If the zone configuration has no
           signature_keys set, no nsec3 records will be added,
           but the file is just passed along the line."""
        syslog.syslog(syslog.LOG_INFO,
                      "NSEC(3)ing zone: " + self.zone_name)
        if len(self.zone_config.signature_keys) > 0:
            if self.zone_config.denial_nsec:
                cmd = [
                    self.get_tool_filename("nseccer"),
                    "-f",
                    self.get_zone_tmp_filename(".processed"),
                    "-w",
                    self.get_zone_tmp_filename(".nsecced")
                ]
                if self.zone_config.soa_minimum >= 0:
                    cmd.append("-m")
                    cmd.append(str(self.zone_config.soa_minimum))
                nsec_p = Util.run_tool(cmd)
            elif self.zone_config.denial_nsec3:
                cmd = [
                    self.get_tool_filename("nsec3er"),
                    "-o", self.zone_name,
                    "-t",
                    str(self.zone_config.denial_nsec3_iterations),
                    "-a",
                    str(self.zone_config.denial_nsec3_algorithm),
                    "-i",
                    self.get_zone_tmp_filename(".processed"),
                    "-w",
                    self.get_zone_tmp_filename(".nsecced")
                ]
                if self.zone_config.soa_minimum >= 0:
                    cmd.append("-m")
                    cmd.append(str(self.zone_config.soa_minimum))
                if self.zone_config.denial_nsec3_salt and self.zone_config.denial_nsec3_salt != "-":
                    cmd.extend(["-s", self.zone_config.denial_nsec3_salt])
                if self.zone_config.denial_nsec3_optout:
                    cmd.append("-p")
                nsec_p = Util.run_tool(cmd)
            if nsec_p:
                for line in nsec_p.stderr:
                    syslog.syslog(syslog.LOG_ERR,
                                "stderr from nseccer: " + line)
        else: # no signatures
            syslog.syslog(syslog.LOG_WARNING,
                "No signatures set, not adding NSEC(3) records")
            try:
                shutil.copy(self.get_zone_tmp_filename(".processed"),
                            self.get_zone_tmp_filename(".nsecced"))
            except Exception, e:
                syslog.syslog(syslog.LOG_ERR, "Error in copy: " + str(e))

        syslog.syslog(syslog.LOG_DEBUG, "Done nseccing")
        return True

    def perform_action(self):
        """Depending on the value set to zone.action, this method
           will sort, nsecify, sign and/or audit the zone"""
        syslog.syslog(syslog.LOG_INFO,
                      "Zone action to perform: " + str(self.action))

        if self.action >= ZoneConfig.RESIGN and os.path.exists(
                          self.get_zone_tmp_filename(".signed")):
            if self.sign(False) and self.finalize() and self.audit():
                self.move_output()
        elif self.action >= ZoneConfig.RENSEC and os.path.exists(
                            self.get_zone_tmp_filename(".processed")) and \
                            self.nsecify():
            if self.sign(False) and self.finalize() and self.audit():
                self.move_output()
        elif self.action >= ZoneConfig.REREAD and self.fetch_axfr() and os.path.isfile(
                                        self.get_zone_input_filename()):
            ser_out = self.get_output_serial()
            ser_in = self.get_input_serial()
            if self.zone_config.soa_serial == "keep" and \
                              self.compare_serial(ser_out, ser_in) <= 0:
                syslog.syslog(syslog.LOG_ERR, "Cannot keep input serial " + str(ser_in) +\
                                              ", output serial " + str(ser_out) +\
                                              " is too large. Aborting operation")
            elif self.sort_input() and self.preprocess() and self.nsecify():
                if self.sign(True) and self.finalize() and self.audit():
                    self.move_output()
        elif self.action >= ZoneConfig.RESORT and self.fetch_axfr() and os.path.isfile(
                                        self.get_zone_input_filename()):
            ## the sorting config has changed. We must also re-sort the
            ## internal zone storage containing our previous signatures,
            ## if any.
            ser_out = self.get_output_serial()
            ser_in = self.get_input_serial()
            if self.zone_config.soa_serial == "keep" and \
                              self.compare_serial(ser_out, ser_in) <= 0:
                syslog.syslog(syslog.LOG_ERR, "Cannot keep input serial " + str(ser_in) +\
                                              ", output serial " + str(ser_out) +\
                                              " is too large. Aborting operation")

            elif self.sort_signed() and self.preprocess_signed() and self.sort_input() and \
               self.preprocess() and self.nsecify():
                if self.sign(True) and self.finalize() and self.audit():
                    self.move_output()
        else:
            syslog.syslog(syslog.LOG_ERR, "Input file missing: " +\
                          self.get_zone_input_filename())
        # if nothing in the config changes, the next action will always
        # be to just resign
        if not self.schedule_now:
            self.action = ZoneConfig.RESIGN

    def compare_serial(self, s1, s2):
        """Compare two serials according to RFC 1982. Return 0 if equal, 
           -1 if s1 is bigger, 1 if s1 is smaller."""
        if s1 == s2:
            return 0
        if s1 < s2 and (s2 - s1) < (2**31):
            return 1
        if s1 > s2 and (s1 - s2) > (2**31):
            return 1
        if s1 < s2 and (s2 - s1) > (2**31):
            return -1
        if s1 > s2 and (s1 - s2) < (2**31):
            return -1
        return 0

    def find_serial(self):
        """Finds the serial number as specified in the xml file.
           By default, the serial from the input file will simply be
           copied. Options are 'unixtime', 'counter', and 'datecounter'
           and 'keep'."""
        soa_serial = None
        if self.zone_config.soa_serial == "unixtime":
            soa_serial = int(time.time())
            prev_serial = self.get_output_serial()
            if self.compare_serial(prev_serial, soa_serial) <= 0:
                soa_serial = prev_serial + 1
            update_serial = soa_serial - prev_serial
        elif self.zone_config.soa_serial == "counter":
            soa_serial = self.get_input_serial()
            # it must be larger than the output serial!
            # otherwise updates won't be accepted
            prev_serial = self.get_output_serial()
            if self.compare_serial(prev_serial, soa_serial) <= 0:
                soa_serial = prev_serial + 1
            update_serial = soa_serial - prev_serial
        elif self.zone_config.soa_serial == "datecounter":
            # if current output serial >= <date>00,
            # just increment by one
            soa_serial = int(time.strftime("%Y%m%d")) * 100
            prev_serial = self.get_output_serial()
            if self.compare_serial(prev_serial, soa_serial) <= 0:
                soa_serial = prev_serial + 1
            update_serial = soa_serial - prev_serial
        elif self.zone_config.soa_serial == "keep":
            soa_serial = self.get_input_serial()
            # it must be larger than the output serial!
            # otherwise updates won't be accepted
            prev_serial = self.get_output_serial()
            if self.compare_serial(prev_serial, soa_serial) <= 0:
                syslog.syslog(syslog.LOG_ERR,
                  "Error: serial setting is set to 'keep', but input "
                  "serial has not increased. Aborting sign operation "
                  "for " + self.zone_name)
                return None
            prev_serial = soa_serial
            update_serial = 0
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          "warning: unknown serial type " +\
                          self.zone_config.soa_serial)
        # RFC 1982
        if update_serial > (2**31)-1:
            update_serial = (2**31)-1
        soa_serial = int( (prev_serial + update_serial) % (2**32))
        return soa_serial
        
    def sign(self, force):
        """Takes the file created by nsecify() or by the previous call
           to sign(), and (re)signs the zone. Returns True if signatures
           have been added or remade. On error, or if nothing has
           changed, False is returned."""
        cmd = [self.get_tool_filename("signer"),
               "-c", self.engine_config.config_file_name,
               "-p", self.get_zone_tmp_filename(".signed"),
               "-w", self.get_zone_tmp_filename(".signed2"),
               "-r"
              ]

        if self.engine_config.syslog_facility_string:
            cmd.append("-l")
            cmd.append(self.engine_config.syslog_facility_string)

        soa_serial = self.find_serial()
        if self.zone_config.soa_serial and soa_serial == None:
            return False

        sign_p = Util.run_tool(cmd)
        if not sign_p:
            if not self.last_signed:
                self.last_signed = int(time.time())
            return False
        Util.write_p(sign_p, "\n", "")
        Util.write_p(sign_p, self.zone_name, ":origin ")
        
        # optional SOA modification values
        Util.write_p(sign_p, self.zone_config.soa_ttl, ":soa_ttl ")
        Util.write_p(sign_p, self.zone_config.soa_minimum,
                     ":soa_minimum ")
        if self.zone_config.soa_serial:
            syslog.syslog(syslog.LOG_DEBUG,
                          "set serial to " + str(soa_serial))
            Util.write_p(sign_p, str(soa_serial), ":soa_serial ")
            if self.zone_config.soa_serial == "keep":
                Util.write_p(sign_p, "1", ":soa_serial_keep ")
        # nsec3 params
        if self.zone_config.denial_nsec3:
            syslog.syslog(syslog.LOG_DEBUG, "set nsec3 values")
            Util.write_p(sign_p, str(self.zone_config.denial_nsec3_algorithm),
                ":nsec3_algorithm ")
            Util.write_p(sign_p, str(self.zone_config.denial_nsec3_iterations),
                ":nsec3_iterations ")
            if self.zone_config.denial_nsec3_salt and self.zone_config.denial_nsec3_salt != "-":
                Util.write_p(sign_p, self.zone_config.denial_nsec3_salt,
                    ":nsec3_salt ") 

        #move time to engine?
        sign_time = int(time.time())
        syslog.syslog(syslog.LOG_DEBUG, "sign time: " + Util.datestamp(sign_time))
        Util.write_p(sign_p,
                     Util.datestamp(self.get_expiration_timestamp(sign_time)),
                     ":expiration ")
        if self.zone_config.signatures_validity_denial:
            Util.write_p(
                sign_p,
                Util.datestamp(
                     self.get_expiration_timestamp_denial(sign_time)),
                ":expiration_denial ")
        if self.zone_config.signatures_jitter and \
           self.zone_config.signatures_jitter != 0:
            Util.write_p(sign_p,
                         str(self.zone_config.signatures_jitter),
                         ":jitter ")
        Util.write_p(sign_p,
                     Util.datestamp(self.get_inception_timestamp(sign_time)),
                     ":inception ")
        Util.write_p(sign_p,
                     Util.datestamp(self.get_refresh_timestamp(sign_time)),
                     ":refresh ")
        if self.zone_config.signatures_validity_denial:
            Util.write_p(
                 sign_p,
                 Util.datestamp(
                      self.get_refresh_timestamp_denial(sign_time)),
                 ":refresh_denial ")

        for k in self.zone_config.signature_keys:
            syslog.syslog(syslog.LOG_DEBUG,
                          "use signature key: " + k["locator"])
            if not k["dnskey"]:
                syslog.syslog(syslog.LOG_WARNING,
                          "no dnskey yet")
                try:
                    syslog.syslog(syslog.LOG_WARNING,
                                  "No information yet for key " +\
                                  k["locator"])
                    if not self.find_key_details(k):
                        sign_p.stdin.close()
                        sign_p.wait()
                        return False
                except ToolException:
                    syslog.syslog(syslog.LOG_ERR,
                                  "Error: Unable to find key " +\
                                  k["locator"])
            scmd = [k["tool_key_id"],
                    str(k["algorithm"]),
                    str(k["flags"])
                   ]
            if (k["zsk"]):
                Util.write_p(sign_p, " ".join(scmd), ":add_zsk ")
            if (k["ksk"]):
                Util.write_p(sign_p, " ".join(scmd), ":add_ksk ")
        nsecced_f = open(self.get_zone_tmp_filename(".nsecced"))
        if not nsecced_f:
            syslog.syslog(syslog.LOG_ERR,
                          "Error opening nsecced zone file: " +
                          self.get_zone_tmp_filename(".nsecced"))
            return False
        for line in nsecced_f:
            #syslog.syslog(syslog.LOG_DEBUG, "send to signer " + line)
            sign_p.stdin.write(line)
        nsecced_f.close()
        sign_p.stdin.close()
        sign_p.wait()
        sig_count = 0
        for line in sign_p.stderr:
            if line[:30] == "Number of signatures created: ":
                try:
                    sig_count = int(line[30:])
                except ValueError:
                    syslog.syslog(syslog.LOG_ERR,
                                  "signer returned bad value for " +
                                  "signature count: " + line[30:])
            else:
                syslog.syslog(syslog.LOG_ERR,
                              "signer stderr: " + line)
        self.last_signed = sign_time
        # Addition: unless we didn't set any keys (in which case we
        # *should* write the output file)
        if force or sig_count > 0 or len(self.zone_config.signature_keys) <= 0:
            syslog.syslog(syslog.LOG_INFO, "Created " +
                          str(sig_count) + " new signatures")
            Util.move_file(self.get_zone_tmp_filename(".signed2"),
                           self.get_zone_tmp_filename(".signed"))
        else:
            syslog.syslog(syslog.LOG_INFO,
                          "No new signatures, keeping zone")
            os.remove(self.get_zone_tmp_filename(".signed2"))
            return False
        return True

    def audit(self):
        """Calls the auditor on the signed output file, if specified
        by the configuration to do so. If the auditor returns 0, True
        is returned (and we can continue with finalize()). If not, log
        error and return False"""
        if self.zone_config.audit:
            syslog.syslog(syslog.LOG_INFO, "Running auditor on zone")
            cmd = [self.engine_config.bindir + os.sep + "ods-auditor",\
                   "-c", self.engine_config.config_file_name,\
                   "-s", self.get_zone_tmp_filename(".finalized"),\
                   "-z", self.zone_name]
            # add extra options here
            audit_p = Util.run_tool(cmd)
            result = audit_p.wait()
            syslog.syslog(syslog.LOG_INFO,
                          "Auditor result: " + str(result))
            return result == 0
        else:
            return True

    def finalize(self):
        """Runs the finalizer tool on the signed zone file, and produces
        the final output zone, for use with the master nameserver.
        Will also run the notifier script from the engine configuration,
        if set. (<UpdateNotifier>)"""
        rr_count = 0
        cmd = [self.get_tool_filename("finalizer"),
               "-f", self.get_zone_tmp_filename(".signed")
              ]
        finalize_p = Util.run_tool(cmd)
        if not finalize_p:
            return False
        output = open(self.get_zone_tmp_filename(".finalized"), "w")
        if not output:
            syslog.syslog(syslog.LOG_ERR,
                          "Error opening finalized zone file: " +
                          self.get_zone_tmp_filename(".finalized"))
            return False
        output.write("; Signed on " +\
                     datetime.fromtimestamp(self.last_signed)\
                     .strftime("%Y-%m-%d %H:%M:%S") + "\n")
        for line in finalize_p.stdout:
            rr_count = rr_count + 1
            output.write(line)
        for line in finalize_p.stderr:
            output.write(line)
        if rr_count == 0:
            syslog.syslog(syslog.LOG_ERR, "No resource records in output")
            return False
        output.close()
        return True

    def move_output(self):
        """Moves the output of the finalizer to the final output
           destination, and calls a notify command if configured"""
        syslog.syslog(syslog.LOG_INFO, "Output zone to " +
                      self.get_zone_output_filename())
        self.write_output_serial()
        Util.move_file(self.get_zone_tmp_filename(".finalized"),
                       self.get_zone_output_filename())
        if self.engine_config.notify_command:
            notify_cmd = self.engine_config.notify_command.replace("%zonefile",
                                                        self.get_zone_output_filename())

            notify_cmd = notify_cmd.replace("%zone", self.zone_name)
            syslog.syslog(syslog.LOG_INFO,
                          "Running update notify command:" + notify_cmd)
            (status, output) = commands.getstatusoutput(notify_cmd)
            if status != 0:
                syslog.syslog(syslog.LOG_ERR,
                              "Error running notification command")
                syslog.syslog(syslog.LOG_ERR,
                              output)
            else:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Update notify command has run")
                if output:
                    syslog.syslog(syslog.LOG_INFO,
                                  "output: " + output)
    def clear_database(self):
        """Remove the internal files, containing the sorted, nsecced,
        and signed zone. The final output is not deleted. On next run
        of perform_action, all actions will be performed, and the
        zone will be completely signed again."""
        if os.path.exists(self.get_zone_tmp_filename(".processed")):
            os.remove(self.get_zone_tmp_filename(".processed"))
        if os.path.exists(self.get_zone_tmp_filename(".sorted")):
            os.remove(self.get_zone_tmp_filename(".sorted"))
        if os.path.exists(self.get_zone_tmp_filename(".unsorted")):
            os.remove(self.get_zone_tmp_filename(".unsorted"))
        if os.path.exists(self.get_zone_tmp_filename(".nsecced")):
            os.remove(self.get_zone_tmp_filename(".nsecced"))
        if os.path.exists(self.get_zone_tmp_filename(".signed")):
            os.remove(self.get_zone_tmp_filename(".signed"))
        if os.path.exists(self.get_zone_tmp_filename(".signed.sorted")):
            os.remove(self.get_zone_tmp_filename(".signed.sorted"))
        if os.path.exists(self.get_zone_tmp_filename(".signed2")):
            os.remove(self.get_zone_tmp_filename(".signed2"))
        if os.path.exists(self.get_zone_tmp_filename(".finalized")):
            os.remove(self.get_zone_tmp_filename(".finalized"))
        
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

    def calc_resign(self):
        """Checks the last_signed value, and calculates the number of
        seconds left until it should be resigned, based on the resign
        value. If last_signed is not set, 0 is returned (and signing
        should be sheduled immediately)"""
        if self.last_signed:
            return int(self.last_signed +\
                       self.zone_config.signatures_resign_time -\
                       time.time())
        else:
            return 0

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
            syslog.syslog(syslog.LOG_WARNING, "No output file found, seconds to resign: 0")
            return 0

    def get_expiration_timestamp(self, time_offset):
        """Returns the absolute expiration date compared to the
           time_offset given (for all non-denial rrsets)."""
        return time_offset +\
               self.zone_config.signatures_validity_default

    def get_expiration_timestamp_denial(self, time_offset):
        """Returns the absolute expiration date compared to the
           time_offset given (for denial rrsets)."""
        return time_offset +\
               self.zone_config.signatures_validity_denial

    def get_inception_timestamp(self, time_offset):
        """Returns the absolute inception date compared to the
           time_offset given."""
        return time_offset - self.zone_config.signatures_inception_offset

    def get_refresh_timestamp(self, time_offset):
        """Returns the absolute time at which signatures for normal
           RRSets should be replaced, compared to the time_offset
           given. The return value of this function is used by the
           signer tool to determine 'old' signatures. If the
           inception date of the signature is before this time,
           the signature will be replaced."""
        return self.get_expiration_timestamp(time_offset) -\
               self.zone_config.signatures_refresh_time

    def get_refresh_timestamp_denial(self, time_offset):
        """Returns the absolute time at which signatures for denial
           RRSets should be replaced, compared to the time_offset
           given. The return value of this function is used by the
           signer tool to determine 'old' signatures. If the
           inception date of the signature is before this time,
           the signature will be replaced."""
        return self.get_expiration_timestamp_denial(time_offset) -\
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
