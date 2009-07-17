#
# $Id$
#
# Copyright (c) 2009 Nominet UK. All rights reserved.
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

require 'rubygems'
require 'syslog'
include Syslog::Constants
require 'kasp_auditor/config.rb'
require 'kasp_auditor/auditor.rb'
require 'kasp_auditor/parse.rb'
require 'kasp_auditor/preparser.rb'

# This module provides auditing capabilities to OpenDNSSEC.
# Once an unsigned zone has been signed, this module is used to check that
# the signing process has run successfully. It checks that no data has been
# lost (or non-DNSSEC data added), and that all the DNSSEC records are correct.
# It used the OpenDNSSEC standard logging (defined in /etc/opendnssec/conf.xml)
# @TODO@ This module should be able to take an optional list of zones to check.
# If this parameter is not present, then all the zones in zonelist.xml will be
# checked.
module KASPAuditor
  # First version of auditor ran by loading whole zone into memory. This won't work for large zones.
  # Second version of auditor needs to run by processing zone files one domain name at a time (one subdomain of the zone at a time, that is)
  # To do that, we need a zone file which has been sorted into subdomain order. We can do that by using OS sort command on a list of reversed domain names.
  class Runner

    # Run the auditor.
    # The filename is optional for testing purposes.
    # The
    def run(path, zones_to_audit = [], filename="zonelist.xml")
      #      path = ARGV[0] + "/"
      if (!path || path.length() == 0)
        path = "/etc/opendnssec/"
      end
      if (path[path.length() -1,1] != "/")
        path = path+ "/"
      end
      syslog_facility = get_syslog_facility(path)
      Syslog.open("kasp_auditor", Syslog::LOG_PID | Syslog::LOG_CONS, syslog_facility) { |syslog| run_with_syslog(path, zones_to_audit, filename, syslog)
      }
    end

    # This method is provided so that the test code can use its own syslog
    def run_with_syslog(path, zones_to_audit, filename, syslog)
      if (path[path.length() -1,1] != "/")
        path = path+ "/"
      end
      zones = Parse.parse(path, filename, syslog)
      check_zones_to_audit(zones, zones_to_audit)
      # Now check the input and output zones using the config
      print "Checking #{zones.length} zones\n"
      if (zones.length == 0)
        syslog.log(LOG_ERR, "Couldn't find any zones to load")
        print "Couldn't find any zones to load"
        exit(-LOG_ERR)
      end
      ret = 999 # Return value to controlling process
      zones.each {|config, input_file, output_file|

        # PREPARSE THE INPUT AND OUTPUT FILES!!!
        pp = Preparser.new
        pids=[]
        [input_file, output_file].each {|f|
          delete_file(f+".parsed")
          delete_file(f+".sorted")
          pids.push(fork {
              pp.normalise_zone_and_add_prepended_names(f, f+".parsed")
              pp.sort(f)
            })
        }
        pids.each {|pid|
          ret_id, ret_status = Process.wait2(pid)
          if (ret_status != 0)
            print "Error sorting file : #{ret_status}\n"
          end
        }

        # Now audit the pre-parsed and sorted file
        auditor = Auditor.new(syslog)
        ret_val = auditor.check_zone(config, input_file, output_file)
        ret = ret_val if (ret_val < ret)

      }
      ret = 0 if (ret == -99)
      ret = 0 if (ret >= LOG_WARNING) # Only return an error if LOG_ERR or above was raised
      exit(ret)
    end

    # Given a list of configured zones, and a list of zones_to_audit, return
    # only those configured zones which are in the list of zones_to_audit.
    # Ignore a trailing dot.
    def check_zones_to_audit(zones, zones_to_audit)
      # If a list of zones to audit has been specified, then only check those
      if (zones_to_audit.length > 0)
        zones.each {|zone|
          if (!(zones_to_audit.include?zone[0].zone.name))
            if (zone[0].zone.name[zone[0].zone.name.length() -1, 1] != ".")
              zones.delete(zone) if !(zones_to_audit.include?(zone[0].zone.name+"."))
            else
              zones.delete(zone)
            end
          end
        }
      end
    end


    # Try to load the syslog facility from the conf.xml file.
    # Returns a Syslog::Constants value
    # Returns Syslog::LOG_DAEMON on any error
    def get_syslog_facility(path)
      File.open(path + "conf.xml" , 'r') {|file|
        begin
          doc = REXML::Document.new(file)
          facility = doc.elements['Configuration/Logging/Syslog/Facility'].text
          # Now turn the facility string into a Syslog::Constants format....
          syslog_facility = eval "Syslog::LOG_" + facility.upcase
          print "Logging facility : #{facility}, #{syslog_facility}\n"
          return syslog_facility
        rescue Exception
          return Syslog::LOG_DAEMON
        end
      }
    end

    # This method allows the auditor to run on files which have already been preparsed.
    # This is primarily for debugging purposes
    def run_no_preparse(path, zones_to_audit = [], filename="zonelist.xml") # :nodoc: all
      if (path[path.length() -1, 1] != "/")
        path = path+ "/"
      end
      syslog_facility = get_syslog_facility(path)
      Syslog.open("kasp_auditor", Syslog::LOG_PID | Syslog::LOG_CONS, syslog_facility) {|syslog|
        zones = Parse.parse(path, filename, syslog)
        check_zones_to_audit(zones, zones_to_audit)
        # Now check the input and output zones using the config
        print "Checking #{zones.length} zones\n"
        if (zones.length == 0)
          syslog.log(LOG_ERR, "Couldn't find any zones to load")
          print "Couldn't find any zones to load"
          exit(-LOG_ERR)
        end
        auditor = Auditor.new(syslog)
        ret = 999 # Return value to controlling process
        zones.each {|config, input_file, output_file|
          ret_val = auditor.check_zone(config, input_file, output_file)
          ret = ret_val if (ret_val < ret)

        }
        ret = 0 if (ret == 999)
        ret = 0 if (ret >= LOG_WARNING) # Only return an error if LOG_ERR or above was raised
        exit(ret)
      }
    end

    def delete_file(f)
      begin
        File.delete(f)
      rescue Exception => e
        #        print "Error deleting #{f} : #{e}\n"
      end
    end

  end
  class KASPTime # :nodoc: all
    # This allows the test code to frig the system time to use old test data.
    def KASPTime.get_current_time
      return Time.now.to_i
    end
  end
end
