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
# Several transient files are created during this process - they are removed
# when the process is complete.
module KASPAuditor
  def KASPAuditor.exit(msg, err)
    # @TODO@ Log exit msg
    print msg + "\n"
    Kernel.exit(err)
  end
  $SAFE = 1
  # The KASPAuditor takes the signed and unsigned zones and compares them.
  # It first parses both files, and creates transient files which are then
  # sorted into canonical order. These files are then processed by the
  # Auditor. If processing an NSEC3-signed file, the Auditor will create
  # additional temporary files, which are processed after the main auditing
  # run.
  class Runner
    DEFAULT_PATH="/etc/opendnssec/"
    DEFAULT_CONF_FILE = "conf.xml"

    attr_accessor :kasp_file, :zone_name, :signed_temp, :conf_file

    # Run the auditor.
    def run
      path = DEFAULT_PATH
      conf_file = @conf_file
      if (!conf_file)
        conf_file = DEFAULT_CONF_FILE
      end
      syslog_facility, working, zonelist, kasp_file = load_config_xml(path, conf_file)
      if (@kasp_file)
        kasp_file = @kasp_file
      end

      Syslog.open("kasp_auditor", Syslog::LOG_PID | Syslog::LOG_CONS, syslog_facility) { |syslog| run_with_syslog(path, zonelist, kasp_file, syslog, working)
      }
    end

    # This method is provided so that the test code can use its own syslog
    def run_with_syslog(path, zonelist_file, kasp_file, syslog, working) # :nodoc: all
      if (path[path.length() -1,1] != "/")
        path = path+ "/"
      end
      zones = Parse.parse(path, zonelist_file, kasp_file, syslog)
      #      check_zones_to_audit(zones, zones_to_audit)
      # Now check the input and output zones using the config
      print "Checking #{zones.length} zones\n"
      if (zones.length == 0)
        syslog.log(LOG_ERR, "Couldn't find any zones to load")
        KASPAuditor.exit("Couldn't find any zones to load", -LOG_ERR)
      end
      pid = Process.pid
      ret = 999 # Return value to controlling process
      zones.each {|config, input_file, output_file|

        # PREPARSE THE INPUT AND OUTPUT FILES!!!
        pp = Preparser.new()
        pids=[]
        [input_file, output_file].each {|f|
          delete_file(working+get_name(f)+".parsed.#{pid}")
          delete_file(working+get_name(f)+".sorted.#{pid}")
          pids.push(fork {
              pp.normalise_zone_and_add_prepended_names(f, working+get_name(f)+".parsed.#{pid}")
              pp.sort(working+get_name(f)+".parsed.#{pid}",
                working+get_name(f)+".sorted.#{pid}")
            })
        }
        do_audit = true
        pids.each {|id|
          ret_id, ret_status = Process.wait2(id)
          if (ret_status != 0)
            print "Error sorting files (#{input_file} and #{output_file}) : ERR #{ret_status}- moving on to next zone\n"
            syslog.log(LOG_ERR, "Error sorting files (#{input_file} and #{output_file}) : ERR #{ret_status}- moving on to next zone")
            ret = 1
            do_audit = false
          end
        }
        if (do_audit)
          # Now audit the pre-parsed and sorted file
          auditor = Auditor.new(syslog, working)
          ret_val = auditor.check_zone(config, working+get_name(input_file)+".sorted.#{pid}",
            working + get_name(output_file)+".sorted.#{pid}",
            input_file, output_file)
          ret = ret_val if (ret_val < ret)
          [input_file, output_file].each {|f|
            delete_file(working+get_name(f)+".parsed.#{pid}")
            delete_file(working+get_name(f)+".sorted.#{pid}")
          }
        end
      }
      ret = 0 if (ret == -99)
      ret = 0 if (ret >= LOG_WARNING) # Only return an error if LOG_ERR or above was raised
      exit(ret)
    end

    def get_name(f)
      # Return the filename, minus the path
      a = f.split(File::SEPARATOR)
      return "/" + a[a.length()-1]
    end

    # Given a list of configured zones, and a list of zones_to_audit, return
    # only those configured zones which are in the list of zones_to_audit.
    # Ignore a trailing dot.
    def check_zones_to_audit(zones, zones_to_audit) # :nodoc: all
      # If a list of zones to audit has been specified, then only check those
      if (zones_to_audit.length > 0)
        zones.each {|zone|
          if (!(zones_to_audit.include?zone[0].name))
            if (zone[0].name[zone[0].name.length() -1, 1] != ".")
              zones.delete(zone) if !(zones_to_audit.include?(zone[0].name+"."))
            else
              zones.delete(zone)
            end
          end
        }
      end
    end


    # Try to load the info from the conf.xml file.
    # Loads syslog facility, working folder and the zonelist file
    # If Privileges items are specified, then user, groups and chroot are
    # adjusted accordingly.
    # Returns a Syslog::Constants value
    # Returns Syslog::LOG_DAEMON on any error
    def load_config_xml(path, conf_file) # :nodoc: all
      working = path
      zonelist = ""
      kasp = ""
      if (!conf_file || (conf_file == ""))
        conf_file = working + DEFAULT_CONF_FILE
      end
      print "Reading config from #{conf_file}\n"
      begin
        File.open((conf_file + "").untaint , 'r') {|file|
          doc = REXML::Document.new(file)
          begin
            working = doc.elements['Configuration/Auditor/WorkingDirectory'].text
          rescue Exception
            KASPAuditor.exit("Can't read working directory from conf.xml - exiting", 1)
          end
          begin
            zonelist = doc.elements['Configuration/Common/ZoneListFile'].text
          rescue Exception
            KASPAuditor.exit("Can't read zonelist location from conf.xml - exiting", 1)
          end
          begin
            kasp = doc.elements['Configuration/Common/PolicyFile'].text
          rescue Exception
            KASPAuditor.exit("Can't read KASP policy location from conf.xml - exiting", 1)
          end
          load_privileges(doc)
          begin
            facility = doc.elements['Configuration/Common/Logging/Syslog/Facility'].text
            # Now turn the facility string into a Syslog::Constants format....
            syslog_facility = eval "Syslog::LOG_" + (facility.upcase+"").untaint
            print "Logging facility : #{facility}, #{syslog_facility}\n"
            return syslog_facility, working, zonelist, kasp
          rescue Exception => e
            print "Error reading config : #{e}\n"
            return Syslog::LOG_DAEMON, working, zonelist,kasp
          end
        }
      rescue Errno::ENOENT
        KASPAuditor.exit("ERROR - Can't find config file : #{conf_file}", 1)
      end
    end

    def change_uid(uid_text)
      uid = Etc.getpwnam((uid_text+"").untaint).uid
      print "Setting uid to #{uid_text}, #{uid}\n"
      Process::Sys.setuid(uid)
    end

    def change_chroot(dir)
      print "Setting Directory chroot to #{dir}\n"
      Dir.chroot((dir+"").untaint)
    end

    def change_group(gid_text)
      gid = Etc.getgrnam((gid_text+"").untaint).gid
      print "Setting group id to #{gid_text}, #{gid}\n"
      Process::Sys.setgid(gid)
    end

    def load_privileges(doc)
      # Configuration/Privileges may be overridden by Auditor/Privileges
      begin
        if (doc.elements['Configuration/Auditor/Privileges/Directory'])
          change_chroot(doc.elements['Configuration/Auditor/Privileges/Directory'].text)
        elsif (doc.elements['Configuration/Privileges/Directory'])
          change_chroot(doc.elements['Configuration/Privileges/Directory'].text)
        end
      rescue Exception => e
        print "Couldn't set Configuration/Privileges/Directory (#{e})\n"
      end
      begin
        if (doc.elements['Configuration/Auditor/Privileges/User'])
          change_uid(doc.elements['Configuration/Auditor/Privileges/User'].text)
        elsif (doc.elements['Configuration/Privileges/User'])
          change_uid(doc.elements['Configuration/Privileges/User'].text)
        end
      rescue Exception => e
        print "Couldn't set Configuration/Privileges/User (#{e})\n"
      end
      begin
        if (doc.elements['Configuration/Auditor/Privileges/Group'])
          change_group(doc.elements['Configuration/Auditor/Privileges/Group'].text)
        elsif (doc.elements['Configuration/Privileges/Group'])
          change_group(doc.elements['Configuration/Privileges/Group'].text)
        end
      rescue Exception => e
        print "Couldn't set Configuration/Privileges/Group (#{e})\n"
      end
    end

    def delete_file(f) # :nodoc: all
      begin
        File.delete(f.untaint)
      rescue Exception => e
        #                print "Error deleting #{f} : #{e}\n"
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
