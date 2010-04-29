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

require 'etc'
begin
  require 'dnsruby'
rescue LoadError
  require 'rubygems'
  require 'dnsruby'
end
require 'syslog'
include Syslog::Constants
include Dnsruby
require 'kasp_auditor/commands.rb'
require 'kasp_auditor/config.rb'
require 'kasp_auditor/key_tracker.rb'
require 'kasp_auditor/auditor.rb'
require 'kasp_auditor/partial_auditor.rb'
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
  # Make sure that the "sort" command works uniformly across platforms
  ENV['LC_ALL']= "C"

  # Give up - all is lost
  def KASPAuditor.exit(msg, err, log = nil)
    if (log)
      log.log(LOG_ERR, msg)
    end
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

    attr_accessor :kasp_file, :zone_name, :signed_temp, :unsigned_zone
    attr_accessor :enable_timeshift, :conf_file
    
    # This the default value for the working folders, which is only used if the XML config can't be found
    attr_accessor :working_folder

    def force_partial
      @force_partial = true
      if (@force_partial && @force_full)
        raise ArgumentError.new("Can't force both full and partial auditor at once")
      end
    end

    def force_full
      @force_full = true
      if (@force_full && @force_partial)
        raise ArgumentError.new("Can't force both full and partial auditor at once")
      end
    end

    def initialize
      @enable_timeshift = false
    end

    # Run the auditor.
    def run
      conf_file = @conf_file
      if (!conf_file)
        KASPAuditor.exit("No configuration file specified", 1)
      end
      syslog_facility, working, signer_working_folder, zonelist, kasp_file, enforcer_interval =
        load_config_xml(conf_file)
      if (@kasp_file)
        kasp_file = @kasp_file
      end

      Syslog.open("ods-auditor", Syslog::LOG_PID |
        Syslog::LOG_CONS, syslog_facility) { |syslog|
        run_with_syslog(zonelist, kasp_file, syslog, working, 
          signer_working_folder, enforcer_interval)
      }
    end

    # This method is provided so that the test code can use its own syslog
    def run_with_syslog(zonelist_file, kasp_file, syslog, 
        working, signer_working_folder, enforcer_interval) # :nodoc: all
      syslog.log(LOG_INFO, "Auditor started")
      print("Auditor started\n")
      if (@enable_timeshift)
        configure_timeshift(syslog)
      end
      zones = nil
      begin
        zones = Parse.parse(File.dirname(kasp_file)  + File::SEPARATOR,
          zonelist_file, kasp_file, syslog)
      rescue Exception => e
        KASPAuditor.exit("Couldn't load configuration files (from #{kasp_file}) - try running ods-kaspcheck", -LOG_ERR, syslog)
      end
      zones = check_zones_to_audit(zones, syslog)
      # Now check the input and output zones using the config
      if (zones.length == 0)
        KASPAuditor.exit("Couldn't find any zones to load", -LOG_ERR, syslog)
      end
      pid = Process.pid
      ret = 999 # Return value to controlling process
      zones.each {|config, output_file|
        next if !config
        syslog.log(LOG_INFO, "Auditor starting on #{config.name}")
        print("Auditor starting on #{config.name}\n")
        # Override this with @unsigned_zone if present
        input_file = signer_working_folder + File::Separator + config.name + ".unsorted"
        if ((@zone_name == config.name) && (@unsigned_zone))
          input_file = @unsigned_zone
        end
        do_audit = true
        [{input_file => "Unsigned"}, {output_file => "Signed"}].each {|hash|
          hash.each {|f, text|
            if (!(File.exist?((f.to_s+"").untaint)))
              msg = "#{text} file #{f} does not exist"
              print(msg+"\n")
              syslog.log(LOG_ERR, msg)
              ret = 1
              do_audit = false
            end
          }
        }

        if (do_audit)
          if ((config.partial_audit && !@force_full) || @force_partial)
            ret = partial_audit(ret, input_file, output_file, working, config, syslog, enforcer_interval)
          else
            ret = full_audit(ret, input_file, output_file, pid, working, config, syslog, enforcer_interval)
          end
        end
      }
      ret = 0 if (ret == 999)
      ret = 0 if (ret >= LOG_WARNING) # Only return an error if LOG_ERR or above was raised
      if (ret == 0)
        print "Auditor found no errors\n"
      else
        print "Auditor found errors - check log for details\n"
      end
      exit(ret)
    end
    
    def partial_audit(ret, input_file, output_file, working, config, syslog, enforcer_interval)
      # Invoke the partial auditor
      auditor = PartialAuditor.new(syslog, working)
      ret_val = auditor.check_zone(config, input_file, output_file, enforcer_interval)
      ret = ret_val if (ret_val < ret)
      if ((config.err > 0) && (config.err < ret))
        ret = config.err
      end
      return ret
    end

    def full_audit(ret, input_file, output_file, pid, working, config, syslog, enforcer_interval)
      # Perform a full audit of every record. This requires sorting the zones canonically.
      # Preparse the input and output files
      do_audit = true
      pids=[]
      new_pid = normalise_and_sort(input_file, "in", pid, working, config)
      pids.push(new_pid)
      new_pid = normalise_and_sort(output_file, "out", pid, working, config)
      pids.push(new_pid)
      pids.each {|id|
        ret_id, ret_status = Process.wait2(id)
        if (ret_status != 0)
          syslog.log(LOG_ERR, "Error sorting files (#{input_file} and #{output_file}) : ERR #{ret_status}- moving on to next zone")
          ret = 1
          do_audit = false
        end
      }
      begin
        if (do_audit)
          # Now audit the pre-parsed and sorted file
          auditor = Auditor.new(syslog, working, enforcer_interval)
          ret_val = auditor.check_zone(config, working+get_name(input_file)+".in.sorted.#{pid}",
            working + get_name(output_file)+".out.sorted.#{pid}",
            input_file, output_file)
          ret = ret_val if (ret_val < ret)
          if ((config.err > 0) && (config.err < ret))
            ret = config.err
          end
        end
      rescue Exception=> e
        syslog.log(LOG_ERR, "Unexpected error auditing files (#{input_file} and #{output_file}) : ERR #{e}- moving on to next zone. Trace for debugging : #{e.backtrace.join("\n")}")
        ret = 1
      ensure
        [input_file + ".in", output_file + ".out"].each {|f|
          delete_file(working + get_name(f)+".parsed.#{pid}")
          delete_file(working + get_name(f)+".sorted.#{pid}")
        }
      end
      return ret
    end

    def normalise_and_sort(f, prefix, pid, working, config)
      pp = Preparser.new(config)
      parsed_file = working+get_name(f)+".#{prefix}.parsed.#{pid}"
      sorted_file = working+get_name(f)+".#{prefix}.sorted.#{pid}"
      delete_file(parsed_file)
      delete_file(sorted_file)
      new_pid = (fork {
          pp.normalise_zone_and_add_prepended_names(f, parsed_file)
          pp.sort(parsed_file, sorted_file)
        })
      return new_pid
    end

    def get_name(f)
      # Return the filename, minus the path
      a = f.split(File::SEPARATOR)
      return File::SEPARATOR + a[a.length()-1]
    end
    
    def Runner.timeshift
      return @@timeshift
    end

    def configure_timeshift(syslog)
      # Frig Time.now to ENV['ENFORCER_TIMESHIFT']
      if (@enable_timeshift)
        timeshift = ENV['ENFORCER_TIMESHIFT']

        # If environment variable not present, then ignore
        if (timeshift)
          # Change the time
          year = timeshift[0,4]
          mon = timeshift[4,2]
          day = timeshift[6,2]
          hour = timeshift[8,2]
          min = timeshift[10,2]
          sec = timeshift[12,2]

          syslog.log(LOG_INFO, "Timeshifting to #{timeshift}\n")
          print "Timeshifting to #{timeshift}\n"

          @@timeshift = Time.mktime(year, mon, day, hour, min, sec).to_i
          require 'time_shift.rb'
        end
      end
    end

    # Given a list of configured zones, and a list of zones_to_audit, return
    # only those configured zones which are in the list of zones_to_audit.
    # Ignore a trailing dot.
    def check_zones_to_audit(zones, syslog) # :nodoc: all
      # If @zone_name is present, then only check that zone
      if @zone_name
        to_keep = nil
        zones.each {|z|
          if (z[0].name == @zone_name.to_s)
            to_keep = z
          end
        }
        if (!to_keep)
          KASPAuditor.exit("Can't find #{@zone_name} zone in zonelist", 1, syslog)
        end
        zones = [to_keep]
      end
      if (@signed_temp)
        # Then, if @signed is also present, then use that name for the
        # signed zonefile.
        conf = nil
        zones.each {|array|
          if (array[0].name == @zone_name.to_s)
            conf = array[0]
          end
        }
        zones=[[conf, @signed_temp]]
      end
      return zones
    end


    # Try to load the info from the conf.xml file.
    # Loads syslog facility, working folder and the zonelist file
    # If Privileges items are specified, then user, groups and chroot are
    # adjusted accordingly.
    # Returns a Syslog::Constants value
    # Returns Syslog::LOG_DAEMON on any error
    def load_config_xml(conf_file) # :nodoc: all
      working = ""
      signer_working = ""
      zonelist = ""
      kasp = ""
      begin
        File.open((conf_file + "").untaint , 'r') {|file|
          doc = REXML::Document.new(file)
          enforcer_interval = 3600
          begin
            e_i_text = doc.elements['Configuration/Enforcer/Interval'].text
            enforcer_interval = Config.xsd_duration_to_seconds(e_i_text)
          rescue Exception
            print "Can't read Enforcer->Interval from Configuration\n"
          end
            begin
              working = doc.elements['Configuration/Auditor/WorkingDirectory'].text
            rescue Exception
              working = @working_folder
            end
            begin
              signer_working = doc.elements['Configuration/Signer/WorkingDirectory'].text
            rescue Exception
              signer_working = @working_folder
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
            return syslog_facility, working, signer_working, zonelist, kasp, enforcer_interval
          rescue Exception => e
            print "Error reading config : #{e}\n"
            return Syslog::LOG_DAEMON, working, signer_working, zonelist,kasp, enforcer_interval
          end
        }
      rescue Errno::ENOENT
        KASPAuditor.exit("ERROR - Can't find config file : #{conf_file}", 1)
      end
    end

    def change_uid(uid_text)
      uid = Etc.getpwnam((uid_text+"").untaint).uid
      Process::Sys.setuid(uid)
    end

    #def change_chroot(dir)
    #  Dir.chroot((dir+"").untaint)
    #end

    def change_group(gid_text)
      gid = Etc.getgrnam((gid_text+"").untaint).gid
      Process::Sys.setgid(gid)
    end

    def change_privilege(user, group)
      return if !user && !group
      begin
        uid, gid = Process.euid, Process.egid
        target_uid = Etc.getpwnam((user+"").untaint).uid if user
        target_gid = Etc.getgrnam((group+"").untaint).gid if group

        if uid != target_uid or gid != target_gid
          Process.initgroups(user, target_gid) if target_gid

          Process::GID.change_privilege(target_gid) if target_gid

          Process::UID.change_privilege(target_uid) if target_uid
        end
      rescue Exception => e
        KASPAuditor.exit("Couldn't set User, Group to #{user.inspect}, #{group.inspect} : (#{e})", 1)
      end
    end

    def load_privileges(doc)
      # Configuration/Privileges may be overridden by Auditor/Privileges
      #begin
      #  if (doc.elements['Configuration/Auditor/Privileges/Directory'])
      #    change_chroot(doc.elements['Configuration/Auditor/Privileges/Directory'].text)
      #  elsif (doc.elements['Configuration/Privileges/Directory'])
      #    change_chroot(doc.elements['Configuration/Privileges/Directory'].text)
      #  end
      #rescue Exception => e
      #  print "Couldn't set Configuration/Privileges/Directory (#{e})\n"
      #end
      user, group = nil
      if (doc.elements['Configuration/Auditor/Privileges/Group'])
        group=(doc.elements['Configuration/Auditor/Privileges/Group'].text)
      elsif (doc.elements['Configuration/Privileges/Group'])
        group=(doc.elements['Configuration/Privileges/Group'].text)
      end
      if (doc.elements['Configuration/Auditor/Privileges/User'])
        user=(doc.elements['Configuration/Auditor/Privileges/User'].text)
      elsif (doc.elements['Configuration/Privileges/User'])
        user=(doc.elements['Configuration/Privileges/User'].text)
      end
      change_privilege(user, group)
    end

    def delete_file(f) # :nodoc: all
      begin
        File.delete(f.untaint)
      rescue Exception => e
        #                print "Error deleting #{f} : #{e}\n"
      end
    end

  end

end
