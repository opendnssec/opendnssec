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

require 'syslog'
include Syslog::Constants
require 'xsd/datatypes'
require 'rexml/document'
include REXML
require 'kasp_auditor/config.rb'

require 'etc'


module KASPChecker
  # This class checks the conf.xml and kasp.xml files to make sure that they
  # syntactically valid, and also semantically valid. Any oddities in the
  # configuration are reported to the user.
  class Checker
    $SAFE = 1
    KASP_FILE = "kasp"
    CONF_FILE = "conf"
    attr_accessor :conf_file, :kasp_file, :rng_path, :xmllint
    def check
      @ret_val = 999
      conf_file = @conf_file
      if (!conf_file)
        KASPAuditor.exit("No configuration file specified", 1)
      end
      # Validate the conf.xml against the RNG
      validate_file(conf_file, CONF_FILE)
      # Now check the config file
      kasp_file = check_config_file(conf_file)

      if (@kasp_file)
        # Override the configured kasp.xml with the user-supplied value
        kasp_file = @kasp_file
      end

      if (kasp_file)
        # Validate the kasp.xml against the RNG
        validate_file(kasp_file, KASP_FILE)
        # Now check the kasp file
        check_kasp_file(kasp_file)
      else
        log(LOG_ERR, "KASP configuration file cannot be found")
      end

      @ret_val = 0 if (@ret_val >= LOG_WARNING) # Only return an error if LOG_ERR or above was raised
      if (@ret_val == 999)
        exit(0)
      else
        exit(@ret_val)
      end

    end

    def log(level, msg)
      if (level.to_i < @ret_val)
        @ret_val = level.to_i
      end
      if (@syslog)
        Syslog.open("ods-kaspcheck", Syslog::LOG_PID |
          Syslog::LOG_CONS, @syslog) { |slog|
          slog.log(level, msg)
        }
      end
      # Convert the level into text, rather than a number? e.g. "WARNING"
      level_string = case level
      when LOG_ERR then "ERROR"
      when LOG_WARNING then "WARNING"
      when LOG_INFO then "INFO"
      when LOG_CRIT then "CRITICAL"
      end
      print "#{level_string}: #{msg}\n"
    end
    
    def validate_file(file, type)
      # Actually call xmllint to do the validation
      if (file)
        rng_location = nil
        if (type == CONF_FILE)
          rng_location = @rng_path + "/conf.rng"
        else
          rng_location = @rng_path + "/kasp.rng"
        end
        rng_location = (rng_location.to_s + "").untaint
        file = (file.to_s + "").untaint

        r, w = IO.pipe
        pid = fork {
          r.close
          $stdout.reopen w

          ret = system("#{(@xmllint.to_s + "").untaint} --noout --relaxng #{rng_location} #{file}")
          w.close
          exit!(ret)
        }
        w.close
        ret_strings = []
        r.each {|l| ret_strings.push(l)}
        Process.waitpid(pid)
        ret_val = $?.exitstatus

        # Now rewrite captured output from xmllint to log method
        ret_strings.each {|line|
          line.chomp!
          if line.index(" validates")
            #            log(LOG_INFO, line + " OK")
          else
            log(LOG_ERR, line)
          end
        }

        if (!ret_val)
          log(LOG_ERR, "Errors found validating " +
              ((file== nil)? "unknown file" : file) +
              " against " + ((type == CONF_FILE) ? "conf" : "kasp") + ".rng")
        end
      else
        log(LOG_ERR, "Not validating : no file passed to validate against " +
            (((type == CONF_FILE) ? "conf" : "kasp") + ".rng"))
      end
    end

    # Load the specified config file and sanity check it.
    # The file should have been validated against the RNG before this method is
    # called. 
    # Sets the syslog facility if it is defined.
    # Returns the configured location of the kasp.xml configuration file.
    def check_config_file(conf_file)
      kasp_file = nil
      begin
        File.open((conf_file + "").untaint , 'r') {|file|
          begin
            doc = REXML::Document.new(file)
          rescue Exception => e
            log(LOG_CRIT, "Can't understand #{conf_file} - exiting")
            exit(1)
          end
          begin
            facility = doc.elements['Configuration/Common/Logging/Syslog/Facility'].text
            # Now turn the facility string into a Syslog::Constants format....
            syslog_facility = eval "Syslog::LOG_" + (facility.upcase+"").untaint
            @syslog = syslog_facility
          rescue Exception => e
            print "Error reading syslog config : #{e}\n"
            #            @syslog = Syslog::LOG_DAEMON
          end
          begin
            kasp_file = doc.elements['Configuration/Common/PolicyFile'].text
          rescue Exception
            log(LOG_ERR, "Can't read KASP policy location from conf.xml - exiting")
          end

          #  Checks we need to run on conf.xml :
          #   1. If a user and/or group is defined in the conf.xml then check that it exists.
          #   Do this for *all* privs instances (in Signer, Auditor and Enforcer as well as top-level)
          warned_users = []
          doc.root.each_element('//Privileges/User') {|user|
            # Now check the user exists
            # Keep a list of the users/groups we have already warned for, and make sure we only warn for them once
            next if (warned_users.include?(user.text))
            begin
              Etc.getpwnam((user.text+"").untaint).uid
            rescue ArgumentError
              warned_users.push(user.text)
              log(LOG_ERR, "User #{user.text} does not exist")
            end
          }
          warned_groups = []
          doc.root.each_element('//Privileges/Group') {|group|
            # Now check the group exists
            # Keep a list of the users/groups we have already warned for, and make sure we only warn for them once
            next if (warned_groups.include?(group.text))
            begin
              Etc.getgrnam((group.text+"").untaint).gid
            rescue ArgumentError
              warned_groups.push(group.text)
              log(LOG_ERR, "Group #{group.text} does not exist")
            end
          }

          check_db(doc)


          # The Directory code is commented out until we support chroot again
          #          doc.root.each_element('//Privileges/Directory') {|dir|
          #            print "Dir : #{dir}\n"
          #            # Now check the directory
          #            if (!File.exist?(dir))
          #              log(LOG_ERR, "Direcotry #{dir} cannot be found")
          #            end
          #          }
          #
          #   2. If there are multiple repositories of the same type
          #   (i.e. Module is the same for them), then each must have a unique TokenLabel
          # So, for each Repository, get the Name, Module and TokenLabel.
          # Then make sure that there are no repositories which share both Module
          #  and TokenLabel
          @repositories = {}
          doc.elements.each('Configuration/RepositoryList/Repository') {|repository|
            name = repository.attributes['name']
            # Check if two repositories exist with the same name
            if (@repositories.keys.include?name)
              log(LOG_ERR, "Two repositories exist with the same name (#{name})")
            end
            mod = repository.elements['Module'].text
            #   5. Check that the shared library (Module) exists.
            if (!File.exist?((mod+"").untaint))
              log(LOG_ERR, "Module #{mod} in Repository #{name} cannot be found")
            end

            tokenlabel = repository.elements['TokenLabel'].text
            #            print "Checking Module #{mod} and TokenLabel #{tokenlabel} in Repository #{name}\n"
            # Now check if repositories already includes the [mod, tokenlabel] hash
            if (@repositories.values.include?([mod, tokenlabel]))
              log(LOG_ERR, "Multiple Repositories in #{conf_file} have the same Module (#{mod}) and TokenLabel (#{tokenlabel}), for Repository #{name}")
            end
            @repositories[name] =  [mod, tokenlabel]
            #   3. If a repository specifies a capacity, the capacity must be greater than zero.
            # This check is performed when the XML is validated against the RNG (which specifies positiveInteger for Capacity)
            #
            #  Also
          }
          # check durations for Interval and RolloverNotification (the only duration elements in conf.xml)
          ["Enforcer/Interval", "Enforcer/RolloverNotification"].each {|element|
            doc.root.each_element("//"+element) {|el| check_duration_element_proc(el, "conf.xml", element, conf_file)}
          }


        }
        return ((kasp_file+"").untaint)
      rescue Errno::ENOENT
        log(LOG_ERR, "Can't find config file : #{conf_file}")
        return nil
      end
    end

    def check_db(doc)
      # Now check that the DB is writable by the user
      # //Enforcer/Datastore/Sqlite
      doc.root.each_element('/Configuration/Enforcer/Datastore/SQLite') {|sqlite|
        file = ((sqlite.text+"").untaint)
        if !File.exist?(file)
          log(LOG_ERR, "Can't find DB file : #{file}")
          return
        end
        stat = File::Stat.new(file)
        # Get the User and Group from the file - default to current
        user_name=nil
        group_name=nil
        begin
          user_name = doc.elements['Configuration/Enforcer/Privileges/User'].text
        rescue Exception
        end
        begin
          group_name = doc.elements['Configuration/Enforcer/Privileges/Group'].text
        rescue Exception
        end
        if (user_name || group_name)
          # Other user of group specified - will need to fire up another process,
          # passing in the UID and GID to change to, and then inspect return
          pid = fork {
            # Do all the changes and then check writable
            begin
              if (group_name)
                group = Etc.getgrnam((group_name+"").untaint).gid
                Process::Sys.setgid(group)
              end
              if (user_name)
                user = Etc.getpwnam((user_name+"").untaint).uid
                Process::Sys.setuid(user)
              end
            rescue Exception => e
              log(LOG_ERR, "Can't change to #{user_name}, #{group_name} to check DB write permissions")
            end
            if (stat.writable?)
              exit(0)
            else
              exit(-1)
            end
          }
          Process.wait(pid)
          ret_status = $? >> 8
          if (ret_status != 0)
            log(LOG_ERR, "#{user_name} user can not write to DB file #{file}\n")
          end
        else
          # No user/group specified - now check that the file is writable by current user
          if !(stat.writable?)
            log(LOG_ERR, "Current user can not write to DB file #{file}\n")
          end

        end
      }
      doc.root.each_element('//Enforcer/Datastore/MySQL') {|mysql|
        # @TODO@ If //Enforcer/Datastore/MySQL is used, then we could try to connect to the database?
        # Complete once MySQL support is complete

      }
    end

    def check_duration_element_proc(element, policy, name, filename)
      duration = element.text
      #           print "Checking duration of #{name} : #{duration}, #{duration.length}\n"
      last_digit = duration[duration.length-1, 1].downcase
      if (last_digit == "m" && !(/T/=~duration))
        log(LOG_WARNING, "In #{(policy == "conf.xml") ? 'Configuration' : 'policy ' + policy + ', '} M used in duration field for #{name} (#{duration})" +
            " in #{filename} - this will be interpreted as 31 days")
      end
      if (last_digit == "y")
        log(LOG_WARNING, "In #{(policy == "conf.xml") ? 'Configuration' : 'policy ' + policy + ', '} Y used in duration field for #{name} (#{duration})" +
            " in #{filename} - this will be interpreted as 365 days")
      end
    end


    def check_kasp_file(kasp_file)
      begin
        File.open((kasp_file.to_s+"").untaint, 'r') {|file|
          begin
            doc = REXML::Document.new(file)
          rescue Exception => e
            log(LOG_CRIT, "Can't understand #{file} - exiting")
            exit(1)
          end

          # Run the following checks on kasp.xml :
          policy_names = []
          doc.elements.each('KASP/Policy') {|policy|
            name = policy.attributes['name']
            # Check if two policies exist with the same name
            if (policy_names.include?name)
              log(LOG_ERR, "Two policies exist with the same name (#{name})")
            end
            policy_names.push(name)

            #   2. For all policies, check that the "Re-sign" interval is less than the "Refresh" interval.
            resign_secs = get_duration(policy,'Signatures/Resign', kasp_file)
            refresh_secs = get_duration(policy, 'Signatures/Refresh', kasp_file)
            if (refresh_secs <= resign_secs)
              log(LOG_ERR, "The Refresh interval (#{refresh_secs} seconds) for " +
                  "#{name} Policy in #{kasp_file} is less than or equal to the Resign interval" +
                  " (#{resign_secs} seconds)")
            end

            #   3. Ensure that the "Default" and "Denial" validity periods are greater than the "Refresh" interval.
            default_secs = get_duration(policy, 'Signatures/Validity/Default', kasp_file)
            denial_secs = get_duration(policy, 'Signatures/Validity/Denial', kasp_file)
            if (default_secs <= refresh_secs)
              log(LOG_ERR, "Validity/Default (#{default_secs} seconds) for #{name} " +
                  "policy in #{kasp_file} is less than the Refresh interval " +
                  "(#{refresh_secs} seconds)")
            end
            if (denial_secs <= refresh_secs)
              log(LOG_ERR, "Validity/Denial (#{denial_secs} seconds) for #{name} " +
                  "policy in #{kasp_file} is less than or equal to the Refresh interval " +
                  "(#{refresh_secs} seconds)")
            end

            #   5. Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period. (This is a bit arbitrary. The point is to get the user to realise that there will be a large spread in the signature lifetimes.)
            jitter_secs = get_duration(policy, 'Signatures/Jitter', kasp_file)
            max_default_denial=[default_secs, denial_secs].max
            max_default_denial_type = max_default_denial == default_secs ? "Default" : "Denial"
            if (jitter_secs > (max_default_denial * 0.5))
              log(LOG_WARNING, "Jitter time (#{jitter_secs} seconds) is large" +
                  " compared to Validity/#{max_default_denial_type} " +
                  "(#{max_default_denial} seconds) for #{name} policy in #{kasp_file}")
            end

            # 14. Error if jitter is greater than either Default or Denial Validity
            if (jitter_secs > default_secs)
              log(LOG_ERR, "Jitter time (#{jitter_secs}) is greater than the Default Validity (#{default_secs}) for #{name} policy in #{kasp_file}")
            end
            if (jitter_secs > denial_secs)
              log(LOG_ERR, "Jitter time (#{jitter_secs}) is greater than the Denial Validity (#{denial_secs}) for #{name} policy in #{kasp_file}")
            end

            #   6. Warn if the InceptionOffset is greater than one hour. (Again arbitrary - but do we really expect the times on two systems to differ by more than this?)
            inception_offset_secs = get_duration(policy, 'Signatures/InceptionOffset', kasp_file)
            if (inception_offset_secs > (60 * 60))
              log(LOG_WARNING, "InceptionOffset is higher than expected " +
                  "(#{inception_offset_secs} seconds) for #{name} policy in #{kasp_file}")
            end

            #   7. Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.
            publish_safety_secs = get_duration(policy, 'Keys/PublishSafety', kasp_file)
            retire_safety_secs = get_duration(policy, 'Keys/RetireSafety', kasp_file)
            ttl_secs = get_duration(policy, 'Keys/TTL', kasp_file)
            [{publish_safety_secs , "Keys/PublishSafety"}, {retire_safety_secs, "Keys/RetireSafety"}].each {|pair|
              pair.each {|time, label|
                if (time < (0.1 * ttl_secs))
                  log(LOG_WARNING, "#{label} (#{time} seconds) in #{name} policy" +
                      " in #{kasp_file} is less than 0.1 * TTL (#{ttl_secs} seconds)")
                end
                if (time > (5 * ttl_secs))
                  log(LOG_WARNING, "#{label} (#{time} seconds) in #{name} policy" +
                      " in #{kasp_file} is more than 5 * TTL (#{ttl_secs} seconds)")
                end
              }
            }

            # Get the denial type (NSEC or NSEC3)
            denial_type = nil
            if (policy.elements['Denial/NSEC'])
              denial_type = "NSEC"
            else
              denial_type = "NSEC3"
              # Now check that the algorithm is correct
            policy.each_element('Denial/NSEC3/Hash/') {|hash|
              alg = hash.elements["Algorithm"].text
              if (alg.to_i != 1)
                  log(LOG_ERR, "NSEC3 Hash algorithm is #{alg} but should be 1");
              end
            }
            end

            # For all keys (if any are configured)...
            max = 9999999999999999
            ksk_lifetime = max
            zsk_lifetime = max
            policy.each_element('Keys/ZSK') {|zsk|
              check_key(zsk, "ZSK", name, kasp_file, denial_type)
              zskl = get_duration(zsk, 'Lifetime', kasp_file)
              zsk_lifetime = [zsk_lifetime, zskl].min
            }
            policy.each_element('Keys/KSK') {|ksk|
              check_key(ksk, "KSK", name, kasp_file, denial_type)
              kskl = get_duration(ksk, 'Lifetime', kasp_file)
              ksk_lifetime = [ksk_lifetime, kskl].min
            }

            #  12. Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.
            if ((ksk_lifetime != max) && (zsk_lifetime != max) && (ksk_lifetime < zsk_lifetime))
              log(LOG_WARNING, "KSK minimum lifetime (#{ksk_lifetime} seconds)" +
                  " is less than ZSK minimum lifetime (#{zsk_lifetime} seconds)"+
                  " for #{name} Policy in #{kasp_file}")
            end

            #   9. If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).
            resigns_per_day = (60 * 60 * 24) / resign_secs
            if (resigns_per_day > 99)
              # Check if the datecounter is used - if so, warn
              policy.each_element('Zone/SOA/Serial') {|serial|
                if (serial.text.downcase == "datecounter")
                  log(LOG_ERR, "In #{kasp_file}, policy #{name}, serial type datecounter used"+
                      " but #{resigns_per_day} re-signs requested."+
                      " No more than 99 re-signs per day should be used with datecounter"+
                      " as only 2 digits are allocated for the version number")
                  #  13. Check that the value of the "Serial" tag is valid.
                elsif !(["unixtime", "datecounter", "keep", "counter"].include?serial.text.downcase)
                  log(LOG_ERR, "In #{kasp_file}, policy #{name}, unknown Serial type encountered ('#{serial.text}')." +
                      " Should be either 'unixtime', 'counter', 'datecounter' or 'keep'")
                end
              }
            end
            ["Signatures/Resign", "Signatures/Refresh", "Signatures/Validity/Default",
              "Signatures/Validity/Denial", "Signatures/Jitter",
              "Signatures/InceptionOffset", "Keys/RetireSafety", "Keys/PublishSafety",
              "Keys/Purge", "NSEC3/Resalt", "SOA/Minimum", "ZSK/Lifetime",
              "KSK/Lifetime", "TTL", "PropagationDelay"].each {|element|
              policy.each_element(element) {|el| check_duration_element_proc(el, name, element, kasp_file)}
            }
          }

          #   1. Warn if a policy named "default" does not exist.
          if (!policy_names.include?"default")
            log(LOG_WARNING, "No policy named 'default' in #{kasp_file}. This " +
                "means you will need to refer explicitly to the policy for each zone")
          end

        }
      rescue Errno::ENOENT
        log(LOG_ERR, "Can't find KASP config file : #{kasp_file}")
      end
    end

    def check_key(key, type, policy, kasp_file, denial_type)
      #   7. The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.
      alg = key.elements['Algorithm'].text
      if (denial_type == "NSEC3")
        # Check correct algorithm used for NSEC3
        if (!(["6","7","8","10"].include?alg))
          log(LOG_ERR, "In policy #{policy}, incompatible algorithm (#{alg}) used for #{type} NSEC3" +
              " in #{kasp_file} - should be 6,7,8 or 10")
        end
      end

      #   9. The key strength should be checked for sanity - warn if less than 1024 or more than 4096
      begin
        key_length = key.elements['Algorithm'].attributes['length'].to_i
        if (key_length < 1024)
          log(LOG_WARNING, "Key length of #{key_length} used for #{type} in #{policy}"+
              " policy in #{kasp_file}. Should probably be 1024 or more")
        elsif (key_length > 4096)
          log(LOG_WARNING, "Key length of #{key_length} used for #{type} in #{policy}"+
              " policy in #{kasp_file}. Should probably be 4096 or less")
        end
      rescue Exception
        # Fine - this is an optional element
      end

      #  10. Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.
      repository = key.elements['Repository'].text
      if (!@repositories.keys.include?repository)
        log(LOG_ERR, "Unknown repository (#{repository}) defined for #{type} in"+
            " #{policy} policy in #{kasp_file}")
      end
    end

    def get_duration(doc, element, kasp_file)
      begin
        text = doc.elements[element].text
        # Now get the numSeconds from the XSDDuration format
        duration = KASPAuditor::Config.xsd_duration_to_seconds(text)
        return duration
      rescue Exception
        log(LOG_ERR, "Can't find #{element} in #{doc.attributes['name']} in #{kasp_file}")
        return 0
      end
    end
  end
end
