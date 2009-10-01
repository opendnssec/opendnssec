require 'syslog'
include Syslog::Constants
require 'xsd/datatypes'
require 'rexml/document'
include REXML
require 'kasp_auditor/config.rb'

require 'etc'


module KASPChecker
  class Checker
    $SAFE = 1
    KASP_FILE = "kasp"
    CONF_FILE = "conf"
    attr_accessor :conf_file, :kasp_file, :rng_path, :xmllint
    def check
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

    end

    def log(level, msg)
      if (@syslog)
        Syslog.open("kasp_check", Syslog::LOG_PID |
          Syslog::LOG_CONS, @syslog) { |slog|
          slog.log(level, msg)
        }
      end
      # @TODO@ Convert the level into text, rather than a number? e.g. "WARNING"
      print "#{level}: #{msg}\n"
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

        stderr = IO::pipe
        pid = fork {
          stderr[0].close
          STDERR.reopen(stderr[1])
          stderr[1].close

          options = Syslog::LOG_PERROR | Syslog::LOG_NDELAY

          Syslog.open("kasp_check_internal", options) {|syslog|
            ret = system("#{xmllint} --noout --relaxng #{rng_location} #{file}")
            exit!(ret)
          }
        }
        stderr[1].close
        Process.waitpid(pid)
        ret_val = $?.exitstatus

        # Now rewrite captured output from xmllint to log method
        while (line = stderr[0].gets)
          line.chomp!
          if line.index(" validates")
            log(LOG_INFO, line)
          else
            log(LOG_ERR, line)
          end
        end

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
          doc = REXML::Document.new(file)
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
          repositories = {}
          doc.elements.each('Configuration/RepositoryList/Repository') {|repository|
            name = repository.attributes['name']
            # @TODO@ Check if two repositories exist with the same name
            mod = repository.elements['Module'].text
            #   5. Check that the shared library (Module) exists.
            if (!File.exist?((mod+"").untaint))
              log(LOG_ERR, "Module #{mod} in Repository #{name} cannot be found")
            end

            tokenlabel = repository.elements['TokenLabel'].text
            print "Checking Module #{mod} and TokenLabel #{tokenlabel} in Repository #{name}\n"
            # Now check if repositories already includes the [mod, tokenlabel] hash
            if (repositories.values.include?([mod, tokenlabel]))
              log(LOG_ERR, "Multiple Repositories in #{conf_file} have the same Module (#{mod}) and TokenLabel (#{tokenlabel}), for Repository #{name}")
            end
            repositories[name] =  [mod, tokenlabel]
            #   3. If a repository specifies a capacity, the capacity must be greater than zero.
            # This check is performed when the XML is validated against the RNG (which specifies positiveInteger for Capacity)
          }

          #
          #  Also 
          # check durations for Interval KeygenInterval and RolloverNotification (the only duration elements in conf.xml)
          ["Enforcer/KeygenInterval", "Enforcer/Interval", "Enforcer/RolloverNotification"].each {|element|
            check_duration_element(doc, element, conf_file)
          }

        }
      rescue Errno::ENOENT
        log(LOG_ERR, "ERROR - Can't find config file : #{conf_file}")
      end
      return ((kasp_file+"").untaint)
    end

    def check_duration_element(doc, name, filename)
      #   1. If 'm' is used in the XSDDuration, then warn the user that 31 days will be used instead of one month.
      #   2. If 'y' is used in the XSDDuration, then warn the user that 365 days will be used instead of one year.
      doc.root.each_element("//"+name) {|element|
        duration = element.text
        #           print "Checking duration of #{name} : #{duration}, #{duration.length}\n"
        last_digit = duration[duration.length-1, 1].downcase
        if (last_digit == "m")
          log(LOG_WARNING, "M used in duration field for #{name} (#{duration})" +
              " in #{filename} - this will be interpreted as 31 days")
        end
        if (last_digit == "y")
          log(LOG_WARNING, "Y used in duration field for #{name} (#{duration})" +
              " in #{filename} - this will be interpreted as 365 days")
        end
      }
    end


    def check_kasp_file(kasp_file)
      begin
        File.open(kasp_file, 'r') {|file|
          doc = REXML::Document.new(file)
          # Run the following checks on kasp.xml :
          policy_names = []
          doc.elements.each('KASP/Policy') {|policy|
            name = policy.attributes['name']
            # @TODO@ Check if two policies exist with the same name
            policy_names.push(name)

            #   2. For all policies, check that the "Re-sign" interval is less than the "Refresh" interval.
            resign_secs = get_duration(policy,'Signatures/Resign')
            refresh_secs = get_duration(policy, 'Signatures/Refresh')
            if (refresh_secs <= resign_secs)
              log(LOG_ERR, "The Refresh interval (#{refresh_secs}) for #{name}" +
                  " Policy in #{kasp_file} is less than the Resign interval" +
                  " (#{resign_secs})")
            end

            #   3. @TODO@ Ensure that the "Default" and "Denial" validity periods are greater than the "Refresh" interval.
            #   4. @TODO@ Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period. (This is a bit arbitrary. The point is to get the user to realise that there will be a large spread in the signature lifetimes.)
            #   5. @TODO@ Warn if the InceptionOffset is greater than ten minutes. (Again arbitrary - but do we really expect the times on two systems to differ by more than this?)
            #   6. @TODO@ Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.
            #   7. @TODO@ The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.
            #   8. @TODO@ If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).
            #   9. @TODO@ The key strength should be checked for sanity - e.g. "1024" bit key is good, but "1023" or "10" is suspect.
            #  10. @TODO@ Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.
            #  11. @TODO@ Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.
            #  12. @TODO@ Check that the value of the "Serial" tag is valid.
          }

          #   1. Warn if a policy named "default" does not exist.
          if (!policy_names.include?"default")
            log(LOG_WARNING, "No policy named 'default' in #{kasp_file}. This " +
                "means you will need to refer explicitly to the policy for each zone")
          end

          ["Signatures/Resign", "Signatures/Refresh", "Signatures/Validity/Default",
            "Signatures/Validity/Denial", "Signatures/Jitter",
            "Signatures/InceptionOffset", "Keys/RetireSafety", "Keys/PublishSafety",
            "Keys/Purge", "NSEC3/Resalt", "SOA/Minimum", "ZSK/Lifetime",
            "KSK/Lifetime", "TTL", "PropagationDelay"].each {|element|
            check_duration_element(doc, element, kasp_file)
          }
        }
      rescue Errno::ENOENT
        log(LOG_ERR, "ERROR - Can't find config file : #{kasp_file}")
      end
    end

    def get_duration(doc, element)
      begin
        text = doc.elements[element].text
        # Now get the numSeconds from the XSDDuration format
        duration = KASPAuditor::Config.xsd_duration_to_seconds(text)
        return duration
      rescue Exception
        log(LOG_ERR, "Can't find #{element} in #{doc.attributes['name']}")
        return 0
      end
    end
  end
end
