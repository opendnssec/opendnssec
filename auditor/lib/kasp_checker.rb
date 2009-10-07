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
      when LOG_FATAL then "FATAL"
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

        stderr = IO::pipe
        pid = fork {
          stderr[0].close
          STDERR.reopen(stderr[1])
          stderr[1].close

          options = Syslog::LOG_PERROR | Syslog::LOG_NDELAY

          Syslog.open("kasp_check_internal", options) {|syslog|
            ret = system("#{(@xmllint.to_s + "").untaint} --noout --relaxng #{rng_location} #{file}")
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
            #            log(LOG_INFO, line + " OK")
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
          }

          #
          #  Also 
          # check durations for Interval and RolloverNotification (the only duration elements in conf.xml)
          ["Enforcer/Interval", "Enforcer/RolloverNotification"].each {|element|
            check_duration_element(doc, element, conf_file)
          }

        }
        return ((kasp_file+"").untaint)
      rescue Errno::ENOENT
        log(LOG_ERR, "ERROR - Can't find config file : #{conf_file}")
        return nil
      end
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

            #   4. Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period. (This is a bit arbitrary. The point is to get the user to realise that there will be a large spread in the signature lifetimes.)
            jitter_secs = get_duration(policy, 'Signatures/Jitter', kasp_file)
            max_default_denial=[default_secs, denial_secs].max
            max_default_denial_type = max_default_denial == default_secs ? "Default" : "Denial"
            if (jitter_secs > (max_default_denial * 0.5))
              log(LOG_WARNING, "Jitter time (#{jitter_secs} seconds) is large" +
                  " compared to Validity/#{max_default_denial_type} " +
                  "(#{max_default_denial} seconds) for #{name} policy in #{kasp_file}")
            end

            #   5. Warn if the InceptionOffset is greater than ten minutes. (Again arbitrary - but do we really expect the times on two systems to differ by more than this?)
            inception_offset_secs = get_duration(policy, 'Signatures/InceptionOffset', kasp_file)
            if (inception_offset_secs > (10 * 60))
              log(LOG_WARNING, "InceptionOffset is higher than expected " +
                  "(#{inception_offset_secs} seconds) for #{name} policy in #{kasp_file}")
            end

            #   6. Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.
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
            end

            # For all keys (if any are configured)...
            max = 9999999999999999
            ksk_lifetime = max
            zsk_lifetime = max
            policy.each_element('//ZSK') {|zsk|
              check_key(zsk, "ZSK", name, kasp_file, denial_type)
              zskl = get_duration(zsk, 'Lifetime', kasp_file)
              zsk_lifetime = [zsk_lifetime, zskl].min
            }
            policy.each_element('//KSK') {|ksk|
              check_key(ksk, "KSK", name, kasp_file, denial_type)
              kskl = get_duration(ksk, 'Lifetime', kasp_file)
              ksk_lifetime = [ksk_lifetime, kskl].min
            }

            #  11. Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.
            if ((ksk_lifetime != max) && (zsk_lifetime != max) && (ksk_lifetime < zsk_lifetime))
              log(LOG_WARNING, "KSK minimum lifetime (#{ksk_lifetime} seconds)" +
                  " is less than ZSK minimum lifetime (#{zsk_lifetime} seconds)"+
                  " for #{name} Policy in #{kasp_file}")
            end

            #  12. Check that the value of the "Serial" tag is valid.
            # - this check is performed by validating the XML against the RNG

            #   8. If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).
            resigns_per_day = (60 * 60 * 24) / resign_secs
            if (resigns_per_day > 99)
              # Check if the datecounter is used - if so, warn
              policy.each_element('//Serial') {|serial|
                if (serial.text.downcase == "datecounter")
                  log(LOG_ERR, "Serial type datecounter used in #{name} policy"+
                      " in #{kasp_file}, but #{resigns_per_day} re-signs requested."+
                      " No more than 99 re-signs per day should be used with datecounter"+
                      " as only 2 digits are allocated for the version number")
                end
              }
            end
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

    def check_key(key, type, policy, kasp_file, denial_type)
      #   7. The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.
      alg = key.elements['Algorithm'].text
      if (denial_type == "NSEC")
        # Check correct algorithm used for NSEC
        if ((["6","7"].include?alg))
          log(LOG_ERR, "Incompatible algorithm (#{alg}) used for #{type} NSEC in #{policy}"+
              " policy in #{kasp_file}")
        end
      else
        # Check correct algorithm used for NSEC3
        if (!(["6","7"].include?alg))
          log(LOG_ERR, "Incompatible algorithm (#{alg}) used for #{type} NSEC3 in #{policy}" +
              " policy in #{kasp_file} - should be 6 or 7")
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
