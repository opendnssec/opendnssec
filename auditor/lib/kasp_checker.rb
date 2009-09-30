require 'syslog'
include Syslog::Constants
require 'xsd/datatypes'
require 'rexml/document'
include REXML


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
    # Returns the configured location of the kasp.xml configuration file.
    def check_config_file(conf_file)
      kasp_file = nil
      #     @TODO@
      begin
        File.open((conf_file + "").untaint , 'r') {|file|
          doc = REXML::Document.new(file)
          begin
            kasp_file = doc.elements['Configuration/Common/PolicyFile'].text
          rescue Exception
            log(LOG_ERR, "Can't read KASP policy location from conf.xml - exiting")
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
        }
      rescue Errno::ENOENT
        log(LOG_ERR, "ERROR - Can't find config file : #{conf_file}")
      end
      return ((kasp_file+"").untaint)
    end


    def check_kasp_file(kasp_file)
      # @TODO@
    end
  end
end
