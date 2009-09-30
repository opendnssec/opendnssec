require 'syslog'

module KASPChecker
  class Checker
    attr_accessor :conf_file, :kasp_file
    def check
      conf_file = @conf_file
      if (!conf_file)
        KASPAuditor.exit("No configuration file specified", 1)
      end
      # @TODO@ Call Sion's code to validate the conf.xml against the RNG
      # @TODO@ Now load the config file
      kasp_file = check_config_file(conf_file)

      # @TODO@ Call Sion's code to validate the kasp.xml against the RNG
      # @TODO@ Now load the kasp file
      check_kasp_file(kasp_file)

    end
  end
end
