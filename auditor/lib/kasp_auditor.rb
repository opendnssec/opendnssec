require 'syslog'
require 'lib/kasp_auditor/config.rb'
require 'lib/kasp_auditor/auditor.rb'
require 'lib/kasp_auditor/parse.rb'

module KASPAuditor
  class Runner
    def run(path, filename="zonelist.xml")
      #      path = ARGV[0] + "/"
      Syslog.open("kasp_auditor") { |syslog| run_with_syslog(path, filename, syslog)
      }
    end
    def run_with_syslog(path, filename, syslog)
      ret = Parse.parse(path, filename, syslog)
      exit(ret)
    end
  end
end
