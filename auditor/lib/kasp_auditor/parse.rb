#!/usr/bin/env ruby

require 'rexml/document'
require 'syslog'
require 'lib/kasp_auditor/config.rb'
require 'lib/kasp_auditor/auditor.rb'
include REXML
include Syslog::Constants

module KASPAuditor
  # Load the config file, then check each of the zones defined there
  path = ARGV[0] + "/"
  zones = []
  Syslog.open() {|syslog|
    File.open(path+"zonelist.xml", 'r') {|file|
      doc = REXML::Document.new(file)
      doc.elements.each("Zonelist/Zone") {|z|
        # First load the config files
        zone_name = z.attributes['name']
        print "Processing zone name #{zone_name}\n"
        policy = z.elements['Policy'].text
        print "Policy #{policy}\n"
        config_file_loc = path + z.elements["SignerConfiguration"].text
        print "Config file location : #{config_file_loc}\n"
        # Now parse the config file
        config = Config.new(config_file_loc)

        input_file_loc = path + z.elements["Adapters"].elements['Input'].elements["File"].text
        print "Input file location : #{input_file_loc}\n"
        output_file_loc = path + z.elements["Adapters"].elements['Output'].elements["File"].text
        print "Output file location : #{output_file_loc}\n"
        zones.push([config, input_file_loc, output_file_loc])


      }
    }
    # Now check the input and output zones using the config
    auditor = Auditor.new(syslog)
    zones.each {|config, input_file, output_file|
      auditor.check_zone(config, input_file, output_file)
    }
  }
  exit(0) # @TODO@ Return value to controlling process!
end