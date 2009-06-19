#!/usr/bin/env ruby
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

require 'rexml/document'
include REXML

module KASPAuditor
  class Parse
    def self.parse(path, filename, syslog)
      # Load the config file, then check each of the zones defined there
      zones = []
      #    File.open(path+"zonelist.xml", 'r') {|file|
      File.open(path + filename, 'r') {|file|
        doc = REXML::Document.new(file)
        doc.elements.each("Zonelist/Zone") {|z|
          # First load the config files
          zone_name = z.attributes['name']
#          print "Processing zone name #{zone_name}\n"
          policy = z.elements['Policy'].text
#          print "Policy #{policy}\n"
          config_file_loc = path + z.elements["SignerConfiguration"].text
#          print "Config file location : #{config_file_loc}\n"
          # Now parse the config file
          config = Config.new(config_file_loc)

          input_file_loc = path + z.elements["Adapters"].elements['Input'].elements["File"].text
#          print "Input file location : #{input_file_loc}\n"
          output_file_loc = path + z.elements["Adapters"].elements['Output'].elements["File"].text
#          print "Output file location : #{output_file_loc}\n"
          zones.push([config, input_file_loc, output_file_loc])
        }
      }
      return zones
    end
  end
end