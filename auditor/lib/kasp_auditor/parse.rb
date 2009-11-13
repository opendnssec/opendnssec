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
    def self.parse(path, zonelist_filename, kasp_filename, syslog, working_folder)
      # We need to open [/etc/opendnssec/]conf.xml,
      #                 [/etc/opendnssec/]kasp.xml,
      #                 [/etc/opendnssec/]zonelist.xml
      #
      # The zonelist.xml specified the zones. It also specified the policy for
      # the zone.
      # The policy refers to a policy defined in kasp.xml, which specifies all
      # except for the salt.
      # The conf.xml specifies the signer working directory, as well as the syslog
      # So, we parse zonelist.xml. We should read the policy from there.
      # We should then read the kasp.xml file to find the policy of interest.
      # We also need to read SignerConfiguration, just so we know the salt.
      zones = []
      File.open((zonelist_filename.to_s+"").untaint, 'r') {|file|
        doc = REXML::Document.new(file)
        doc.elements.each("ZoneList/Zone") {|z|
          # First load the config files
          zone_name = z.attributes['name']
          policy = z.elements['Policy'].text

          config_file_loc = z.elements["SignerConfiguration"].text
          if (config_file_loc.index(File::SEPARATOR) != 0)
            config_file_loc = path + config_file_loc
          end

          # Now parse the config file
          begin
            config = Config.new(zone_name, kasp_filename, policy,
              config_file_loc, syslog)

            input_file_loc = z.elements["Adapters"].elements['Input'].elements["File"].text
            # Input file should not come from the unsigned/<zone> file.
            # It should come from tmp/<zone>.unsorted
            sep = input_file_loc.rindex(File::Separator)
            filename = input_file_loc[(sep ? sep + 1 : 0), input_file_loc.length]
            input_file_loc = working_folder + File::Separator + filename + ".unsorted"

            output_file_loc = z.elements["Adapters"].elements['Output'].elements["File"].text
            if (output_file_loc.index(File::SEPARATOR) != 0)
              output_file_loc = path + output_file_loc
            end
            zones.push([config, input_file_loc, output_file_loc])
          rescue Config::ConfigLoadError => e
            msg = "Can't load #{zone_name} SignerConfiguration file (#{config_file_loc}) : #{e}"
            print msg+"\n"
            syslog.log(LOG_ERR, msg)
          end
        }
      }
      return zones
    end
  end
end