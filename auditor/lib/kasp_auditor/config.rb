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

require 'xsd/datatypes'
module KASPAuditor
  # Represents KASP configuration file
  class Config
    attr_accessor :zone
    def initialize(config_file_loc)
      #      @zones = []
#      print "Opening config file : #{config_file_loc}\n"
      File.open(config_file_loc, 'r') {|file|
        doc = REXML::Document.new(file)
        #        doc.elements.each("SignerConfiguration/Zone") {|z|
        z = doc.elements['SignerConfiguration/Zone']
#        print "Name : #{z.attributes['name']}"
        new_zone = Zone.new(z.attributes['name'])
        # Fill out new zone
        new_zone.signatures = Zone::Signatures.new(z.elements['Signatures'])
        new_zone.denial = Zone::Denial.new(z.elements['Denial'])
        new_zone.keys = Zone::Keys.new(z.elements['Keys'])
        @zone = new_zone
        #          @zones.push(new_zone)
        #        }
      }
    end
    def self.xsd_duration_to_seconds xsd_duration
      # XSDDuration hack
      xsd_duration = "P0DT#{$1}" if xsd_duration =~ /^PT(.*)$/
      xsd_duration = "-P0DT#{$1}" if xsd_duration =~ /^-PT(.*)$/
      a = XSD::XSDDuration.new xsd_duration
      from_min = 0 | a.min * 60
      from_hour = 0 | a.hour * 60 * 60
      from_day = 0 | a.day * 60 * 60 * 24
      from_month = 0 | a.month * 60 * 60 * 24 * 30
      from_year = 0 | a.year * 60 * 60 * 24 * 30 * 12
      # XSD::XSDDuration seconds hack.
      x = a.sec.to_s.to_i + from_min + from_hour + from_day + from_month + from_year
      return x
    end

    class Zone
      def initialize(name=nil)
        @name = name
      end
      attr_accessor :name, :signatures, :keys, :denial
        
      class Signatures
        #               element Signatures {
        #	                        element Resign { xsd:duration },
        #	                        element Refresh { xsd:duration },
        #	                        element Validity {
        #	                                element Default { xsd:duration },
        #	                                element Denial { xsd:duration }
        #	                        },
        #	                        element Jitter { xsd:duration },
        #	                        element InceptionOffset { xsd:duration }
        #	                },
        attr_accessor :resign, :refresh, :jitter, :inception_offset, :validity
        def initialize(e)
          resign_text = e.elements['Resign'].text
          @resign = Config.xsd_duration_to_seconds(resign_text)
          refresh_text = e.elements['Refresh'].text
          @refresh = Config.xsd_duration_to_seconds(refresh_text)
          jitter_text = e.elements['Jitter'].text
          @jitter = Config.xsd_duration_to_seconds(jitter_text)
          inception_offset_text = e.elements['InceptionOffset'].text
          @inception_offset = Config.xsd_duration_to_seconds(inception_offset_text)

          @validity = Validity.new(e.elements['Validity'])
        end
        class Validity
          attr_accessor :default, :denial
          def initialize(e)
            default_text = e.elements['Default'].text
            @default = Config.xsd_duration_to_seconds(default_text)
            denial_text = e.elements['Denial'].text
            @denial = Config.xsd_duration_to_seconds(denial_text)
          end
        end
      end
      class Denial
        attr_accessor :nsec, :nsec3
        def initialize(e)
          if (e.elements['NSEC'])
            @nsec = Nsec.new() # e.elements['NSEC'])
          else
            @nsec3 = Nsec3.new(e.elements['NSEC3'])
          end
        end
        class Nsec
        end
        class Nsec3 # @TODO@ Actually create a Dnsruby::Resource::RR::NSEC3 here?
          attr_accessor :optout, :hash, :parameters
          def initialize(e)
            @optout = false
            if (e.elements['OptOut'])
              @optout = true
            end
            @hash = Hash.new(e.elements['Hash'])
            @parameters = Parameters.new(e.elements['Parameters'])
          end
          class Parameters
            attr_accessor :ttl
            def initialize(e)
              ttl_text = e.elements['TTL'].text
              @ttl = Config.xsd_duration_to_seconds(ttl_text)
            end
          end
          class Hash
            attr_accessor :algorithm, :iterations, :salt
            def initialize(e)
              @algorithm = e.elements['Algorithm'].text.to_i
              @iterations = e.elements['Algorithm'].text.to_i
              @salt = e.elements['Algorithm'].text
            end
          end
        end
      end
      class SOA
        attr_accessor :ttl, :minimum, :serial
      end
      class Keys
        attr_accessor :ttl, :keys
          def initialize(e)
              ttl_text = e.elements['TTL'].text
              @ttl = Config.xsd_duration_to_seconds(ttl_text)
              # Don't think we need any of the Key elements just now
          end
        class Key
          # Shouldn't need to use the Key element for the auditor
          attr_accessor :ttl, :flags, :algorithm, :locator, :ksk, :zsk, :publish
          #                       element Key {
          #	                                # DNSKEY flags
          #	                                element Flags { xsd:positiveInteger },
          #
          #	                                # DNSKEY algorithm
          #	                                algorithm,
          #	             
          #	                                # The key locator is matched against PKCS#11 CKA_ID in hex
          #	                                # e.g. DFE7265B-783F-4186-8538-0AA784C2F31D
          #	                                # is written as DFE7265B783F418685380AA784C2F31D
          #	                                element Locator { xsd:string },
          #
          #	                                # sign all the DNSKEY RRsets with this key?
          #	                                element KSK { empty }?,
          #
          #	                                # sign all non-DNSKEY RRsets with this key?
          #	                                element ZSK { empty }?,
          #
          #	                                # include this key in the zonefile?
          #	                                element Publish { empty }?
          #	                        }+
          #	                },
        end
      end
    end
  end
end