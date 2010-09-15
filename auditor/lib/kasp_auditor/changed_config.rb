# $Id$
#
# Copyright (c) 2010 Nominet UK. All rights reserved.
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

module KASPAuditor
  # This class holds information about configuration elements which have changed,
  # if the changed element is likely to affect the way the zone is audited.
  # It keeps a list of the elements which we are interested in, the last value they
  # were seen to have, and the timestamp at which that value changed (0 if they
  # have not been seen to change).
  # It allows the auditor to respond to changes in policy, and not raise errors
  # when it sees records in the zone which still conform to the old policy.
  # @TODO@ TEST CODE FOR THIS CLASS!
  # @TODO@ TEST CODE FOR THE POLICY CHANGES FUNCTIONALITY - check that the auditor
  #   does not produce errors as a result of changes in policy.
  class ChangedConfig
     # This class holds some data, along with the timestamp at which is was last
     # seen to change
    class Element
      attr_accessor :timestamp
      attr_reader :value
      # e.g. Element.new(3)
      # Element.new(3, Time.now.to_i)
      def initialize(*args)
        @timestamp = 0
        if (args.length >= 1)
          @value = args[0]
          if (args.length == 2)
            @timestamp = args[1]
          end
        end
      end
      def to_s
        if (@value.class == Array)
          ret = ""
          @value.each {|v|
            ret += "#{v}, "
          }
          ret += "#{@timestamp}"
          return ret
        else
          return "#{@value}, #{@timestamp}"
        end
      end

    end

    # This class allows a Key config element to be stored in a single Element,
    # with meaningful methods to access the data within.
    class Key < Element
      def algorithm
        return @value[0]
      end
      def alg_length
        return @value[1]
      end
      def standby
        return @value[2]
      end
      def lifetime
        return @value[3]
      end
    end
    
    attr_accessor :rrsig_inception_offset, :zsks, :ksks
    attr_accessor :kasp_timestamp, :conf_timestamp

    # Initialised by the config parsing system - works out what has changed on
    # startup, and stores the data internally. The only other public methods are
    # inspection methods
    def initialize(*args)
      zone = args[0]
      conf_file = args[1]
      kasp_file = args[2]
      config = args[3]
      working_folder = args[4]
      signconf_file = args[5]
      syslog = args[6]
      return if args.length > 7

      tracker_folder = (working_folder + File::SEPARATOR +
        "tracker").untaint

      begin
        Dir.mkdir(tracker_folder) unless File.directory?(tracker_folder)
      rescue Errno::ENOENT
        syslog.log(LOG_ERR, "Can't create working folder : #{tracker_folder}")
        KASPAuditor.exit("Can't create working folder : #{tracker_folder}", 1)
      end


      tracker_filename = tracker_folder + File::SEPARATOR + zone + ".config"
      tracker_filename = (tracker_filename.to_s + "").untaint


      if !(load_last_config_changes(tracker_filename))
        reset_elements(config, conf_file, kasp_file)
      end
      
      # Now get the timestamps for the conf and kasp files
      kasp_file = (kasp_file.to_s + "").untaint
      conf_file = (conf_file.to_s + "").untaint
      signconf_file = (signconf_file.to_s + "").untaint
      conf_timestamp = File.mtime(conf_file).to_i
      kasp_timestamp = File.mtime(kasp_file).to_i
      signconf_timestamp = File.mtime(signconf_file).to_i
      @conf_timestamp = conf_timestamp
      @kasp_timestamp = kasp_timestamp


      new_enforcer_interval = load_enforcer_interval(conf_file)
      # Has the enforcer interval changed?
      if !(new_enforcer_interval == @enforcer_interval.value)
        # If so, then store it along with the timestamp
        @enforcer_interval = Element.new(new_enforcer_interval, conf_timestamp)
      end
      # If the kasp_filename hasn't changed, then we can simply use the kasp_timestamp
      # for all KASP config items.
      timestamp = kasp_timestamp
      if (kasp_file != @kasp_filename.value)
        @kasp_filename = Element.new(kasp_file, conf_timestamp)
        if (conf_timestamp < timestamp)
          timestamp = conf_timestamp
        end
      end
      # Also check the timestamp of the signconf file, and warn if it
      # is older than the kasp.xml.
      if (signconf_timestamp < kasp_timestamp)
        syslog.log(LOG_WARNING, "THE SIGNER CONFIGURATION IS OLDER THAN THE KASP CONFIGURATION - IT MAY NOT HAVE BEEN UPDATED. IF SO, ERRORS MAY BE RAISED BY THE AUDITOR")
      end


      check_kasp_config(config, timestamp)

      write_config_changes(tracker_filename)
    end

    def write_config_changes(file)
      # Store the data to file!
      File.open(file + ".temp", 'w') { |f|
        f.puts(@kasp_filename.to_s)
        f.puts(@enforcer_interval.to_s)
        f.puts(@rrsig_inception_offset.to_s)
        f.puts(@rrsig_refresh.to_s)
        f.puts(@rrsig_resign.to_s)
        f.puts(@rrsig_jitter.to_s)
        f.puts(@rrsig_validity_default.to_s)
        f.puts(@rrsig_validity_denial.to_s)
        # ZSKs, KSKs
        f.puts("ZSK")
        @zsks.each {|zsk|
          f.puts(zsk.to_s)
          # algorithm, alg_length, standby, lifetime
        }
        f.puts("KSK")
        @ksks.each {|ksk|
          f.puts(ksk.to_s)
        }
      }
      # Now move the .temp file over the original
      begin
        File.delete(file)
      rescue Exception => e
        #                print "Error deleting #{f} : #{e}\n"
      end
      File.rename(file+".temp", file)
    end

    def load_last_config_changes(file)
      # Load the file storing the previously saved values for the config items
      # Return true if loaded successfully
      begin
      File.open(file) { |f|
        line = f.gets
        @kasp_filename = Element.new(line.split()[0].chop, line.split()[1].to_i)
        line = f.gets
        @enforcer_interval = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_inception_offset = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_refresh = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_resign = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_jitter = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_validity_default = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        line = f.gets
        @rrsig_validity_denial = Element.new(line.split()[0].to_i, line.split()[1].to_i)
        f.gets # "ZSK"
        @zsks = []
        until ((line = f.gets) == "KSK\n")
          algorithm = line.split()[0]
          alg_length = line.split()[1].to_i
          standby = line.split()[2].to_i
          lifetime = line.split()[3].to_i
          zsk = Key.new([algorithm, alg_length, standby, lifetime], line.split()[4].to_i)
          @zsks.push(zsk)
        end
        @ksks = []
        while (line = f.gets)
          algorithm = line.split()[0]
          alg_length = line.split()[1].to_i
          standby = line.split()[2].to_i
          lifetime = line.split()[3].to_i
          ksk = Key.new([algorithm, alg_length, standby, lifetime], line.split()[4].to_i)
          @ksks.push(ksk)
        end
        return true
      }
      rescue Exception
        return false
      end
      return false
    end

    # Reset the cache
    def reset_elements(config, conf_file, kasp_file)
      @zsks = []
      @ksks = []
      @kasp_filename = Element.new(kasp_file)
      @enforcer_interval = Element.new(load_enforcer_interval(conf_file))
      @rrsig_inception_offset = Element.new(config.signatures.inception_offset)
      @rrsig_refresh = Element.new(config.signatures.refresh)
      @rrsig_resign = Element.new(config.signatures.resign)
      @rrsig_jitter = Element.new(config.signatures.jitter)
      @rrsig_validity_default = Element.new(config.signatures.validity.default)
      @rrsig_validity_denial = Element.new(config.signatures.validity.denial)
    end

    def check_kasp_config(config, timestamp)
      # Check off the config items we're interested in from the KASP
      if (@rrsig_inception_offset.value != config.signatures.inception_offset)
        @rrsig_inception_offset = Element.new(config.signatures.inception_offset, timestamp)
      end
      if (@rrsig_refresh.value != config.signatures.refresh)
        @rrsig_refresh = Element.new(config.signatures.refresh, timestamp)
      end
      if (@rrsig_resign.value != config.signatures.resign)
        @rrsig_resign = Element.new(config.signatures.resign, timestamp)
      end
      if (@rrsig_jitter.value != config.signatures.jitter)
        @rrsig_jitter = Element.new(config.signatures.jitter, timestamp)
      end
      if (@rrsig_validity_default.value != config.signatures.validity.default)
        @rrsig_validity_default = Element.new(config.signatures.validity.default, timestamp)
      end
      if (@rrsig_validity_denial.value != config.signatures.validity.denial)
        @rrsig_validity_denial = Element.new(config.signatures.validity.denial, timestamp)
      end
      # NOW DO ZSKs AND KSKs
      check_key_config(@zsks, config.keys.zsks, timestamp)
      check_key_config(@ksks, config.keys.ksks, timestamp)
    end
    
    def check_key_config(store_keys, config_keys, timestamp)
      # There is a ZSK lifetime for each ZSK element in the Keys config - [alg, alg_length, standby, lifetime] tuple
      # How do we identify each ZSK tuple? by algorithm/length - and hope that all aren't changed at once?
      # Or can we simply identify ones which *have not* changed?
      # i.e. go through, and if we don't recognise a ZSK or KSK, then set the timestamp to the new timestamp for that ZSK/KSK
      # and remember to remove ones we have seen in the past if we no longer see them now!
      used_config_keys = []
      store_keys.each {|key|
        zsk_unchanged = false
        config_index = 0
        config_keys.each {|config_zsk|
          zsk_unchanged = ((config_zsk.algorithm == key.value[0]) &&
              (config_zsk.alg_length == key.value[1]) &&
              (config_zsk.standby == key.value[2]) &&
              (config_zsk.standby == key.value[3]))
          break if zsk_unchanged
          config_index += 1
        }
        if (zsk_unchanged)
          # Mark the fact that we have used this config_zsk
          used_config_keys.push(config_index)
        else
          # This ZSK is no longer found. So - do we create a new ZSK, and delete the old one?
          store_keys.delete(key)
        end
      }
      # Now what about the config_zsk blocks which have not been used?
      index = 0
      config_keys.each {|config_key|
        next if (used_config_keys.include?index)
        # This config_zsk was not used - create a new ZSK Element for it
        k = Key.new([config_key.algorithm, config_key.alg_length,
            config_key.standby, config_key.lifetime], timestamp)
        store_keys.push(k)

        index += 1
      }
    end

    def get_signature_timestamp
      # Get the earliest signature-related timestamp which is not 0
      min_timestamp = 999999999999
      [@rrsig_inception_offset, @rrsig_refresh, @rrsig_resign, @rrsig_jitter,
       @rrsig_validity_default, @rrsig_validity_denial].each {|el|
        if ((el.timestamp > 0) && (el.timestamp < min_timestamp))
          min_timestamp = el.timestamp
        end
      }
      if (min_timestamp == 999999999999)
        return 0
      else
        return min_timestamp
      end
    end

    # Has the Signature configuration for this policy changed?
    def signature_config_changed?
      if (get_signature_timestamp != 0)
        return true
      end
      return false
    end

    def load_enforcer_interval(conf_file)
      # Now load the enforcer_interval
      enforcer_interval = nil
      File.open((conf_file + "").untaint , 'r') {|file|
        doc = REXML::Document.new(file)
        begin
          e_i_text = doc.elements['Configuration/Enforcer/Interval'].text
          enforcer_interval = Config.xsd_duration_to_seconds(e_i_text)
        rescue Exception
          KASPAuditor.exit("Can't read Enforcer->Interval from Configuration", 1)
        end
      }
      return enforcer_interval

    end
  end
end