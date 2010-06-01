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

include Syslog::Constants
module KASPAuditor
  # The Auditor class performs the actual auditing of the parsed zone files.
  # It processes the canonically sorted files one top-level sub-domain of the
  # zone at a time. If processing an NSEC3-signed zone, then the auditor will
  # also create some transient files (to allow it to check the types_covered
  # field of the NSEC3 record, and to check opt-out). These files will be
  # removed at the end of the run.

  # @TODO@ SOA Checks - format, etc.
  
  class Auditor # :nodoc: all
    class FatalError < Exception
    end
    EMPTY_NAME = Name.create(".")
    ##
    # Create a new Auditor - pass in the created syslog for logging, the path
    # of the working (temporary) directory, and the //Enforcer/Interval
    # Once created, use the check_zone method to audit a zone.
    # An Auditor class can be reset using the reset method, but it's probably
    # best to create a new Auditor for each zone you want to audit.
    # This class is thread-safe.
    def initialize(syslog, working, enforcer_interval)
      @syslog = syslog
      @working = (working.to_s + "").untaint
      @enforcer_interval = enforcer_interval
      reset
    end
    # Reset the auditor - used privately. It's best to instantiate a new Auditor
    # for each zone you want to audit.
    def reset
      @ret_val = 999
      @keys = []
      @keys_used = []
      @unsigned_keys = []
      @algs = []
      @last_nsec3_hashed = nil
      @nsec3param = nil
      @first_nsec3 = nil
      @count = 0
      @last_nsec = nil
      @first_nsec = nil
      @warned_about_nsec3param = false
      @zone_name = ""
      @soa = nil
      @config = nil
      @key_tracker = nil
      @key_cache = nil
      @unknown_nsecs = {}
    end
    attr_reader :config
    def set_config(c) # :nodoc: all
      @config = c
      if (@config.inconsistent_nsec3_algorithm?)
        log(LOG_WARNING, "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used")
      end
    end

    # Actually audit a zone.
    # Pass in the Config object, and the paths to :
    #  the parsed and sorted signed file
    #  the parsed and sorted unsigned file
    #  the original (unparsed) unsigned file
    #  the original (unparsed) signed file
    # Returns an error code equivalent to the worst log level message created.
    # A non-zero return is only generated if LOG_ERR or worse log level messages
    # were created.
    # If the zone to be audited is NSEC3-signed, then additional temporary files
    # will be created during the audit. These will be deleted at the end of the
    # audit.
    # In order to track keys over time, a "permanent temporary" file is created,
    # in a "tracker" folder in the working directory. This will not be deleted
    # by the auditor, as it is required to keep state on the zone over time.
    def check_zone(cnfg, unsigned_file, signed_file, original_unsigned_file, original_signed_file)
      reset
      @num_output_lines = 0
      set_config(cnfg)
      nsec3auditor = Nsec3Auditor.new(self, @working)
      nsec3auditor.delete_nsec3_files()
      begin
        # Load SOA record from top of original signed and unsigned files!
        load_soas(original_unsigned_file, original_signed_file)
        if ((@config.name != @soa.name.to_s) && (@config.name != @soa.name.to_s.chop))
          log(LOG_ERR, "SOA name (#{@soa.name}) is different to the configured zone name (#{@config.name}) - aborting")
          return 1
        end
        if (!@soa.name.absolute?)
          log(LOG_ERR, "SOA name not absolute #{@soa.name} - aborting")
          return 1
        end
        log(LOG_INFO, "Auditing #{@soa.name} zone : #{@config.denial.nsec ? 'NSEC' : 'NSEC3'} SIGNED")
        @key_tracker = KeyTracker.new(@working, @soa.name.to_s, self, @config, @enforcer_interval)
        @key_cache = @key_tracker.load_tracker_cache

        signed_file = (signed_file.to_s + "").untaint
        unsigned_file = (unsigned_file.to_s + "").untaint
        File.open(unsigned_file) {|unsignedfile|
          File.open(signed_file) {|signedfile|
            last_signed_rr = get_next_rr(signedfile)
            last_unsigned_rr = get_next_rr(unsignedfile)
            while (!unsignedfile.eof? || !signedfile.eof?)

              # Load up zone one subdomain (of zone) at a time. This may be many RRSets.
              #   Keep loading until we have all the RRSets for that subdomain.
              # Do this in both files. If they get out of step, then resynch using alphabetical order as guide.

              # So, load the next record from each file.
              # Compare the records (first subdomain of soa.name)
              # If they are not the same, then print out all the RRs which are for a different name.
              #    - keep going through "lowest" file until subdomain of other file is reached.
              # If they are the same, then continue loading that subdomain from both files.
              # Then process that domain
              #
              # Of course, we will always load one record too many here. We need to keep that last record
              # so we can build up the next subdomains rrsets with it.
              unsigned_domain_rrs = []
              compare_return = compare_subdomain_of_zone(last_signed_rr, last_unsigned_rr)
              while (last_unsigned_rr && compare_return != 0 && (!unsignedfile.eof? || !signedfile.eof?))
                # Work out which file is behind, then continue loading records from that zone until we're at the same subdomain of the zone soa
                if ((compare_return > 0) || (!last_signed_rr)) # unsigned < signed
                  # Log missing signed subdomain - check if out of zone first
                  process_additional_unsigned_rr(last_unsigned_rr)
                  # Load next unsigned record
                  #                print "Loading another unsigned record to catch up to signed\n"
                  last_unsigned_rr = get_next_rr(unsignedfile)
                elsif (compare_return < 0) # unsigned > signed
                  #                print "Signed file behind unsigned - loading next subdomain from #{last_signed_rr.name}\n"
                  last_signed_rr = load_signed_subdomain(signedfile, last_signed_rr, [])
                  #                print "Last signed rr now: #{last_signed_rr}\n"
                end
                #              print"Comparing signed #{last_signed_rr} to unsigned #{last_unsigned_rr}\n"
                compare_return = compare_subdomain_of_zone(last_signed_rr, last_unsigned_rr)
              end

              # Now we're at the same subdomain of the zone name. Keep loading from both files until the subdomain changes in that file.
              #            print "Now at #{last_signed_rr.name} for signed, and #{last_unsigned_rr.name} for unsigned\n"
              unsigned_domain_rrs, last_unsigned_rr = load_unsigned_subdomain(unsignedfile, last_unsigned_rr)
              last_signed_rr = load_signed_subdomain(signedfile, last_signed_rr, unsigned_domain_rrs)

            end
            if (last_unsigned_rr && (!last_signed_rr || (compare_return != 0) ) )
              process_additional_unsigned_rr(last_unsigned_rr)
            end
          }
        }
        # Now take a look at how the keys are changing over time...
        @key_tracker.process_key_data(@keys, @keys_used, @soa.serial, @config.soa.ttl)

        # Check the last nsec(3) record in the chain points back to the start
        do_final_nsec_check()

        # Now check the keys we have built up
        Auditor.check_key_config(@keys, @unsigned_keys, @key_cache, @config, self)

        # Now check the NSEC3 opt out and types_covered, if applicable
        if (@config.denial.nsec3)
          nsec3auditor.check_nsec3_types_and_opt_out(@unknown_nsecs)
        end
      rescue FatalError => e
        return 3
      end

      # Now sort out the return value
      log(LOG_INFO, "Finished auditing #{@soa.name} zone")
      if (@ret_val == 999)
        return 0
      else
        return @ret_val
      end

    end

    # Make sure that the last NSEC(3) record points back to the first one
    def do_final_nsec_check()
      if ((!@first_nsec) && (!@first_nsec3))
        log(LOG_ERR, "No #{nsec_string} records in zone")
        return
      end
      if (@config.denial.nsec && (@first_nsec.type == Dnsruby::Types::NSEC))
        # Now check that the last nsec points to the first nsec
        if (@first_nsec && (@last_nsec.next_domain == @first_nsec.name))
        else
          # An unknown NSEC could be between the last and first
          if (@unknown_nsecs[@last_nsec.next_domain.to_s+"." + @zone_name + "."] &&
                (@unknown_nsecs[@last_nsec.next_domain.to_s+"." + @zone_name + "."] == @first_nsec.to_s+"."))
          else
            log(LOG_ERR, "Can't follow NSEC loop from #{@last_nsec.name} to #{@last_nsec.next_domain}")
          end
        end
      elsif (@config.denial.nsec3) # && ((@first_nsec.type == Dnsruby::Types::NSEC3)))
        # Now check that the last nsec3 points to the first nsec3
        if (@first_nsec && (get_next_nsec3_name(@last_nsec).to_s == @first_nsec.name.to_s))
        else
          # An unknown NSEC3 could be between the last and first
          if (@unknown_nsecs[get_next_nsec3_name(@last_nsec).to_s+"."] &&
                (@unknown_nsecs[get_next_nsec3_name(@last_nsec).to_s+"."] == @first_nsec.name.labels()[0].to_s))
          else
            log(LOG_ERR, "Can't follow NSEC3 loop from #{@last_nsec.name} to #{get_next_nsec3_name(@last_nsec)}. Was actually #{@first_nsec.name}")
          end
        end
      end
    end

    # Load the next RR from the specified file
    def get_next_rr(file)
      while (!file.eof?)
        line = file.gets
        next if (!line || (line.length == 0))
        next if (line.index(';') == 0)
        next if (line.strip.length == 0)
        rr_text = "\n"
        begin
          # Strip off prepended name up to "\v" character before creating RR
          rr_text = line[line.index(Preparser::SORT_SEPARATOR) +
              Preparser::SORT_SEPARATOR.length, line.length]
        rescue Exception => e
          log(LOG_INFO, "File contains unrecognisable line : #{rr_text}, ERROR : #{e} - skipping this line")
          next
        end
        begin
          rr = RR.create(rr_text)
          return rr
          #        rescue DecodeError => e
        rescue Exception => e
          split = rr_text.split
          if (split[3].index("NSEC3"))
            @unknown_nsecs[split[0]] = split[8] # Store the next name
          elsif (split[3].index("NSEC"))
            @unknown_nsecs[split[0]] = split[4] # Store the next name
          end
          # Assume this is a valid, but unsupported, type - we then need simply to ignore it.
          # But we also need to ignore the NSEC/NSEC3 and the RRSIG(s) (including for the hashed owner name)
          # So - if we're loading an NSEC3 record, then make sure we grab the owner name
          # We can then check it in the NSEC3 chain, and not try to validate the RRSIG for that NSEC3.
          #
          #          log(LOG_ERR, "File contains invalid RR : #{rr_text.chomp}, ERROR : #{e}")
          log(LOG_INFO, "File contains invalid RR : #{rr_text.chomp}, ERROR : #{e} - skipping this record")
        end

      end
      return nil
    end

    # Work out which subdomain of the zone we want to load next
    def get_subdomain_to_load(last_rr)
      return "" if (!last_rr)
      subdomain = last_rr.name
      subdomain = lose_n_labels(subdomain, @soa.name.labels.length)
      subdomain = subdomain.labels()[subdomain.labels.length() - 1]
      return subdomain
    end

    # Load in the next subdomain of the zone from the unsigned file
    def load_unsigned_subdomain(file, last_rr)
      subdomain = get_subdomain_to_load(last_rr)
      #      print "Loading unsigned subdomain : #{subdomain}\n"
      domain_rrs = []
      l_rr = last_rr
      while (l_rr && test_subdomain(l_rr, subdomain))
        #        print "Loaded unsigned RR : #{l_rr}\n"
        # Add the last_rr to the domain_rrsets
        domain_rrs.push(l_rr)
        # If this is a DNSKEY record, then remember to add it to the keys!
        if (l_rr.type == Types::DNSKEY)
          @keys.push(l_rr)
          @unsigned_keys.push(l_rr)
          #          print "Using key #{l_rr.key_tag}\n"
          @algs.push(l_rr.algorithm) if !@algs.include?l_rr.algorithm
        end
        l_rr = get_next_rr(file)
      end
      #      print "Finsihed loading unsigned #{subdomain} subdomain - returning #{l_rr}\n"
      return domain_rrs, l_rr

    end

    # Work out what RRSet type this belongs to
    def get_type_from_rr(rr)
      if (rr.type == Types::RRSIG)
        return rr.type_covered
      else
        return rr.type
      end
    end

    # Check the RRSIG for this RRSet
    def check_signature(rrset, is_glue, delegation)
      return if is_glue
      if (delegation && ([Types::AAAA, Types::A].include?rrset.type))
        # glue - don't verify
        return
      end
      return if (out_of_zone(rrset.name))
      rrset_sig_types = []
      rrset.sigs.each {|sig| rrset_sig_types.push(sig.algorithm)}
      @algs.each {|alg|
        if !(rrset_sig_types.include?alg)
          if ((rrset.type == Types::NS) && (rrset.name != @soa.name)) # NS RRSet NOT at zone apex is OK
          else
            s = ""
            rrset_sig_types.each {|t| s = s + " #{t} "}
            log(LOG_ERR, "RRSIGS should include algorithm #{alg} for #{rrset.name}, #{rrset.type}, have :#{s}")
          end
        end
      }
      #  b) RRSIGs validate for at least one key in DNSKEY RRSet  (Note: except for the zone apex, there should be no RRSIG for NS RRsets.)
      #          print "Verifying RRSIG for #{rrset}\n"
      # @TODO@ Create an RRSET with *only* the RRSIG we are interested in - check that they all verify ok?
      # Check if this is an NS RRSet other than the zone apex - if so, then skip the verify test
      if ((rrset.type == Types::NS) && ((rrset.name != @soa.name)))
        # Skip the verify test
      elsif (@unknown_nsecs[rrset.name.to_s+"."])
        log(LOG_INFO,"Skipping verification test for #{rrset.name}, #{rrset.type} : Original type is not supported")
        # Skip the verify test
      else
        begin
          #          print "About to verify #{rrset.name} #{rrset.type}, #{rrset.rrs.length} RRs, #{rrset.sigs.length} RRSIGs, #{@keys.length} keys\n"
          Dnssec.verify_rrset(rrset, @keys)
          #          print "Verified OK!!\n"
        rescue VerifyError => e
          log(LOG_ERR, "RRSet (#{rrset.name}, #{rrset.type}) failed verification : #{e}, tag = #{rrset.sigs()[0] ? rrset.sigs()[0].key_tag : 'none'}")
        end
        # Add the key_tags to the list of tags which have actually been used in this zone
        # This is used for tracking key lifecycles through time (with the KeyTracker)
        rrset.sigs.each {|sig|
          if (!@keys_used.include?sig.key_tag)
            @keys_used.push(sig.key_tag)
          end
        }
      end
      #  c) inception date in past by at least interval specified by config
      rrset.sigs.each {|sig|
        time_now = Time.now.to_i
        if (sig.inception > (time_now + @config.signatures.inception_offset))
          log(LOG_ERR, "Inception error for #{sig.name}, #{sig.type_covered} : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{@config.signatures.inception_offset}, difference = #{time_now - sig.inception}")
        else
          #                      print "OK : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{@config.signatures.inception_offset}, difference = #{time_now - sig.inception}\n"
        end

        #  d) expiration date in future by at least interval specified by config
        refresh = @config.signatures.refresh
        resign = @config.signatures.resign
        # We want to check that there is at least the refresh period left before
        # the signature expires.
        # @TODO@ Probably want to have a WARN level and an ERROR level
        # Expired signatures are caught by the verify_rrset() call above
        if ((time_now <= sig.expiration) && time_now > (sig.expiration - refresh + resign))
          log(LOG_ERR, "Signature expiration (#{sig.expiration}) for #{sig.name}, #{sig.type_covered} should be later than (the refresh period (#{refresh}) - the resign period (#{resign})) from now (#{time_now})")
        else
          #            print "OK : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}\n"
        end

        # Check signature lifetime :
        # inceptionoffset + validity - jitter ≤ (exception - inception) ≤ inceptionoffset + validity +jitter
        validity = @config.signatures.validity.default
        if ([Types::NSEC, Types::NSEC3].include?sig.type_covered)
          validity = @config.signatures.validity.denial
        end

        # Check signature lifetime
        min_lifetime = @config.signatures.inception_offset + validity - @config.signatures.jitter
        max_lifetime = @config.signatures.inception_offset + validity + @config.signatures.jitter
        actual_lifetime = sig.expiration - sig.inception
        if (min_lifetime > actual_lifetime)
          log(LOG_ERR, "Signature lifetime too short - should be at least #{min_lifetime} but was #{actual_lifetime}")
        end
        if (max_lifetime < actual_lifetime)
          log(LOG_ERR, "Signature lifetime too long - should be at most #{max_lifetime} but was #{actual_lifetime}")
        end

      }


    end

    # Get the string for the type of denial this zone is using : either "NSEC" or "NSEC3"
    def nsec_string()
      if (@config.denial.nsec)
        return "NSEC"
      else
        return "NSEC3"
      end
    end

    # Check the TTL of the NSEC(3) record
    def check_nsec_ttl(nsec)
      if (@config.soa && @config.soa.minimum)
        if (nsec.ttl != @config.soa.minimum)
          log(LOG_ERR, "#{nsec.type} record should have TTL of #{@config.soa.minimum} from zone policy //Zone/SOA/Minimum, but is #{nsec}")
        end
      else
        if (nsec.ttl != @soa.minimum)
          log(LOG_ERR, "#{nsec.type} record should have TTL of #{@soa.minimum} from unsigned zone SOA RR minimum, but is #{nsec}")
        end
      end
    end

    # Check the types covered by this NSEC record
    def check_nsec_types(nsec, types)
      nsec.types.each {|type|
        if !(types.include?type)
          log(LOG_ERR, "#{nsec.type} includes #{type} which is not in rrsets for #{nsec.name}")
        end
        types.delete(type)
      }
      if (types.length > 0)
        # Otherwise, log the missing types
        s = ""
        types.each {|t| s = s + " #{t} "}
        log(LOG_ERR, "#{s} types not in #{nsec.type} for #{nsec.name}")
      end
    end

    # Check the next_domain/next_hashed for this NSEC(3)
    # Names are expected rather than Strings
    def check_nsec_next(rr, last_next)
      # Keep last_nsec_next.
      if (!@last_nsec)
        @last_nsec = rr
        return
      end

      compare_val = (last_next <=> rr.name)
      if (compare_val > 0)
        # last was greater than we expected - we missed an NSEC
        # Was the NSEC in the unknown_nsecs list?
        if (n = @unknown_nsecs[last_next.to_s+"."])
          # We missed one because the type was unknown.
          # So - fix up the list. We need to check that the unknown NSEC points to rr.name
          if (rr.type == "NSEC3")
            if (n == (rr.name.labels()[0].to_s))
              @last_nsec = rr
              return
            end
          else
            if (n == (rr.name.to_s + "."))
              @last_nsec = rr
              return
            end
          end
        end
        # print an error
        log(LOG_ERR, "Can't follow #{rr.type} loop from #{@last_nsec.name} to #{last_next}")
      elsif (compare_val < 0)
        # last was less than we expected - we have an extra nsec
        # print an error
        log(LOG_ERR, "NSEC record left after folowing closed loop : #{rr.name}. Was expecting #{last_next}")
      else
        # All OK
      end
      @last_nsec = rr

    end

    # Check this NSEC record
    def check_nsec(l_rr, types_covered)
      # Check the policy is not for NSEC3!
      if !(@config.denial.nsec)
        log(LOG_ERR, "NSEC RRs included in NSEC3-signed zone")
        return
      end
      # We can check the TTL of the NSEC here
      check_nsec_ttl(l_rr)
      # Check RR types
      check_nsec_types(l_rr, types_covered)
      if (@last_nsec)
        check_nsec_next(l_rr, @last_nsec.next_domain)
      else
        check_nsec_next(l_rr, nil)
      end
    end

    # Check this NSEC3PARAM record
    def check_nsec3param(l_rr, subdomain)
      # Check the policy is not for NSEC!
      if (@config.denial.nsec)
        log(LOG_ERR, "NSEC3PARAM RRs included in NSEC-signed zone")
        return
      end
      # Check NSEC3PARAM flags
      if (l_rr.flags != 0)
        log(LOG_ERR, "NSEC3PARAM flags should be 0, but were #{l_rr.flags} for #{@soa.name}")
      end
      # Check that we are at the apex of the zone here
      if (subdomain && (subdomain != ""))
        log(LOG_ERR, "NSEC3PARAM seen at #{subdomain} subdomain : should be at zone apex")
      end
      # Check that we have not seen an NSEC3PARAM before
      if (!@nsec3param)
        #  Store the NSEC3PARAM parameters for use with the rest of the zones' NSEC3 records
        # We know that no NSECs should have been seen by now, as this record is at the zone apex and NSEC(3) RRs appear at the bottom of the RRSets for the domain
        @nsec3param = l_rr
      else
        log(LOG_ERR, "Multiple NSEC3PARAM RRs for #{@soa.name}")
      end
      #      end
      # Check that the NSEC3PARAMs are the same as those defined in the Config
      if (l_rr.salt != @config.denial.nsec3.hash.salt)
        log(LOG_ERR, "NSEC3PARAM has wrong salt : should be #{@config.denial.nsec3.hash.salt} but was #{(l_rr.salt)}")
      end
      if (l_rr.iterations != @config.denial.nsec3.hash.iterations)
        log(LOG_ERR, "NSEC3PARAM has wrong iterations : should be #{@config.denial.nsec3.hash.iterations} but was #{l_rr.iterations}")
      end
      if (l_rr.hash_alg != @config.denial.nsec3.hash.algorithm)
        log(LOG_ERR, "NSEC3PARAM has wrong algorithm : should be #{@config.denial.nsec3.hash.algorithm} but was #{l_rr.hash_alg.string}")
      end
    end

    # Check this NSEC3 record
    def check_nsec3(l_rr)
      # Check the policy is not for NSEC!
      if (@config.denial.nsec)
        log(LOG_ERR, "NSEC3 RRs included in NSEC-signed zone")
        return
      end
      if (!@nsec3param && !@warned_about_nsec3param)
        log(LOG_ERR, "NSEC3 record found for #{l_rr.name}, before NSEC3PARAM record was found - won't report again for this zone")
        @warned_about_nsec3param = true
        @first_nsec3 = l_rr # Store so we have something to work with
      end
      # Check that the parameters are the same as those defined in the config
      if (l_rr.salt != @config.denial.nsec3.hash.salt)
        log(LOG_ERR, "NSEC3 has wrong salt : should be #{@config.denial.nsec3.hash.salt} but was #{l_rr.salt}")
      end
      if (l_rr.iterations != @config.denial.nsec3.hash.iterations)
        log(LOG_ERR, "NSEC3 has wrong iterations : should be #{@config.denial.nsec3.hash.iterations} but was #{l_rr.iterations}")
      end
      if (l_rr.hash_alg != @config.denial.nsec3.hash.algorithm)
        log(LOG_ERR, "NSEC3 has wrong algorithm : should be #{@config.denial.nsec3.hash.algorithm} but was #{l_rr.hash_alg}")
      end
      # Check TTL
      check_nsec_ttl(l_rr)
      #  Check NSEC3 next_hashed chain
      if (@last_nsec)
        check_nsec_next(l_rr, get_next_nsec3_name(@last_nsec))
      else
        check_nsec_next(l_rr, nil)
      end

      # Now record the owner name, the next hashed, and the types associated with it
      # This information will be used by the NSEC3Auditor once the zone file has
      # been processed.
      File.open(@working + "#{File::SEPARATOR}audit.nsec3.#{Process.pid}", "a") { |f|
        types = get_types_string(l_rr.types)
        f.write("#{l_rr.name.to_s} #{types}\n")
      }
      if (!l_rr.opt_out?)
        File.open(@working + "#{File::SEPARATOR}audit.optout.#{Process.pid}", "a") { |f|
          f.write("#{l_rr.name.to_s} #{RR::NSEC3.encode_next_hashed(l_rr.next_hashed) + "." + @soa.name.to_s}\n")
        }
      end
    end

    # Work out the Name that next_hashed points to (adds the zone name)
    # Name returned from String input
    def get_next_nsec3_name(rr)
      return Name.create(Dnsruby::RR::NSEC3.encode_next_hashed(rr.next_hashed) + "." + @zone_name)
    end

    # Check the DNSKEY against all the configured keys
    def Auditor.match_key_config(key, configured_keys)
      # See if we can match our key against any of the configured keys.
      # We're looking for algorithm and alg_length
      begin
        configured_keys.each {|configured_key|
          if (configured_key.algorithm == key.algorithm) &&
              (configured_key.alg_length == key.key_length)
            return true
          end
        }
        return false
      rescue NoMethodError
        return true # Omit this test - this version of Dnsruby does not have the key_length method
      end
    end

    def Auditor.check_key_config(keys, unsigned_keys, key_cache, config, auditor)
      # This method should be called at the end of the run, when all the DNSKEY records
      # in both the signed and unsigned zones have been collated.
      # We don't bother checking keys which were defined in the unsigned zone
      keys.each {|l_rr|\
          found_unsigned = false
        unsigned_keys.each {|uk|
          if ((uk.key_tag == l_rr.key_tag) && (uk.key == l_rr.key) && (uk.name == l_rr.name)) # Ignore the TTL
            found_unsigned = true
            break
          end
        }
        next if found_unsigned
        if (!key_cache.include_key?l_rr)
          # Check algorithm and length
          if (l_rr.sep_key?)
            # Check against all the KSKs defined in the config
            if !Auditor.match_key_config(l_rr, config.keys.ksks)
              # Print error
              auditor.log(LOG_ERR, "New KSK DNSKEY has incorrect algorithm (was #{l_rr.algorithm}) or alg_length (was #{l_rr.key_length})")
            end
          else
            # Check against all the ZSKs defined in the config
            if !Auditor.match_key_config(l_rr, config.keys.zsks)
              # Print error
              auditor.log(LOG_ERR, "New ZSK DNSKEY has incorrect algorithm (was #{l_rr.algorithm}) or alg_length (was #{l_rr.key_length})")
            end
          end
          if (l_rr.flags & ~RR::DNSKEY::SEP_KEY & ~RR::DNSKEY::REVOKED_KEY & ~RR::DNSKEY::ZONE_KEY > 0)
            log(LOG_ERR, "DNSKEY has invalid flags : #{l_rr}")
          end
          # Protocol check done by dnsruby when loading DNSKEY RR
          # Algorithm check done by dnsruby when loading DNSKEY RR
          # Check TTL
          if (config.keys.ttl != l_rr.ttl)
            log(LOG_ERR, "Key #{l_rr.key_tag} has incorrect TTL : #{l_rr.ttl} instead of zone policy #{@config.keys.ttl}")
          end
        end
      }
    end

    # Load the next subdomain of the zone from the signed file
    # This method also audits the subdomain.
    # It is passed the loaded subdomain from the unsigned file, which it checks against.
    def load_signed_subdomain(file, last_rr, unsigned_domain_rrs = nil)
      # Load next subdomain of the zone (specified in the last_rr.name)
      # Keep going until zone subdomain changes.
      # If we are loading the signed zone, then we also check the records against the unsigned, and build up useful data for the auditing code
      return if !last_rr
      subdomain = get_subdomain_to_load(last_rr)
      #      print "Loading signed subdomain : #{subdomain}\n"
      seen_dnskey_sep_set = false
      seen_dnskey_sep_clear = false
      l_rr = last_rr
      old_rr = last_rr
      types_covered = [l_rr.type]
      current_domain = l_rr.name
      seen_nsec_for_domain = false
      current_rrset = RRSet.new
      is_glue = false
      delegation = false
      while (l_rr && test_subdomain(l_rr, subdomain))
        #                print "Loaded signed RR : #{l_rr}\n"

        # Remember to reset types_covered when the domain changes
        if (l_rr.name != current_domain)
          if (@config.denial.nsec3)
            # Build up a list of hashed domains and the types seen there,
            # iff we're using NSEC3
            write_types_to_file(current_domain, types_covered, last_rr.name, is_glue)
          end
          if !(l_rr.name.subdomain_of?current_domain)
            delegation = false
          end
          is_glue = true
          seen_nsec_for_domain = false
          types_covered = []
          types_covered.push(l_rr.type)
          current_domain = l_rr.name
          last_rr = old_rr
        end
        if l_rr.type == Types::NS
          delegation = true
        end

        # Keep track of the RRSet we're currently loading - as soon as all the RRs have been loaded, then check the RRSIG
        # So, keep track of the last RR type (or type_covered, if RRSIG)
        # When that changes, check the signature for the RRSet
        if (current_rrset.add(l_rr, false))
          if (l_rr.type == Types::RRSIG)
            if !(types_covered.include?Types::RRSIG)
              types_covered.push(Types.RRSIG)
            end
          else
            if (!types_covered.include?l_rr.type)
              types_covered.push(l_rr.type)
            end
          end
        else
          # We have a complete RRSet.
          # Now check the signatures!
          check_signature(current_rrset, is_glue, delegation)
          current_rrset = RRSet.new
          current_rrset.add(l_rr, false)
          types_covered.push(l_rr.type)
        end

        if (l_rr.type == Types::DNSKEY) # Check the DNSKEYs
          if (l_rr.sep_key?)
            seen_dnskey_sep_set = true
          else
            seen_dnskey_sep_clear = true
          end
          @keys.push(l_rr)
          @algs.push(l_rr.algorithm) if !@algs.include?l_rr.algorithm

        elsif (l_rr.type == Types::NSEC)
          if (!@first_nsec)
            @first_nsec = l_rr
          end
          seen_nsec_for_domain = true
          check_nsec(l_rr, types_covered)

        elsif (l_rr.type == Types::NSEC3PARAM)
          check_nsec3param(l_rr, subdomain)

        elsif (l_rr.type == Types::NSEC3)
          if (!@first_nsec)
            @first_nsec = l_rr
          end
          check_nsec3(l_rr)

        end
        # Check if the record exists in both zones - if not, print an error
        if (unsigned_domain_rrs  &&  !(unsigned_domain_rrs.delete(l_rr))) # delete the record from the unsigned
          # ADDITIONAL SIGNED RECORD!! Check if we should error on it
          process_additional_signed_rr(l_rr)
          if (l_rr.type == Types::SOA)
            unsigned_domain_rrs.each {|u_rr|
              unsigned_domain_rrs.delete(u_rr) if u_rr.type == Types::SOA
            }
          end
        end
        old_rr = l_rr
        l_rr = get_next_rr(file)
      end
      if (@config.denial.nsec3)
        # Build up a list of hashed domains and the types seen there,
        # iff we're using NSEC3
        write_types_to_file(current_domain, types_covered, last_rr.name, is_glue)
      end
      # Remember to check the signatures of the final RRSet!
      check_signature(current_rrset, is_glue, delegation)
      if (@config.denial.nsec)
        if (!is_glue)
          if (!seen_nsec_for_domain)
            if (@unknown_nsecs[current_rrset.name.to_s+"."])
            else
              log(LOG_ERR, "No #{nsec_string()} record for #{current_domain}")
            end
          end
        else
          if (current_rrset.length == 0)
            if (seen_nsec_for_domain)
              log(LOG_ERR, "#{nsec_string()} record seen for #{current_domain}, which is glue")
            end
          end
        end
      end

      # Check that there are no records left in unsigned - if there are, then print an error
      if (unsigned_domain_rrs && unsigned_domain_rrs.length > 0)
        unsigned_domain_rrs.each { |unsigned_rr|
          # Check if out of zone - if not, then print an error
          process_additional_unsigned_rr(unsigned_rr)
        }
      end
      if (!subdomain || subdomain == "")
        check_dnskeys_at_zone_apex(seen_dnskey_sep_set, seen_dnskey_sep_clear)
      end
      return l_rr
    end

    # This method is called if an NSEC3-sgned zone is being audited.
    # It records the types actually seen at the owner name, and the hashed
    # owner name. At the end of the auditing run, this is checked against
    # the notes of what the NSEC3 RR claimed *should* be at the owner name.
    #
    # It builds a transient file (<zone_file>.types) which has records of the
    # following form:
    #   <hashed_name> <unhashed_name> <[type1] [type2] ...>
    #
    # It is passed the domain, and the types seen at the domain
    def write_types_to_file(domain, types_covered, last_name, is_glue)
      return if (is_glue && ( types_covered.clone.delete_if{|t| t == Types::A || t == Types::AAAA}.empty? ))
      return if (types_covered.include?Types::NSEC3) # Only interested in real domains
      #      return if (out_of_zone(domain)) # Only interested in domains which should be here!
      types_string = get_types_string(types_covered)
      salt = ""
      iterations = 0
      hash_alg = Nsec3HashAlgorithms.SHA_1
      if (@nsec3param)
        salt = @nsec3param.salt
        iterations = @nsec3param.iterations
        hash_alg = @nsec3param.hash_alg
      elsif (@first_nsec3)
        salt = @first_nsec3.salt
        iterations = @first_nsec3.iterations
        hash_alg = @first_nsec3.hash_alg
      end
      # Need to add non-glue empty noneterminals here too!
      empty_nonterminals = []
      # Have we skipped any empty nonterminals?
      #    - check the number of labels compared to the expected number of labels
      #    - if more than one different, then there is at least one empty nonterminal
      name_to_check_against = @soa.name
      if (domain.subdomain_of?(last_name))
        # Check the number of labels since last_name
        name_to_check_against = last_name
      else
        # Check the number of labels since the origin
      end
      last = Name.create(domain)
      while (last.labels.length > name_to_check_against.labels.length + 1)
        # Add the empty nonterminal to the list
        last.labels = last.labels[1,last.labels.length]
        empty_nonterminals.push(last)
      end

      # If so, should it be covered by an NSEC3 record?
      #    - don't add any NSEC3 for empty nonterminals if this is only glue
      if (!is_glue && empty_nonterminals.length > 0)
        # If so, add the appropriate NSEC3 record to the "expected NSEC3s" file
        empty_nonterminals.each {|empty_nonterminal|
          add_domain_to_types_file(empty_nonterminal, iterations, salt, hash_alg, "")
        }
      end
      add_domain_to_types_file(domain, iterations, salt, hash_alg, types_string)
    end

    def add_domain_to_types_file(domain, iterations, salt, hash_alg, types_string)
      hashed_domain = RR::NSEC3.calculate_hash(domain, iterations,
        RR::NSEC3.decode_salt(salt), hash_alg)
      File.open(@working + "#{File::SEPARATOR}audit.types.#{Process.pid}", "a") { |f|
        f.write("#{hashed_domain+"."+@soa.name.to_s} #{domain} #{types_string}\n")
      }
    end

    # Turn the types_covered array into a string to display in the log
    def get_types_string(types_covered)
      types_string = ""
      types_covered.uniq.each {|type|
        types_string += " #{type}"
      }
      return types_string
    end

    # Check if we ar at the zone apex - if we are, then check we have seen DNSKEYs
    # both with SEP set and clear.
    def check_dnskeys_at_zone_apex(seen_dnskey_sep_set, seen_dnskey_sep_clear)
      # We are at the zone apex - we should have seen DNSKEYs here
      if (!seen_dnskey_sep_set)
        log(LOG_ERR, "No DNSKEY RR with SEP bit set in output zone")
      end
      if (!seen_dnskey_sep_clear)
        log(LOG_ERR, "No DNSKEY RR with SEP bit clear in output zone")
      end
    end

    # There is an extra RR in the unsigned file to the signed file.
    # Error if it is in zone, warn if it is out of zone.
    def process_additional_unsigned_rr(unsigned_rr)
      if (unsigned_rr)
        if !out_of_zone(unsigned_rr.name)
          if ([Types::DNSKEY, Types::RRSIG, Types::NSEC, Types::NSEC3, Types::NSEC3PARAM].include?unsigned_rr.type)
            # Ignore DNSSEC data in input zone?
            log(LOG_WARNING, "#{unsigned_rr.type} RR present in unsigned file : #{unsigned_rr}")
          else
            log(LOG_ERR, "Output zone does not contain non-DNSSEC RRSet : #{unsigned_rr.type}, #{unsigned_rr}")
          end
        else
          log(LOG_WARNING, "Output zone does not contain out of zone RRSet : #{unsigned_rr.type}, #{unsigned_rr}")
        end
      end
    end

    # There is an extra RR in the signed file. If it is not a DNSSEC record, then
    # error (unless it is an SOA, in which case we info the serial change
    def process_additional_signed_rr(rr)
      # There was an extra signed record that wasn't in the unsigned - check it out
      if (!(["SOA", "NSEC", "NSEC3", "RRSIG", "DNSKEY", "NSEC3PARAM"].include?rr.type.string))
        log(LOG_ERR, "non-DNSSEC RRSet #{rr.type} included in Output that was not present in Input : #{rr}")
      end
    end

    # Check to see if we are still in the same subdomain of the zone
    # e.g. true for ("a.b.c", "b.c.", "c")
    # but false for ("z.a.b.c", "a.b.c", "c")
    def test_subdomain(rr, subdomain)
      ret = false
      rr_name = rr.name
      rr_name = lose_n_labels(rr_name, @soa.name.labels.length)

      if (subdomain && rr_name)
        ret = (rr_name.labels()[rr_name.labels.length() - 1] == subdomain)
      else
        ret =  (rr.name == @soa.name)
      end
      return ret
    end


    # Get rid of the last label in the Name
    def lose_n_labels(name, n)
      if (name.labels.length <= n)
        return EMPTY_NAME # Name.create(".")
      end
      n = Name.new(name.labels()[0, name.labels.length-n], name.absolute?)
      return n
    end

    # Are n1 and n2 in the same subdomain of the zone SOA?
    def compare_subdomain_of_zone(n1, n2)
      # Are we in the same main subdomain of the zone?
      # @TODO@ SURELY THIS REPLICATES test_subdomain?
      return 0 if (!n1 && !n2)
      return -1 if !n1
      return 1 if !n2

      name1 = n1.name
      name2 = n2.name
      return 0 if ((name1.labels.length <= @soa.name.labels.length) &&
          (name2.labels.length <= @soa.name.labels.length))
      return -1 if name2.labels.length <= @soa.name.labels.length
      return 1 if name1.labels.length <= @soa.name.labels.length
      # Look at the label immediately before the soa name, and see if they are the same.
      # So, we need to strip the soa off, then look at the last label
      name1 = lose_n_labels(name1, @soa.name.labels.length)
      name2= lose_n_labels(name2, @soa.name.labels.length)
      #      print "Now comparing subdomains of #{name1} and #{name2} (#{name1.labels[name1.labels.length-1]}, #{name2.labels[name2.labels.length-1]}\n"
      return ((name1.labels[name1.labels.length-1]) <=> (name2.labels[name2.labels.length-1]))
    end

    # Load the SOAs from the *unparsed* files.
    def load_soas(input_file, output_file)
      # Load the SOA record from both zones, and check they are the same.
      signed_soa = get_soa_from_file(output_file)
      unsigned_soa = get_soa_from_file(input_file)
      @zone_name = unsigned_soa.name.to_s

      # Then return the SOA record (of the signed zone)
      if (signed_soa.name != unsigned_soa.name)
        log(LOG_ERR, "Different SOA name in signed zone! (was #{unsigned_soa.name} in unsigned zone, but is #{signed_soa.name} in signed zone")
      end
      if (signed_soa.serial != unsigned_soa.serial)
        if (@config.soa.serial == Config::SOA::KEEP)
          # The policy configuration for the zone says that the SOA serial
          # should stay the same through the signing process. So, if it's changed,
          # and we're in SOA.KEEP, then log an error
          log(LOG_ERR, "Policy configuration is to keep SOA serial the same, " +
              "but has changed from #{unsigned_soa.serial} to " +
              "#{signed_soa.serial}")
        else
          log(LOG_INFO, "SOA differs : from #{unsigned_soa.serial} to #{signed_soa.serial}")
        end
      end
      # Check if the Policy specifies an SOA TTL
      if (@config.soa.ttl)
        # If it does, then check that it is used
        if (signed_soa.ttl != @config.soa.ttl)
          log(LOG_ERR, "SOA TTL should be #{@config.soa.ttl} as defined in zone policy. Was #{signed_soa.ttl}")
        end
      else
        # Otherwise, check that the unsigned SOA TTL == signed SOA TTL
        if (signed_soa.ttl != unsigned_soa.ttl)
          log(LOG_ERR, "SOA TTL differs : from #{unsigned_soa.ttl} to #{signed_soa.ttl}")
        end
      end


      @soa =  signed_soa
    end

    # Load the SOA from an unparsed file
    def get_soa_from_file(file)
      # SOA should always be first (non-comment) line
      file = (file.to_s+"").untaint
      pp = Dnsruby::ZoneReader.new(@config.name, @config.soa ? @config.soa.minimum : nil,
        @config.soa ? @config.soa.ttl : nil)

      IO.foreach(file) {|line|
        ret = pp.process_line(line)
        if (ret)
          new_line, unused = ret
          rr = RR.create(new_line)
          if (rr.type.to_s != "SOA")
            log(LOG_ERR, "Expected SOA RR as first record in #{file}, but got line : #{new_line.chomp}")
            next
          end
          if (rr.type != Types::SOA)
            log(LOG_ERR, "Expected SOA RR as first record in #{file}, but got RR : #{rr}")
            next
          end

          return rr
        end

      }
      log(LOG_ERR, "Can't load SOA from #{file}")
      raise FatalError.new("Can't load SOA from #{file}")
    end

    # Log the message, and set the return value to the most serious code so far
    def log(pri, msg)
      if (pri.to_i < @ret_val)
        @ret_val = pri.to_i
      end
      return if (@num_output_lines >= 100)
      @num_output_lines += 1
      if (@num_output_lines == 100)
        msg = "Too much output from auditor - suppressing for rest of run"
        print "#{msg}\n"
        @syslog.log(LOG_WARNING, msg)
        return
      end
      print "#{pri}: #{msg}\n"
      begin
        @syslog.log(pri, msg)
      rescue ArgumentError # Make sure we continue no matter what
      end
    end

    # Check if the name is out of the zone
    def out_of_zone(name)
      return !((name.subdomain_of?@soa.name) || (name == @soa.name))
    end



    # The Nsec3Auditor class checks the NSEC3 types_covered and opt-out.
    # It runs through files which were created during the main auditing phase,
    # which include lists of NSEC3 RR types_covered, as well as lists of the
    # actual types found at the unhashed domain name.
    # The files also record those NSEC3 RRs for which opt-out was not set.
    # This class is for private use by the Auditor class
    class Nsec3Auditor
      # Initialise the Nsec3Auditor.
      # The parent is taken for ease of testing.
      # The working directory is passed.
      def initialize(parent, working)
        @parent = parent
        @working = working
      end
      def check_nsec3_types_and_opt_out(unknown_nsecs)
        # First of all we will have to sort the types file.
        system("#{Commands.sort} -t' ' #{@working}#{File::SEPARATOR}audit.types.#{Process.pid} > #{@working}#{File::SEPARATOR}audit.types.sorted.#{Process.pid}")

        # Go through each name in the files and check them
        # We want to check two things :
        # a) types covered
        # b) no hashes in between non-opt-out names

        # This checks the types covered for each domain name
        if (!File.exists?(@working +
                "#{File::SEPARATOR}audit.optout.#{Process.pid}"))
          File.new(@working +
              "#{File::SEPARATOR}audit.optout.#{Process.pid}", "w")
        end
        if (!File.exists?(@working +
                "#{File::SEPARATOR}audit.nsec3.#{Process.pid}"))
          File.new(@working +
              "#{File::SEPARATOR}audit.nsec3.#{Process.pid}", "w")
        end
        File.open(@working + 
            "#{File::SEPARATOR}audit.types.sorted.#{Process.pid}") {|ftypes|
          File.open(@working + 
              "#{File::SEPARATOR}audit.nsec3.#{Process.pid}") {|fnsec3|
            File.open(@working + 
                "#{File::SEPARATOR}audit.optout.#{Process.pid}") {|foptout|
              while (!ftypes.eof? && !fnsec3.eof? && !foptout.eof?)
                types_name, types_name_unhashed, types_types = get_name_and_types(ftypes, true)
                nsec3_name, nsec3_types = get_name_and_types(fnsec3)
                owner, next_hashed = get_next_non_optout(foptout)
                owner, next_hashed = check_optout(types_name_unhashed, owner, next_hashed, types_name, foptout)
                
                while ((nsec3_name < types_name) && (!fnsec3.eof?))
                  log(LOG_WARNING, "Found NSEC3 record for hashed domain which couldn't be found in the zone (#{nsec3_name})")
                  nsec3_name, nsec3_types = get_name_and_types(fnsec3)
                end
                while ((types_name < nsec3_name) && (!ftypes.eof?))
                  if (!unknown_nsecs[types_name_unhashed+"."])
                    if (types_types.length > 0)
                      log(LOG_ERR, "Found RRs for #{types_name_unhashed} (#{types_name}) which was not covered by an NSEC3 record")
                    else
                      log(LOG_ERR, "Can't find NSEC3 for empty nonterminal #{types_name_unhashed} (should be #{types_name})")
                    end
                  end
                  types_name, types_name_unhashed, types_types = get_name_and_types(ftypes, true)

                  # Check the optout names as we load in more types
                  owner, next_hashed = check_optout(types_name_unhashed, owner, next_hashed, types_name, foptout)
                end
                # If there is only an NS record, and we are opt-out, then there should be no NSEC3 record here
                if (@parent.config.denial.nsec3.optout && (nsec3_types.include?Types::NS) && nsec3_types.include?(Types::RRSIG) && (nsec3_types.length == 2))
                  log(LOG_WARNING, "NSEC3 record found for #{types_name_unhashed} (#{nsec3_name}). Only an NS record is present, and opt out is being used, so no NSEC3 is expected")
                end
                # Now check the NSEC3 types_covered against the types ACTUALLY at the name
                if (types_types != nsec3_types)
                  log(LOG_ERR, "ERROR : expected #{@parent.get_types_string(nsec3_types)}" +
                      " at #{types_name_unhashed} (#{nsec3_name}) but found " +
                      "#{@parent.get_types_string(types_types)}")
                end
              end
            }
          }
        }

        # Now delete any intermediary files, if we're using NSEC3
        delete_nsec3_files()
      end

      #  Check the optout names
      def check_optout(types_name_unhashed, owner, next_hashed, types_name, foptout)
        if (types_name > owner)
          if (types_name >= next_hashed)
            # Load next non-optout
            owner, next_hashed = get_next_non_optout(foptout)
          else
            # ERROR!
            log(LOG_ERR, "Found domain (#{types_name_unhashed}) whose hash (#{types_name}) is between owner (#{owner}) and next_hashed (#{next_hashed})for non-optout NSEC3")
          end
        end
        return owner, next_hashed
      end


      def get_next_non_optout(file)
        loptout = file.gets
        owner, next_hashed = loptout.split" "
        return owner, next_hashed
      end

      def get_name_and_types(file, get_unhashed_name = false)
        line = file.gets
        array = line.split" "
        name = array[0]
        types = []
        num = 1
        unhashed_name = nil
        if (get_unhashed_name)
          num = 2
          unhashed_name = array[1]
        end
        (array.length-num).times {|i|
          types.push(array[i+num])
        }
        if (get_unhashed_name)
          return name, unhashed_name, types.uniq.sort
        else
          return name, types.uniq.sort
        end
      end

      # Delete the intermediary files used for NSEC3 checking
      def delete_nsec3_files()
        w = Dir.new(@working)
        w.each {|f|
          if ((f.index("audit")) && (f.index("#{Process.pid}")))
            begin
              File.delete(@working + File::SEPARATOR + f.untaint)
            rescue Exception => e
              print "Can't delete temporary auditor file #{f}, error : #{e}\n"
            end
          end
        }
      end

      def log(pri, msg)
        @parent.log(pri, msg)
      end

    end


  end
end
