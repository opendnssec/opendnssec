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

require 'dnsruby'
include Dnsruby
include Syslog::Constants
module KASPAuditor
  class Auditor
    def initialize(syslog)
      @syslog = syslog
      @ret_val = 999
      @keys = []
      @algs = []
      @last_nsec3_hashed = nil
      @nsec3param = nil
      @count = 0
      @last_nsec = nil
      @first_nsec = nil
      @warned_about_nsec3param = false
      @zone_name = ""
    end
    #This version of the auditor will work on sorted zone files, rather than loading whole zones into memory
    def check_zone(config, unsigned_file, signed_file)
      if (config.inconsistent_nsec3_algorithm?)
        log(LOG_WARNING, "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used")
      end
      # Load SOA record from top of original signed and unsigned files!
      soa_rr= load_soas(unsigned_file, signed_file)
      log(LOG_INFO, "Auditing #{soa_rr.name} zone : #{config.zone.denial.nsec ? 'NSEC' : 'NSEC3'} SIGNED")

      File.open(unsigned_file + ".sorted") {|unsignedfile|
        File.open(signed_file + ".sorted") {|signedfile|

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
            # so we can build up the next subdomains rrsets with it (although watch out for EOF here!).
            unsigned_domain_rrs = []
            compare_return = compare_subdomain_of_zone(soa_rr.name, last_signed_rr, last_unsigned_rr)
            while (compare_return != 0 && (!unsignedfile.eof? || !signedfile.eof?))
              # Work out which file is behind, then continue loading records from that zone until we're at the same subdomain of the zone soa
              if (compare_return > 0) # unsigned < signed
                # Log missing signed subdomain - check if out of zone first
                process_additional_unsigned_rr(last_unsigned_rr, soa_rr)
                # Load next unsigned record
                #                print "Loading another unsigned record to catch up to signed\n"
                last_unsigned_rr = get_next_rr(unsignedfile)
              elsif (compare_return < 0) # unsigned > signed
                #                print "Signed file behind unsigned - loading next subdomain from #{last_signed_rr.name}\n"
                last_signed_rr = load_signed_subdomain(config, signedfile, last_signed_rr, soa_rr, [])
                #                print "Last signed rr now: #{last_signed_rr}\n"
              end
              #              print"Comparing signed #{last_signed_rr} to unsigned #{last_unsigned_rr}\n"
              compare_return = compare_subdomain_of_zone(soa_rr.name, last_signed_rr, last_unsigned_rr)
            end

            # Now we're at the same subdomain of the zone name. Keep loading from both files until the subdomain changes in that file.
            #            print "Now at #{last_signed_rr.name} for signed, and #{last_unsigned_rr.name} for unsigned\n"
            unsigned_domain_rrs, last_unsigned_rr = load_unsigned_subdomain(unsignedfile, last_unsigned_rr, soa_rr)
            last_signed_rr = load_signed_subdomain(config, signedfile, last_signed_rr, soa_rr, unsigned_domain_rrs)

          end
          if (last_unsigned_rr)
            process_additional_unsigned_rr(last_unsigned_rr, soa_rr)
          end
        }
      }
      do_final_nsec_check(config)
      #      return -@ret_val
      log(LOG_INFO, "Finished auditing #{soa_rr.name} zone")
      if (@ret_val == 999)
        return 0
      else
        return @ret_val
      end

    end

    # Make sure that the last NSEC(3) record points back to the first one
    def do_final_nsec_check(config)
      if (config.zone.denial.nsec && (@first_nsec.type == Dnsruby::Types.NSEC))
        # Now check that the last nsec points to the first nsec
        if (@first_nsec && (@last_nsec.next_domain == @first_nsec.name))
        else
          log(LOG_ERR, "Can't follow NSEC loop from #{@last_nsec.name} to #{@last_nsec.next_domain}")
        end
      elsif (config.zone.denial.nsec3 && ((@first_nsec.type == Dnsruby::Types.NSEC3)))
        # Now check that the last nsec3 points to the first nsec3
        if (@first_nsec && (get_next_nsec3_name(@last_nsec).to_s == @first_nsec.name.to_s))
        else
          log(LOG_ERR, "Can't follow NSEC3 loop from #{@last_nsec.name} to #{get_next_nsec3_name(@last_nsec)}. Was actually #{@first_nsec.name}")
        end
      end
    end

    # Load the next RR from the specified file
    def get_next_rr(file)
      while (!file.eof?)
        line = file.gets
        next if (line.index(';') == 0)
        next if (!line || (line.length == 0))
        # Strip off prepended name up to "\v" character before creating RR
        begin
          rr_text = line[line.index(Preparser::SEPARATOR) + 1, line.length]
          rr = RR.create(rr_text)
          #          print "Loaded #{rr}\n"
          return rr
        rescue DecodeError => e
          log(LOG_ERR, "File contains invalid RR : #{rr_text.chomp}, ERROR : #{e}")
        end

      end
      return nil
    end

    # Work out which subdomain of the zone we want to load next
    def get_subdomain_to_load(last_rr, soa_rr)
      return "" if (!last_rr)
      subdomain = last_rr.name
      soa_rr.name.labels.length.times {|n|
        subdomain = lose_last_label(subdomain)
      }
      subdomain = subdomain.labels()[subdomain.labels.length() - 1]
      return subdomain
    end

    # Load in the next subdomain of the zone from the unsigned file
    def load_unsigned_subdomain(file, last_rr, soa_rr)
      subdomain = get_subdomain_to_load(last_rr, soa_rr)
      #      print "Loading unsigned subdomain : #{subdomain}\n"
      domain_rrs = []
      l_rr = last_rr
      while (l_rr && test_subdomain(l_rr, subdomain, soa_rr))
        #        print "Loaded unsigned RR : #{l_rr}\n"
        # Add the last_rr to the domain_rrsets
        domain_rrs.push(l_rr)
        #        if (["NSEC", "NSEC3", "RRSIG", "DNSKEY", "NSEC3PARAM"].include?rr.type.string)
        #          log(LOG_WARNING, "DNSSEC RRSet present in input zone (#{rr.name}, #{rr.type}")
        #        end
        # If this is a DNSKEY record, then remember to add it to the keys!
        if (l_rr.type == Types.DNSKEY)
          @keys.push(l_rr)
          print "Using key #{l_rr.key_tag}\n"
          @algs.push(l_rr.algorithm) if !@algs.include?l_rr.algorithm
        end
        l_rr = get_next_rr(file)
      end
      #      print "Finsihed loading unsigned #{subdomain} subdomain - returning #{l_rr}\n"
      return domain_rrs, l_rr

    end

    # Work out what RRSet type this belongs to
    def get_type_from_rr(rr)
      if (rr.type == Types.RRSIG)
        return rr.type_covered
      else
        return rr.type
      end
    end

    # Check the RRSIG for this RRSet
    def check_signature(rrset, config, soa, is_glue, is_unsigned_delegation)
      return if is_glue
      return if is_unsigned_delegation
      return if (out_of_zone(rrset.name, soa.name))
      rrset_sig_types = []
      rrset.sigs.each {|sig| rrset_sig_types.push(sig.algorithm)}
      @algs.each {|alg|
        if !(rrset_sig_types.include?alg)
          if ((rrset.type == Types.NS) && (rrset.name != soa.name)) # NS RRSet NOT at zone apex is OK
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
      if ((rrset.type == Types.NS) && ((rrset.name != soa.name)))
        # Skip the verify test
        #            next if (ns_rrsets.length > 0 && ds_rrsets.length == 0)
        #            next if (types_covered.include?Types.NS && !(types_covered.include?Types.DS))
        #          elsif (rrset.sigs.length == 0 &&
        ##                (ns_rrsets.length > 0 && ds_rrsets.length == 0))
        #                (types_covered.include?Types.NS && !(types_covered.include?Types.DS)))
        #            next # unsigned delegation
      else
        begin
          #          print "About to verify #{rrset.name} #{rrset.type}, #{rrset.rrs.length} RRs, #{rrset.sigs.length} RRSIGs, #{@keys.length} keys\n"
          Dnssec.verify_rrset(rrset, @keys)
          #          print "Verified OK!!\n"
        rescue VerifyError => e
          log(LOG_ERR, "RRSet (#{rrset.name}, #{rrset.type}) failed verification : #{e}, tag = #{rrset.sigs()[0] ? rrset.sigs()[0].key_tag : 'none'}")
        end
      end
      #  c) inception date in past by at least interval specified by config
      rrset.sigs.each {|sig|
        time_now = KASPTime.get_current_time
        if (sig.inception >= (time_now + config.zone.signatures.inception_offset))
          log(LOG_ERR, "Inception error for #{sig.name}, #{sig.type_covered} : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}")
        else
          #                      print "OK : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}\n"
        end

        #  d) expiration date in future by at least interval specified by config
        validity = config.zone.signatures.validity.default
        if ([Types.NSEC, Types.NSEC3, Types.NSEC3PARAM].include?rrset.type)
          validity = config.zone.signatures.validity.denial
        end
        #  We want to check that at least the validity period remains before the signatures expire
        # @TODO@ Probably want to have a validity WARN level and an ERROR level for validity
        if ((sig.expiration -  time_now).abs <=  validity)
          log(LOG_ERR, "Validity error for #{sig.name}, #{sig.type_covered} : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}")
        else
          #            print "OK : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}\n"
        end
      }
    end

    # Get the string for the type of denial this zone is using : either "NSEC" or "NSEC3"
    def nsec_string(config)
      if (config.zone.denial.nsec)
        return "NSEC"
      else
        return "NSEC3"
      end
    end

    # Check the TTL of the NSEC(3) record
    def check_nsec_ttl(nsec, soa)
      if (nsec.ttl != soa.minimum)
        log(LOG_ERR, "#{nsec.type} record should have SOA of #{soa.minimum}, but is #{nsec}")
      end
    end

    # Check the types covered by this NSEC record
    def check_nsec_types(nsec, types)
      #      print "Checking NSEC types for {"
      #      nsec.types.each {|type| print " " + type.string}
      #      print " } from {"
      #      types.each {|type| print " " + type.string}
      #      print " }\n"
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
    def check_nsec(l_rr, config, soa_rr, types_covered)
      # Check the policy is not for NSEC3!
      if !(config.zone.denial.nsec)
        log(LOG_ERR, "NSEC RRs included in NSEC3-signed zone")
        return
      end
      # We can check the TTL of the NSEC here
      check_nsec_ttl(l_rr, soa_rr)
      # Check RR types
      check_nsec_types(l_rr, types_covered)
      if (@last_nsec)
        check_nsec_next(l_rr, @last_nsec.next_domain)
      else
        check_nsec_next(l_rr, nil)
      end
    end

    # Check this NSEC3PARAM record
    def check_nsec3param(l_rr, config, subdomain, soa_rr)
      # Check the policy is not for NSEC!
      if (config.zone.denial.nsec)
        log(LOG_ERR, "NSEC3PARAM RRs included in NSEC-signed zone")
        return
      end
      # Check NSEC3PARAM flags
      if (l_rr.flags != 0)
        log(LOG_ERR, "NSEC3PARAM flags should be 0, but were #{l_rr.flags} for #{soa_rr.name}")
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
        log(LOG_ERR, "Multiple NSEC3PARAM RRs for #{soa_rr.name}")
      end
      #      end
      # Check that the NSEC3PARAMs are the same as those defined in the Config
      if (l_rr.salt != config.zone.denial.nsec3.hash.salt)
        log(LOG_ERR, "NSEC3PARAM has wrong salt : should be #{config.zone.denial.nsec3.hash.salt} but was #{(l_rr.salt)}")
      end
      if (l_rr.iterations != config.zone.denial.nsec3.hash.iterations)
        log(LOG_ERR, "NSEC3PARAM has wrong iterations : should be #{config.zone.denial.nsec3.hash.iterations} but was #{l_rr.iterations}")
      end
      if (l_rr.hash_alg != config.zone.denial.nsec3.hash.algorithm)
        log(LOG_ERR, "NSEC3PARAM has wrong algorithm : should be #{config.zone.denial.nsec3.hash.algorithm} but was #{l_rr.hash_alg.string}")
      end
    end

    # Check this NSEC3 record
    def check_nsec3(l_rr, config, soa_rr)
      # Check the policy is not for NSEC!
      if (config.zone.denial.nsec)
        log(LOG_ERR, "NSEC3 RRs included in NSEC-signed zone")
      end
      if (!@nsec3param && !@warned_about_nsec3param)
        log(LOG_ERR, "NSEC3 record found for #{l_rr.name}, before NSEC3PARAM record was found - won't report again for this zone")
        @warned_about_nsec3param = true
      end
      if (@nsec3param)
        # Check that the parameters are the same as those defined in the NSEC3PARAM
        if (l_rr.salt != @nsec3param.salt)
          log(LOG_ERR, "NSEC3 has wrong salt : should be #{@nsec3param.salt} but was #{l_rr.salt}")
        end
        if (l_rr.iterations != @nsec3param.iterations)
          log(LOG_ERR, "NSEC3 has wrong iterations : should be #{@nsec3param.iterations} but was #{l_rr.iterations}")
        end
        if (l_rr.hash_alg != @nsec3param.hash_alg)
          log(LOG_ERR, "NSEC3 has wrong algorithm : should be #{@nsec3param.hash_alg} but was #{l_rr.hash_alg}")
        end
      end
      # Check TTL
      check_nsec_ttl(l_rr, soa_rr)
      #  Check NSEC3 next_hashed chain
      if (@last_nsec)
        check_nsec_next(l_rr, get_next_nsec3_name(@last_nsec))
      else
        check_nsec_next(l_rr, nil)
      end

      # @TODO@     If an NSEC3 record does not have the opt-out bit set, there are no domain names in the zone for which
      # the hash lies between the hash of this domain name and the value in the "Next Hashed Owner" name field.


      # @TODO@ Check RR types - IS THIS POSSIBLE? NSEC3 domain may be found before actual domain - not sure how to cope with this
      # @TODO@ When we go through original preparser, can we build up info on NSEC3s?
      # NO - TOO EXPENSIVE IN PRE-PARSER! Can we construct the name->hashed map to a file as we go through the main stage of the auditor?
      #
      # For checking types : 
      # @TODO@ If using NSEC3, then check for empty nonterminals in the input zone
      #            if (nsec.type == Types.NSEC3)
      #              # If the input zone does not contain the pre-hashed nsec3 name, then ignore it
      #              if (!hash_to_domain_map[nsec.name.canonical])
      #                # Ignore
      #                return
      #              end
      #            end
    end

    # Work out the Name that next_hashed points to (adds the zone name)
    # Name returned from String input
    def get_next_nsec3_name(rr)
      return Name.create(Dnsruby::RR::NSEC3.encode_next_hashed(rr.next_hashed) + "." + @zone_name)
    end

    # Check the DNSKEY RR
    def check_dnskey(l_rr, config)
      if (l_rr.flags & ~RR::DNSKEY::SEP_KEY & ~RR::DNSKEY::REVOKED_KEY & ~RR::DNSKEY::ZONE_KEY > 0)
        log(LOG_ERR, "DNSKEY has invalid flags : #{l_rr}")
      end
      # Protocol check done by dnsruby when loading DNSKEY RR
      # Algorithm check done by dnsruby when loading DNSKEY RR
      # Check TTL
      if (config.zone.keys.ttl != l_rr.ttl)
        log(LOG_ERR, "Key #{l_rr.key_tag} has incorrect TTL : #{l_rr.ttl} instead of zone policy #{config.zone.keys.ttl}")
      end
    end

    # Load the next subdomain of the zone from the signed file
    # This method also audits the subdomain.
    # It is passed the loaded subdomain from the unsigned file, which it checks against.
    def load_signed_subdomain(config, file, last_rr, soa_rr, unsigned_domain_rrs = nil)
      # Load next subdomain of the zone (specified in the last_rr.name)
      # Keep going until zone subdomain changes.
      # If we are loading the signed zone, then we also check the records against the unsigned, and build up useful data for the auditing code
      return if !last_rr
      subdomain = get_subdomain_to_load(last_rr, soa_rr)
      #      print "Loading signed subdomain : #{subdomain}\n"
      seen_dnskey_sep_set = false
      seen_dnskey_sep_clear = false
      l_rr = last_rr
      types_covered = [l_rr.type]
      current_domain = l_rr.name
      seen_nsec_for_domain = false
      current_rrset = RRSet.new
      is_glue = false
      is_unsigned_delegation = false
      while (l_rr && test_subdomain(l_rr, subdomain, soa_rr))
        #                print "Loaded signed RR : #{l_rr}\n"

        # Remember to reset types_covered when the domain changes
        if (l_rr.name != current_domain)
          is_glue = true
          seen_nsec_for_domain = false
          types_covered = []
          types_covered.push(l_rr.type)
          current_domain = l_rr.name
        end

        # Keep track of the RRSet we're currently loading - as soon as all the RRs have been loaded, then check the RRSIG
        # So, keep track of the last RR type (or type_covered, if RRSIG)
        # When that changes, check the signature for the RRSet
        if (current_rrset.add(l_rr, false))
          if (l_rr.type == Types::RRSIG)
            if !(types_covered.include?Types::RRSIG)
              types_covered.push(Types::RRSIG)
            end
          else
            if (!types_covered.include?l_rr.type)
              types_covered.push(l_rr.type)
            end
          end
        else
          # We have a complete RRSet.
          # Now check the signatures!
          check_signature(current_rrset, config, soa_rr, is_glue, is_unsigned_delegation)
          current_rrset = RRSet.new
          current_rrset.add(l_rr, false)
          types_covered.push(l_rr.type)
        end

        if (l_rr.type == Types::DNSKEY) # Check the DNSKEYs
          check_dnskey(l_rr, config)
          if (l_rr.sep_key?)
            seen_dnskey_sep_set = true
          else
            seen_dnskey_sep_clear = true
          end
          @keys.push(l_rr)
          print "Using key #{l_rr.key_tag}\n"
          @algs.push(l_rr.algorithm) if !@algs.include?l_rr.algorithm

        elsif (l_rr.type == Types::NSEC)
          if (!@first_nsec)
            @first_nsec = l_rr
          end
          seen_nsec_for_domain = true
          check_nsec(l_rr, config, soa_rr, types_covered)

        elsif (l_rr.type == Types::NSEC3PARAM)
          check_nsec3param(l_rr, config, subdomain, soa_rr)

        elsif (l_rr.type == Types::NSEC3)
          if (!@first_nsec)
            @first_nsec = l_rr
          end
          check_nsec3(l_rr, config, soa_rr)

        end
        # Check if the record exists in both zones - if not, print an error
        if (unsigned_domain_rrs  && !unsigned_domain_rrs.delete(l_rr)) # delete the record from the unsigned
          # ADDITIONAL SIGNED RECORD!! Check if we should error on it
          process_additional_signed_rr(l_rr, soa_rr)
        end
        l_rr = get_next_rr(file)
      end
      # Remember to check the signatures of the final RRSet!
      check_signature(current_rrset, config, soa_rr, is_glue, is_unsigned_delegation)
      if (config.zone.denial.nsec)
        if (!is_glue)
          if (!seen_nsec_for_domain)
            log(LOG_ERR, "No #{nsec_string(config)} record for #{current_domain}")
          end
        else
          if (current_rrset.length == 0)
            if (seen_nsec_for_domain)
              log(LOG_ERR, "#{nsec_string(config)} record seen for #{current_domain}, which is glue")
            end
          end
        end
      end

      # Check that there are no records left in unsigned - if there are, then print an error
      if (unsigned_domain_rrs && unsigned_domain_rrs.length > 0)
        unsigned_domain_rrs.each { |unsigned_rr|
          # Check if out of zone - if not, then print an error
          process_additional_unsigned_rr(unsigned_rr, soa_rr)
        }
      end
      print_if_count(10000, subdomain, l_rr)
      if (!subdomain || subdomain == "")
        check_dnskeys_at_zone_apex(seen_dnskey_sep_set, seen_dnskey_sep_clear)
      end
      return l_rr
    end

    # Print where we are every max records
    def print_if_count(max, subdomain, l_rr)
      if (@count == max)
        print "Finished loading signed #{subdomain} subdomain - returning #{l_rr}\n"
        @count = 0
      else
        @count = @count + 1
      end
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
    def process_additional_unsigned_rr(unsigned_rr, soa_rr)
      if !out_of_zone(unsigned_rr.name, soa_rr.name)
        if ([Types::RRSIG, Types::RRSIG, Types::NSEC, Types::NSEC3, Types::NSEC3PARAM].include?unsigned_rr.type)
          # Ignore DNSSEC data in input zone?
          log(LOG_WARNING, "#{unsigned_rr.type} RR present in unsigned file : #{unsigned_rr}")
        else
        log(LOG_ERR, "Output zone does not contain non-DNSSEC RRSet : #{unsigned_rr.type}, #{unsigned_rr}")
        end
      else
        log(LOG_WARNING, "Output zone does not contain out of zone RRSet : #{unsigned_rr.type}, #{unsigned_rr}")
      end
    end

    # There is an extra RR in the signed file. If it is not a DNSSEC record, then
    # error (unless it is an SOA, in which case we info the serial change
    def process_additional_signed_rr(rr, soa)
      # There was an extra signed record that wasn't in the unsigned - check it out
      if (rr.type == Types::SOA)
        if (rr.name == soa.name)
          log(LOG_INFO, "SOA differs : from #{soa.serial} to #{rr.serial}")
        else
          log(LOG_ERROR,"Different SOA name in output zone!")
        end
      elsif (!(["NSEC", "NSEC3", "RRSIG", "DNSKEY", "NSEC3PARAM"].include?rr.type.string))
        log(LOG_ERR, "non-DNSSEC RRSet #{rr.type} included in Output that was not present in Input : #{rr}")
      end
    end

    # Check to see if we are still in the same subdomain of the zone
    # e.g. true for ("a.b.c", "b.c.", "c")
    # but false for ("z.a.b.c", "a.b.c", "c")
    def test_subdomain(rr, subdomain, soa_rr)
      ret = false
      rr_name = rr.name
      soa_rr.name.labels.length.times {|n|
        rr_name = lose_last_label(rr_name)
      }

      if (subdomain && rr_name)
        ret = (rr_name.labels()[rr_name.labels.length() - 1] == subdomain)
      else
        ret =  (rr.name == soa_rr.name)
      end
      return ret
    end


    # Get rid of the last label in the Name
    def lose_last_label(name)
      n = Name.new(name.labels()[0, name.labels.length-1], name.absolute?)
      return n
    end

    # Are we in the same main subdomain of the zone?
    # @TODO@ SURELY THIS REPLICATES test_subdomain?
    def compare_subdomain_of_zone(soa, n1, n2)
      return 0 if (!n1 && !n2)
      return -1 if !n1
      return 1 if !n2

      name1 = n1.name
      name2 = n2.name
      # Look at the label immediately before the soa name, and see if they are the same.
      # So, we need to strip the soa off, then look at the last label
      soa.labels.length.times {|n|
        name1 = name1 = lose_last_label(name1)
        name2 = name2= lose_last_label(name2)
      }
      return 0 if ((name1.labels.length == 0) && (name2.labels.length == 0))
      #      print "Now comparing subdomains of #{name1} and #{name2} (#{name1.labels[name1.labels.length-1]}, #{name2.labels[name2.labels.length-1]}\n"
      return -1 if name2.labels.length == 0
      return 1 if name1.labels.length == 0
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
        log(LOG_INFO, "SOA differs : from #{unsigned_soa.serial} to #{signed_soa.serial}")
      end
      if (signed_soa.ttl != unsigned_soa.ttl)
        log(LOG_ERR, "SOA TTL differs : from #{unsigned_soa.ttl} to #{signed_soa.ttl}")
      end
      return unsigned_soa
    end

    # Load the SOA from an unparsed file
    def get_soa_from_file(file)
      # SOA should always be first (non-comment) line
      IO.foreach(file) {|line|
        next if (line.index(';') == 0)
        next if (!line || (line.length == 0))
        soa = RR.create(line)
        if (soa.type != Types::SOA)
          log(LOG_ERR, "Expected SOA RR as first record in #{file}, but got #{soa}")
          next
        end
        return soa
      }
    end

    # Log the message, and set the return value to the most serious code so far
    def log(pri, msg)
      print "#{pri}: #{msg}\n"
      if (pri.to_i < @ret_val)
        @ret_val = pri.to_i
      end
      begin
      @syslog.log(pri, msg)
      rescue ArgumentError # Make sure we continue no matter what
      end
    end

    # Check if the name is out of the zone
    def out_of_zone(name, soa_name)
      return !((name.subdomain_of?soa_name) || (name == soa_name))
    end
    


    #    def check_signatures(config, domain_rrsets, soa, nss, keys)
    #      # Need to get DNSKEY RRSet for zone.
    #      # Then, check each signed domain against it
    #      # Want to check each signed domain :
    #      algs = []
    #      if (keys.length > 0)
    #        #        keys.rrs.each {|key|
    #        keys.each {|key|
    #          #          print "Using key #{key.key_tag}\n"
    #          algs.push(key.algorithm) if !algs.include?key.algorithm
    #        }
    #      end
    #
    #
    #      domain_rrsets.each {|domain, rrsets|
    #        #        print "Checking domain #{domain}\n"
    #        # @TODO@ If rr arrays are in order, then we can just go through each of those for each domain name
    #        #          rrsets.each {|rrsets|
    #        # Skip if this is glue
    #        next if (is_glue(domain, soa, nss))
    #        #        print "Checked glue\n"
    #        # Also skip the verify test if this is an unsigned delegation
    #        # (NS records but no DS records)
    #        ns_rrsets = rrsets.select{|rrset| rrset.type == Types.NS}
    #        ds_rrsets = rrsets.select{|rrset| rrset.type == Types.DS}
    #        print "#{ns_rrsets.length} NS, #{ds_rrsets.length} DS for #{domain}\n"
    #
    #        #        print "starting going through sigs\n"
    #
    #        next if out_of_zone(domain, soa.name)
    #        rrsets.each {|rrset|
    #          #        print "Checking sigs for #{domain}, #{rrset.type}\n"
    #          #  a) RRSIG for each algorith  for which there is a DNSKEY
    #          rrset_sig_types = []
    #          rrset.sigs.each {|sig| rrset_sig_types.push(sig.algorithm)}
    #          algs.each {|alg|
    #            if !(rrset_sig_types.include?alg)
    #              if ((rrset.type == Types.NS) && (rrset.name != soa.name)) # NS RRSet NOT at zone apex is OK
    #              else
    #                s = ""
    #                rrset_sig_types.each {|t| s = s + " #{t} "}
    #                log(LOG_ERR, "RRSIGS should include algorithm #{alg} for #{rrset.name}, #{rrset.type}, have :#{s}")
    #              end
    #            end
    #          }
    #          #  b) RRSIGs validate for at least one key in DNSKEY RRSet  (Note: except for the zone apex, there should be no RRSIG for NS RRsets.)
    #          #          print "Verifying RRSIG for #{rrset}\n"
    #          # @TODO@ Create an RRSET with *only* the RRSIG we are interested in - check that they all verify ok?
    #          # Check if this is an NS RRSet other than the zone apex - if so, then skip the verify test
    #          if ((rrset.type == Types.NS) && ((rrset.name != soa.name)))
    #            # Skip the verify test
    #            next if (ns_rrsets.length > 0 && ds_rrsets.length == 0)
    #          elsif (rrset.sigs.length == 0 && (ns_rrsets.length > 0 && ds_rrsets.length == 0))
    #            next # unsigned delegation
    #          else
    #            begin
    #              #              print "About to verify #{rrset.name} #{rrset.type}, #{rrset.rrs.length} RRs, #{rrset.sigs.length} RRSIGs, #{keys.length} keys\n"
    #              Dnssec.verify_rrset(rrset, keys)
    #              #              print "Verified OK!!\n"
    #            rescue VerifyError => e
    #              log(LOG_ERR, "RRSet (#{rrset.name}, #{rrset.type}) failed verification : #{e}, tag = #{rrset.sigs()[0] ? rrset.sigs()[0].key_tag : 'none'}")
    #            end
    #          end
    #          rrset.sigs.each {|sig|
    #            #  c) inception date in past by at least interval specified by config
    #            time_now = KASPTime.get_current_time
    #            if (sig.inception >= (time_now + config.zone.signatures.inception_offset))
    #              log(LOG_ERR, "Inception error for #{sig.name}, #{sig.type_covered} : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}")
    #            else
    #              #            print "OK : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}\n"
    #            end
    #
    #            #  d) expiration date in future by at least interval specified by config
    #            validity = config.zone.signatures.validity.default
    #            if ([Types.NSEC, Types.NSEC3, Types.NSEC3PARAM].include?rrset.type)
    #              validity = config.zone.signatures.validity.denial
    #            end
    #            #  We want to check that at least the validity period remains before the signatures expire
    #            # @TODO@ Probably want to have a validity WARN level and an ERROR level for validity
    #            if ((sig.expiration -  time_now).abs <=  validity)
    #              log(LOG_ERR, "Validity error for #{sig.name}, #{sig.type_covered} : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}")
    #            else
    #              #            print "OK : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}\n"
    #            end
    #          }
    #        }
    #      }
    #      #      print "\nFINISHE D CHECKING RRSIG\n\n"
    #    end

    #
    #    def check_nsec_ttl_and_types(nsec, soa, domain_rrsets, hash_to_domain_map = nil)
    #      if (nsec.ttl != soa.minimum)
    #        log(LOG_ERR, "#{nsec.type} record should have SOA of #{soa.minimum}, but is #{nsec}")
    #      end
    #      # Check the types field of the NSEC RRs to make sure that they cover the right types!
    #      # Problem with NSEC3 here - they have HASHED owner name. So we need to match the nsec3.name up with the HASHED owner name.
    #      # So we need a map of domain name <-> Hashed owner name
    #      rrset_array=[]
    #      if ([Types.NSEC3, Types.NSEC3PARAM].include?nsec.type )
    #        rrset_array = domain_rrsets[hash_to_domain_map[nsec.name.canonical]]
    #        if (!rrset_array)
    #          rrset_array = domain_rrsets[nsec.name]
    #        end
    #      else
    #        rrset_array = domain_rrsets[nsec.name]
    #      end
    #      if (!rrset_array)
    #        log(LOG_ERR, "Failed looking up RR types for #{nsec.type} for #{nsec.name}")
    #        return
    #      end
    #      types = []
    #      seen_rrsig = false
    #      rrset_array.each {|rrset|
    #        types.push(rrset.type)
    #        if (!seen_rrsig && (rrset.sigs.length > 0))
    #          seen_rrsig = true
    #          types.push(Types.RRSIG)
    #        end
    #      }
    #      nsec.types.each {|type|
    #        if !(types.include?type)
    #          log(LOG_ERR, "#{nsec.type} includes #{type} which is not in rrsets for #{nsec.name}")
    ##          print "Unhashed = "
    #          hash_to_domain_map.each_pair{ |key, value|
    ##            print "#{key} : #{value}\n"
    #          }
    #        end
    #        types.delete(type)
    #      }
    #      if (types.length > 0)
    #        # If using NSEC3, then check for empty nonterminals in the input zone
    #        if (nsec.type == Types.NSEC3)
    #          # If the input zone does not contain the pre-hashed nsec3 name, then ignore it
    #          if (!hash_to_domain_map[nsec.name.canonical])
    #            # Ignore
    #            return
    #          end
    #        end
    #        # Otherwise, log the missing types
    #        s = ""
    #        types.each {|t| s = s + " #{t} "}
    #        log(LOG_ERR, "#{s} types not in #{nsec.type} for #{nsec.name}")
    #      end
    #    end
    #
    #    def check_nsec3(config, nsecs, nsec3s, nsec3params, nsec3names, domains, soa, domain_rrsets, nss)
    #      if (nsecs.length > 0)
    #        log(LOG_ERR, "NSEC RRs included in NSEC3-signed zone")
    #      end
    #      nsec3param = nil
    #
    #      if (nsec3s.length == 0)
    #        log(LOG_ERR, "No NSEC3 records in zone #{soa.name}")
    #        return
    #      end
    #
    #      # Create a list of the hashed owner names in the zone
    #      nsec3 = nsec3s[0]
    #      hash_to_domain_map = {}
    #      hashed_domains = []
    #      (domains - nsec3names).each {|domain|
    #        hashed_domain = (RR::NSEC3.calculate_hash(domain, nsec3.iterations, RR::NSEC3.decode_salt(nsec3.salt), nsec3.hash_alg))
    #        hashed_domains.push(hashed_domain)
    #        hashed_domain = Name.create(hashed_domain.to_s + "." + soa.name.to_s)
    #        hash_to_domain_map[hashed_domain.canonical] = domain
    #        #      print "Added #{hashed_domain} for #{domain}\n"
    #      }
    #      #    hashed_domains = hash_to_domain_map.values
    #      hashed_domains.sort!
    #
    #      if (nsec3params.length > 0)
    #        # Check NSEC3PARAM - if present, must be only one, and present at apex
    #        #                  - flags should be zero
    #        #                  - All NSEC3 records in zone have same alg and salt params as nsec3param
    #        if (nsec3params.length > 1)
    #          log(LOG_ERR, "#{nsec3params.length} NSEC3PARAM RRs for #{soa.name}")
    #        end
    #        nsec3param = nsec3params[0]
    #        if (nsec3param.flags != 0)
    #          log(LOG_ERR, "NSEC3PARAM flags should be 0, but were #{nsec3param.flags} for #{soa.name}")
    #        end
    #      end
    #
    #      nsec3s.each {|nsec3|
    #        if (nsec3param)
    #          if (nsec3.hash_alg != nsec3param.hash_alg)
    #            log(LOG_ERR, "#{nsec3.name} NSEC3 has algorithm #{nsec3.hash_alg}, but NSEC3PARAM has #{nsec3param.hash_alg}")
    #          end
    #          if (nsec3.salt != nsec3param.salt)
    #            log(LOG_ERR, "#{nsec3.name} NSEC3 has salt #{nsec3.salt}, but NSEC3PARAM has #{nsec3param.salt}")
    #          end
    #        end
    #        # NSEC3 RR has correct bits set to identify RR types in RRSet
    #        check_nsec_ttl_and_types(nsec3, soa, domain_rrsets, hash_to_domain_map)
    #
    #        # Take next hashed owner name out of list
    #        next_hashed = Name.create(RR::NSEC3.encode_next_hashed(nsec3.next_hashed) + "." + soa.name.to_s + ".")
    #        nsec3names.delete(next_hashed)
    #
    #        if !(nsec3.opt_out?)
    #          # If an NSEC3 record does not have the opt-out bit set, there are no domain names in the zone for which
    #          # the hash lies between the hash of this domain name and the value in the "Next Hashed Owner" name field.
    #          # @TODO@ What about glue records and unsigned delegations?
    #          # Glue records are not signed.
    #          # Delegation to an unsigned sub-domain MAY not be signed if the opt-out bit is set.
    #
    #          # so - check hashed_domains for anything in between nsec3.name and nsec3.next_hashed
    #          found_domains = hashed_domains.select {|hash| ((nsec3.name.to_s < hash) && (hash < RR::NSEC3.encode_next_hashed(nsec3.next_hashed)))}
    #          found_domains.each {|domain|
    #            # Check that domain is :
    #            # a) Not a glue record, and
    #            # b) @TODO@ Not an unsigned delegation (NS but no DS), and
    #            # c) Not out of zone
    #            # Need to find unhashed domain...
    #            unhashed_domain = hash_to_domain_map[Name.create(domain.to_s + "." + soa.name.to_s).canonical]
    #
    #            if ((is_glue(unhashed_domain, soa, nss) ||
    #                    (out_of_zone(unhashed_domain, soa.name))))
    #              found_domains.delete(domain)
    #            end
    #          }
    #          if (found_domains.length > 0)
    #            log(LOG_ERR, "#{found_domains.length} domains between #{nsec3.name} and #{RR::NSEC3.encode_next_hashed(nsec3.next_hashed)}, with opt out not set")
    #          end
    #
    #        end
    #      }
    #      # NSEC3 next_hashed should form closed loop of all NSEC3s (but not all domains)
    #      # We have already removed all the next_hashed names from the list of nsec3names - so there should
    #      # be no nsec3names left in the list
    #      if (nsec3names.length > 0)
    #        log(LOG_ERR, "#{nsec3names.length} NSEC3 names outside of closed loop of hashed owner names")
    #      end
    #      #      print "\nFINISHED CHECKING NSEC3\n\n"
    #    end
    #
  end
end
