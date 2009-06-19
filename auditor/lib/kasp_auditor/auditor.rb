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
    end
    def check_zone(config, input_file, output_file)
      input, soa = load_zone(input_file)
      rrs, keys, sigs, nsecs, nsecnames, nsec3s, nsec3params, nsec3names,
        domains, signed_domains, domain_rrsets, nss = load_zone(output_file, true)

      # Check the zone!
      check_non_dnssec_data(input, rrs, soa)
      check_dnskeys(config, keys)
      check_signatures(config, sigs, signed_domains, domain_rrsets, soa, nss)
      if (config.zone.denial.nsec)
        check_nsec(nsecs, nsecnames, nsec3s, nsec3params, domains, soa, domain_rrsets, nss)
      else
        check_nsec3(config, nsecs, nsec3s, nsec3params, nsec3names, domains, soa, domain_rrsets, nss)
      end

      # @TODO@ Implement checking of only part of the zone
      # How does that work? Load only part of the zone file? Which bit?
    end

    def log(pri, msg)
      print "#{pri}: #{msg}\n"
      @syslog.log(pri, msg)
    end

    def check_non_dnssec_data(inp, outp, soa)
      # All non-DNSSEC data in input zone must be identical to output zone
      # So, go through input zone, removing each
      # RR from both input and output. Then, check through output zone, and
      # ensure that only DNSSEC records remain.
      # This method destroys the input arrays
      # and returns the soa for the zone
      inp.each {|rr|
        if (["NSEC", "NSEC3", "RRSIG", "DNSKEY", "NSEC3PARAM"].include?rr.type.string)
          log(LOG_WARNING, "DNSSEC RRSet present in input zone (#{rr.name}, #{rr.type}")
        end
        if (rr.type == Types.SOA)
          #          print "SOA : ignoring"
        elsif (!outp.include?rr)
          if !out_of_zone(rr.name, soa.name)
            log(LOG_ERR, "Output zone does not contain non-DNSSEC RRSet : #{rr.type}, #{rr}")
          else
            log(LOG_WARNING, "Output zone does not contain out of zone non-DNSSEC RRSet : #{rr.type}, #{rr}")
          end
        end
        outp.delete(rr)
      }
      outp.each {|rr|
        if (rr.type == Types.SOA)
          if (rr.name == soa.name)
            log(LOG_INFO, "SOA differs : from #{soa.serial} to #{rr.serial}")
          else
            log(LOG_ERROR,"Different SOA name in output zone!")
          end
        elsif (!["NSEC", "NSEC3", "RRSIG", "DNSKEY", "NSEC3PARAM"].include?rr.type.string)
          log(LOG_ERR, "non-DNSSEC RRSet #{rr.type} included in Output that was not present in Input : #{rr}")
        end
      }
      print "\nFINISHED CHECKING non_DNSSEC DATA\n\n"
    end

    def out_of_zone(name, soa_name)
      return !(name.subdomain_of?soa_name || name == soa_name)
    end

    def check_dnskeys(config, keys)
      # check each DNSKEY record in the zone

      seen_key_with_sep_set = false
      seen_key_with_sep_clear = false
      #    keys.each {|key_rrset|
      keys.each {|key|
        #        print "Checking key : #{key}"
        if (key.flags & ~RR::DNSKEY::SEP_KEY & ~RR::DNSKEY::REVOKED_KEY & ~RR::DNSKEY::ZONE_KEY > 0)
          log(LOG_ERR, "DNSKEY has invalid flags : #{key}")
        end
        if key.sep_key?
          seen_key_with_sep_set = true
        else
          seen_key_with_sep_clear = true
        end
        # Protocol check done by dnsruby when loading DNSKEY RR
        # Algorithm check done by dnsruby when loading DNSKEY RR

        # Check TTL
        if (config.zone.keys.ttl != key.ttl)
          log(LOG_ERR, "Key #{key.key_tag} has incorrect TTL : #{key.ttl} instead of zone policy #{config.zone.keys.ttl}")
        end
      }
      if (!seen_key_with_sep_set)
        log(LOG_ERR, "No DNSKEY RR with SEP bit set in output zone")
      end
      if (!seen_key_with_sep_clear)
        log(LOG_ERR, "No DNSKEY RR with SEP bit clear in output zone")
      end
      print "\nFINISHED CHECKING DNSKEYs\n\n"
    end

    def check_signatures(config, sigs, signed_domains, domain_rrsets, soa, nss)
      # Need to get DNSKEY RRSet for zone.
      # Then, check each signed domain against it
      # Want to check each signed domain :
      algs = []
      key_rrset = domain_rrsets[soa.name].select{|rrset| rrset.type == Types.DNSKEY} [0]
      if (!key_rrset || key_rrset.rrs.length == 0)
        log(LOG_ERR, "No DNSKEYs found in zone!")
        return
      end
      key_rrset.rrs.each {|key|
        print "Using key #{key.key_tag}\n"
        algs.push(key.algorithm) if !algs.include?key.algorithm
      }
      domain_rrsets.each {|domain, rrsets|
        # Skip if this is glue
        next if (is_glue(domain, soa, nss))
        # Also skip the verify test if this is an unsigned delegation
        # (NS records but no DS records)
        ns_rrsets = rrsets.select{|rrset| rrset.type == Types.NS}
        ds_rrsets = rrsets.select{|rrset| rrset.type == Types.DS}
        next if (ns_rrsets.length > 0 && ds_rrsets.length == 0)

        next if out_of_zone(domain, soa.name)
        rrsets.each {|rrset|
          #        print "Checking sigs for #{domain}, #{rrset.type}\n"
          #  a) RRSIG for each algorith  for which there is a DNSKEY
          rrset_sig_types = []
          rrset.sigs.each {|sig| rrset_sig_types.push(sig.algorithm)}
          algs.each {|alg|
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
          else
            begin
              #              print "About to verify #{rrset.name} #{rrset.type}, #{rrset.rrs.length} RRs, #{rrset.sigs.length} RRSIGs, #{key_rrset.rrs.length} keys\n"
              Dnssec.verify_rrset(rrset, key_rrset)
              #              print "Verified OK!!/n"
            rescue VerifyError => e
              log(LOG_ERR, "RRSet (#{rrset.name}, #{rrset.type}) failed verification : #{e}, tag = #{rrset.sigs()[0] ? rrset.sigs()[0].key_tag : 'none'}")
            end
          end
          rrset.sigs.each {|sig|
            #  c) inception date in past by at least interval specified by config
            time_now = KASPTime.get_current_time
            if (sig.inception >= (time_now + config.zone.signatures.inception_offset))
              log(LOG_ERR, "Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}")
            else
              #            print "OK : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{config.zone.signatures.inception_offset}, difference = #{time_now - sig.inception}\n"
            end

            #  d) expiration date in future by at least interval specified by config
            validity = config.zone.signatures.validity.default
            if ([Types.NSEC, Types.NSEC3, Types.NSEC3PARAM].include?rrset.type)
              validity = config.zone.signatures.validity.denial
            end
            #  We want to check that at least the validity period remains before the signatures expire
            # @TODO@ Probably want to have a validity WARN level and an ERROR level for validity
            if ((sig.expiration -  time_now).abs <=  validity)
              log(LOG_ERR, "Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}")
            else
              #            print "OK : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}\n"
            end
          }
        }
      }
      print "\nFINISHED CHECKING RRSIG\n\n"
    end

    def is_glue(domain, soa, nss)
      # Work out if this is a glue record
      # Glue records :
      # 3) in-bailiwick: NSDNAME is a subdomain of APEX, and, NSDNAME is equal to or a subdomain of NSOWNER.
      # 4) sibling: NSDNAME is a subdomain of APEX, and, NSDNAME is equal to or a subdomain of some other NSOWNER.
      #
      #      rrset_array = domain_rrsets[domain]
      ns_array = nss.select{|ns| ns.nsdname == domain}
      return false if (!ns_array || ns_array.length == 0)
      is_glue = false
      ns_array.each {|ns_rr|
        if (ns_rr.nsdname.subdomain_of?soa.name)
          if (ns_rr.nsdname.subdomain_of?ns_rr.name || ns_rr.nsdname == ns_rr.name)
            is_glue = true
            break
          else
            # Check all other NSOWNER names...
            nss.each {|other_ns|
              if (ns_rr.nsdname.subdomain_of?other_ns.name || ns_rr.nsdname == other_ns.name)
                is_glue = true
                break
              end
            }
          end
        end
        break if is_glue
      }
      return is_glue
    end

    def check_nsec(nsecs, nsecnames, nsec3s, nsec3params, domains, soa, domain_rrsets, nss)
      if (nsec3s.length > 0)
        log(LOG_ERR, "NSEC3 RRs included in NSEC-signed zone")
      end
      if (nsec3params.length > 0)
        log(LOG_ERR, "NSEC3PARAM RRs included in NSEC-signed zone")
      end
      # Check each domain has a corresponding NSEC record
      # Watch out for glue!
      domains.each {|domain|
        if !(nsecnames.include?domain)
          if (!is_glue(domain, soa, nss))
            log(LOG_ERR, "No NSEC record for #{domain}")
          end
        else
          #        print "Found NSEC for #{domain}\n"
        end
      }

      # Follow NSEC loop, checking each TTL, and following Next Domain field.
      nsec = nsecs.delete_at(0)
      check_nsec_ttl_and_types(nsec, soa, domain_rrsets)
      start_name = nsec.name
      while ((nsec.next_domain != start_name) && (nsecs.length > 0))
        # Find the nsec whose name is next_domain
        #      print "Following NSEC loop from #{nsec.name} to #{nsec.next_domain}\n"
        candidates = nsecs.select{|n| n.name == nsec.next_domain}
        if (candidates.length == 0)
          log(LOG_ERR, "Can't follow NSEC loop from #{nsec.name} to #{nsec.next_domain} - starting new loop at next NSEC record")
          nsec = nsecs.delete_at(0)
          break if !nsec
        else
          nsec = candidates[0]
          # Remove that from the list
          nsec = nsecs.delete(nsec)
        end
        # Check the TTL
        check_nsec_ttl_and_types(nsec, soa, domain_rrsets)
        # And follow it's NSEC...
      end

      # Make sure all form closed loop, with no NSECs left
      # (Remember last NSEC points to zone apex)
      if (nsecs.length > 0)
        msg = "Some NSEC records left after folowing closed loop. Details : "
        nsecs.each {|nsec| msg = msg + "#{nsec}, "}
        msg = msg + "End of extra NSEC list"
        log(LOG_ERR, msg)
      end
      print "\nFINISHED CHECKING NSEC\n\n"

    end

    def check_nsec_ttl_and_types(nsec, soa, domain_rrsets, hash_to_domain_map = nil)
      if (nsec.ttl != soa.minimum)
        log(LOG_ERR, "NSEC record should have SOA of #{soa.minimum}, but is #{nsec}")
      end
      # Check the types field of the NSEC RRs to make sure that they cover the right types!
      # Problem with NSEC3 here - they have HASHED owner name. So we need to match the nsec3.name up with the HASHED owner name.
      # So we need a map of domain name <-> Hashed owner name
      rrset_array=[]
      if ([Types.NSEC3, Types.NSEC3PARAM].include?nsec.type )
        rrset_array = domain_rrsets[hash_to_domain_map[nsec.name.canonical]]
        if (!rrset_array)
          rrset_array = domain_rrsets[nsec.name]
        end
      else
        rrset_array = domain_rrsets[nsec.name]
      end
      if (!rrset_array)
        log(LOG_ERR, "Failed looking up RR types for #{nsec.type} for #{nsec.name}")
        return
      end
      types = []
      seen_rrsig = false
      rrset_array.each {|rrset|
        types.push(rrset.type)
        if (!seen_rrsig && (rrset.sigs.length > 0))
          seen_rrsig = true
          types.push(Types.RRSIG)
        end
      }
      nsec.types.each {|type|
        if !(types.include?type)
          log(LOG_ERR, "#{nsec.type} includes #{type} which is not in rrsets for #{nsec.name}")
        end
        types.delete(type)
      }
      if (types.length > 0)
        # If using NSEC3, then check for empty nonterminals in the input zone
        if (nsec.type == Types.NSEC3)
          # If the input zone does not contain the pre-hashed nsec3 name, then ignore it
          if (!hash_to_domain_map[nsec.name.canonical])
            # Ignore
            return
          end
        end
        # Otherwise, log the missing types
        s = ""
        types.each {|t| s = s + " #{t} "}
        log(LOG_ERR, "#{s} types not in #{nsec.type} for #{nsec.name}")
      end
    end

    def check_nsec3(config, nsecs, nsec3s, nsec3params, nsec3names, domains, soa, domain_rrsets, nss)
      if (nsecs.length > 0)
        log(LOG_ERR, "NSEC RRs included in NSEC3-signed zone")
      end
      nsec3param = nil
    
      if (nsec3s.length == 0)
        log(LOG_ERR, "No NSEC3 records in zone #{soa.name}")
        return
      end

      # Create a list of the hashed owner names in the zone
      nsec3 = nsec3s[0]
      hash_to_domain_map = {}
      hashed_domains = []
      (domains - nsec3names).each {|domain|
        hashed_domain = (RR::NSEC3.calculate_hash(domain, nsec3.iterations, RR::NSEC3.decode_salt(nsec3.salt), nsec3.hash_alg))
        hashed_domains.push(hashed_domain)
        hashed_domain = Name.create(hashed_domain.to_s + "." + soa.name.to_s)
        hash_to_domain_map[hashed_domain.canonical] = domain
        #      print "Added #{hashed_domain} for #{domain}\n"
      }
      #    hashed_domains = hash_to_domain_map.values
      hashed_domains.sort!

      if (nsec3params.length > 0)
        # Check NSEC3PARAM - if present, must be only one, and present at apex
        #                  - flags should be zero
        #                  - All NSEC3 records in zone have same alg and salt params as nsec3param
        if (nsec3params.length > 1)
          log(LOG_ERR, "#{nsec3params.length} NSEC3PARAM RRs for #{soa.name}")
        end
        nsec3param = nsec3params[0]
        if (nsec3param.flags != 0)
          log(LOG_ERR, "NSEC3PARAM flags should be 0, but were #{nsec3param.flags} for #{soa.name}")
        end
      end

      nsec3s.each {|nsec3|
        if (nsec3param)
          if (nsec3.hash_alg != nsec3param.hash_alg)
            log(LOG_ERR, "#{nsec3.name} NSEC3 has algorithm #{nsec3.hash_alg}, but NSEC3PARAM has #{nsec3param.hash_alg}")
          end
          if (nsec3.salt != nsec3param.salt)
            log(LOG_ERR, "#{nsec3.name} NSEC3 has salt #{nsec3.salt}, but NSEC3PARAM has #{nsec3param.salt}")
          end
        end
        # NSEC3 RR has correct bits set to identify RR types in RRSet
        check_nsec_ttl_and_types(nsec3, soa, domain_rrsets, hash_to_domain_map)

        # Take next hashed owner name out of list
        next_hashed = Name.create(RR::NSEC3.encode_next_hashed(nsec3.next_hashed) + "." + soa.name.to_s + ".")
        nsec3names.delete(next_hashed)

        if !(nsec3.opt_out?)
          # If an NSEC3 record does not have the opt-out bit set, there are no domain names in the zone for which
          # the hash lies between the hash of this domain name and the value in the "Next Hashed Owner" name field.
          # @TODO@ What about glue records and unsigned delegations?
          # Glue records are not signed.
          # Delegation to an unsigned sub-domain MAY not be signed if the opt-out bit is set.

          # so - check hashed_domains for anything in between nsec3.name and nsec3.next_hashed
          found_domains = hashed_domains.select {|hash| ((nsec3.name.to_s < hash) && (hash < RR::NSEC3.encode_next_hashed(nsec3.next_hashed)))}
          found_domains.each {|domain|
            # Check that domain is :
            # a) Not a glue record, and
            # b) @TODO@ Not an unsigned delegation (NS but no DS), and
            # c) Not out of zone
            # Need to find unhashed domain...
            unhashed_domain = hash_to_domain_map[Name.create(domain.to_s + "." + soa.name.to_s).canonical]

            if ((is_glue(unhashed_domain, soa, nss) ||
                (out_of_zone(unhashed_domain, soa.name))))
              found_domains.delete(domain)
            end
          }
          if (found_domains.length > 0)
            log(LOG_ERR, "#{found_domains.length} domains between #{nsec3.name} and #{RR::NSEC3.encode_next_hashed(nsec3.next_hashed)}, with opt out not set")
          end

        end
      }
      # NSEC3 next_hashed should form closed loop of all NSEC3s (but not all domains)
      # We have already removed all the next_hashed names from the list of nsec3names - so there should
      # be no nsec3names left in the list
      if (nsec3names.length > 0)
        log(LOG_ERR, "#{nsec3names.length} NSEC3 names outside of closed loop of hashed owner names")
      end
      print "\nFINISHED CHECKING NSEC3\n\n"
    end

    def load_zone(file, do_dnssec = false)
      # For each zone file, we want to load it as a collection of RRSets.
      # We need a list of nsec3 records, a list of nsec records,
      # a list of non-DNSSEC records, and a list of signed domains
      # Some records may be in more than one list.
      # We should hold a list of domains in the zone
      # And a list of signed domains in the zone
      # We should also hold a list of RRSets in the zone\
      # We want a hash of domain_names to [rrsets_for_that_name]

      rrs = []
      keys=[]
      nsecs=[]
      nsecnames=[]
      nsec3s=[]
      nsec3params=[]
      nsec3names = []
      sigs=[]
      domains = []
      signed_domains = []
      rrsets = []
      nss = []
      soa = nil
      File.open(file, 'r') {|f|
        while (line = f.gets)
          line.chomp!
          line.strip!
          next if (line.index(';') == 0)
          next if (!line || (line.length == 0))
          rr = nil
          begin
            rr = RR.create(line)
            #            print "#{rr}\n"
            add_to_rrs(rrs, rr)
            add_to_rrset(rrsets, rr)
            add_to_domains(domains, signed_domains, rr)
            if (do_dnssec)
              if (rr.type == Types.DNSKEY)
                add_to_rrs(keys, rr)
              elsif (rr.type == Types.NSEC)
                add_to_rrs(nsecs, rr)
                nsecnames.push(rr.name)
              elsif (rr.type == Types.NSEC3)
                add_to_rrs(nsec3s, rr)
                nsec3names.push(rr.name)
              elsif (rr.type == Types.NSEC3PARAM)
                add_to_rrs(nsec3params, rr)
              elsif (rr.type == Types.RRSIG)
                add_to_rrs(sigs, rr)
              elsif (rr.type == Types.NS)
                add_to_rrs(nss, rr)
              end
            elsif (rr.type == Types.SOA)
              soa = rr
            end
          rescue DecodeError => e
            log(LOG_ERR, "#{file} contains invalid RR : #{line}")
          end
        end
      }
      #          print "\nDone file\n\n"
      if (do_dnssec)
        domain_rrsets = load_domain_rrsets(rrsets)
        #      return rrsets.sort!, keys.sort!, sigs.sort!, nsecs.sort!, nsec3s.sort!, nsec3params.sort!
        return rrs, keys, sigs, nsecs, nsecnames.sort, nsec3s, nsec3params, nsec3names.sort, domains.sort, signed_domains.sort, domain_rrsets, nss
      else
        #      rrsets.sort!.each {|x| print x.name.to_s + "\n"}
        #      return rrsets.sort!
        return rrs, soa
      end
    end
    def load_domain_rrsets(rrsets)
      domain_rrsets = Hash.new
      rrsets.each {|rrset|
        if (arr = domain_rrsets[rrset.name])
          # Add to the existing array
          arr.push(rrset)
        else
          # Create a new array of RRSets to add to domain_rrsets
          domain_rrsets[rrset.name] = [rrset]
        end
      }
      return domain_rrsets
    end
    def add_to_rrs(rrs, rr)
      rrs.push(rr)
    end
    def add_to_rrset(rrsets, rr)
      found_rrset = false
      # Does rrsets contain an RRSet which this rr could join?
      rrsets.each {|rrset|
        if (rrset.add(rr))
          #                                  print "Added to existing RRSet (#{rr})\n"
          found_rrset = true
          break
        end
      }
      if (!found_rrset)
        #                            print "Creating new RRSet for #{rr}\n"
        new_rrset = RRSet.new(rr)
        rrsets.push(new_rrset)
      end
    end
    def add_to_domains(domains, signed_domains, rr)
      # Maintain a list of unique domains in the zone, as well as unique
      # signed domains in the zone
      if !(domains.include?rr.name)
        domains.push(rr.name)
      end
      if !(signed_domains.include?rr.name)
        if (rr.type == Types.RRSIG)
          signed_domains.push(rr.name)
        end
      end
    end
  end
end
