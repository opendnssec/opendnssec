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

module KASPAuditor
  class PartialAuditor
    class ScanOptions
      def initialize
        @follow_nsec_loop = false
      end
      attr_accessor :follow_nsec_loop # Follow the NSEC/NSEC3 next domain loop - will also check all nsec3 rrs against nsec3param

      attr_accessor :num_domains # a number of domains to check - limited to 500
    end

    attr_accessor :scan_options
    attr_reader :domain_list, :keys, :soa, :config

    def get_scan_options
      # This should be read from a file or something
      scan_options = ScanOptions.new
      scan_options.follow_nsec_loop = true
      scan_options.num_domains = 1000
      return scan_options
    end

    def initialize(syslog, working)
      @syslog = syslog
      @working = (working.to_s+"").untaint
    end

    def set_config(c) # :nodoc: all
      @config = c
      if (@config.inconsistent_nsec3_algorithm?)
        log(LOG_WARNING, "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used")
      end
    end

    def check_zone(config, unsigned_file, signed_file, enforcer_interval)
      # Run quick checks on the zone.
      # These include :
      #   a) Checking if the number of non-DNSSEC records is the same
      #   b) Checking details of some records as we go
      #
      #  So, we can look out for the interesting records as we go, and only bother
      #  to parse them. Of course, we also need to store some somewhere so we can
      #  compare them after - this could be in memory (if there are few) or in a file
      #  if there are many. We'll need at least those records at the zone apex.
      #
      @num_output_lines = 0
      pid = Process.pid
      temp_unsigned_file = (@working + File::SEPARATOR + File.basename(unsigned_file) + ".#{pid}").untaint
      temp_signed_file = (@working + File::SEPARATOR + File.basename(signed_file) + ".#{pid}").untaint
      temp_keys_file = (@working + File::SEPARATOR + File.basename(signed_file) + ".keys.#{pid}").untaint
      temp_unsigned_keys_file = (@working + File::SEPARATOR + File.basename(signed_file) + ".unsigned.keys.#{pid}").untaint
      @nsec_temp_file = (@working + File::SEPARATOR + File.basename(signed_file) + ".nsec.#{pid}").untaint
      domain_file = (@working + File::SEPARATOR + File.basename(signed_file) + ".domains.#{pid}").untaint
      # Set up a buffer for writing the NSEC records to
      @nsec_buffer = []
      # Remember to flush the buffer when the scan is complete!
      begin # Make sure we delete the temp files afterwards
        @ret_val = 999
        set_config(config)
        @keys = []
        @soa = nil
        @enforcer_interval=enforcer_interval
        @keys_used = []
        @domain_list = []
        log(LOG_INFO, "Auditing #{@config.name} zone : #{@config.denial.nsec ? 'NSEC' : 'NSEC3'} SIGNED")

        # Load the stored key history from previous runs
        @key_tracker = KeyTracker.new(@working, @config.name, self, @config, @enforcer_interval)
        @key_cache = @key_tracker.load_tracker_cache

        # Work out what we need to check about this zone, and thus what we
        # should be looking for as we run through the input files.
        @scan_options = get_scan_options

        types_to_find = {"DNSKEY" => lambda {|split| do_basic_dnskey_checks(split)},
          #        "SOA" => lambda {|split| do_basic_soa_checks(split)},
          "RRSIG" => lambda {|split| do_basic_rrsig_checks(split)}}
        types_to_find["NSEC"]=lambda{|split| do_basic_nsec_checks(split)} # if @scan_options.nsec
        types_to_find["NSEC3"]=lambda{|split| do_basic_nsec3_checks(split)} # if @scan_options.nsec3
        types_to_find["NSEC3PARAM"]=lambda{|split| do_basic_nsec3param_checks(split)} # if @scan_options.nsec3param
        # Remember that TYPE may be either "DNSKEY" or "TYPE46" - but the ods-signer will always write DNSKEY

        if (@scan_options.num_domains)
          load_domains((signed_file.to_s + "").untaint)
        end

        #
        # Start scanning through the output file to make sure that it looks good
        # Also start scanning through the input file to pick out the interesting records

        begin
          pids=[]
          srd, swr = IO.pipe
          new_pid = fork {signed_scanner = SignedZoneScanner.new(self, config, types_to_find)
            begin
              srd.close
              @ret_val = 999
              rr_count, soa = signed_scanner.scan_signed_file(signed_file, domain_file)
              store_keys_and_keys_used(temp_keys_file)
              flush_nsec_buffer
              swr.write("#{@ret_val}\n")
              swr.write("#{rr_count}\n")
              swr.write("#{soa}\n")
              swr.close
            rescue Exception => e
              print e.backtrace
              raise e
            end
          }
          swr.close
          pids.push(new_pid)
          urd, uwr = IO.pipe
          new_pid = fork {
            urd.close
            @ret_val = 999
            unsigned_scanner = UnsignedZoneScanner.new(self, config)
            rr_count, soa = unsigned_scanner.scan_unsigned_file(unsigned_file, temp_unsigned_file)
            unsigned_scanner.store_unsigned_keys(self, temp_unsigned_keys_file)
            uwr.write("#{@ret_val}\n")
            uwr.write("#{rr_count}\n")
            uwr.write("#{soa}\n")
            uwr.close
          }
          uwr.close
          pids.push(new_pid)
          unsigned_ret_val_string = urd.readline()
          rr_count_string = urd.readline()
          soa_line = urd.readline()
          unsigned_ret_val = unsigned_ret_val_string.split()[0].to_i
          unsigned_soa = RR.create(soa_line)
          unsigned_rr_count = rr_count_string.to_i
          urd.close
          signed_ret_val = srd.readline().split()[0].to_i
          rr_count_string = srd.readline()
          soa_line = srd.readline()
          signed_rr_count = rr_count_string.to_i
          signed_soa = RR.create(soa_line)
          srd.close
          pids.each {|id|
            ret_id, ret_status = Process.wait2(id)
            if (ret_status != 0)
              @syslog.log(LOG_ERR, "Error auditing files (#{unsigned_file} and #{signed_file}) : ERR #{ret_status}")
              return ret_status
            end
          }
        ensure
        end
        #      load_soa(temp_unsigned_file)
        # SOA checks of signed against unsigned SOAs
        compare_soas(unsigned_soa, signed_soa)
        @soa = signed_soa
        load_keys_and_keys_used(temp_keys_file)
        unsigned_keys = load_unsigned_keys(temp_unsigned_keys_file)
        Auditor.check_key_config(@keys, unsigned_keys, @key_cache, @config, self)
        found_sep = false
        found_non_sep = false
        @keys.each {|key|
          if (@keys_used.include?key.key_tag)
            if (key.sep_key?)
              found_sep = true
            else
              found_non_sep = true
            end
          end
        }
        if (!found_sep)
          log(LOG_ERR, "No SEP DNSKEY found in use")
        end
        if (!found_non_sep)
          log(LOG_ERR, "No non-SEP DNSKEY found in use")
        end
        if (@scan_options.follow_nsec_loop)
          # Then, we can quickly scan through the .nsec file to make sure that they form a single closed loop.
          check_nsec_loop
        end
        #      print  "#{unsigned_rr_count} unsigned RRs found\n"
        #      print  "#{signed_rr_count} signed RRs found\n"
        if (unsigned_rr_count != signed_rr_count)
          # Remember to only count non-DNSSEC records here!
          # @TODO@ What about DNSSEC records in the input zone?
          log(LOG_WARNING, "Number of non-DNSSEC resource records differs : #{unsigned_rr_count} in #{unsigned_file}, and #{signed_rr_count} in #{signed_file}")
        end
        update_key_stores
        log(LOG_INFO, "Finished auditing #{@soa.name} zone")
        @ret_val = [@ret_val, unsigned_ret_val, signed_ret_val].min
        if (@ret_val == 999)
          return 0
        else
          return @ret_val
        end
      ensure # Make sure we always delete these files
        # @TODO@ Need to wait for both PIDs to finish, then close and delete the files before returning
        delete(temp_keys_file)
        delete(temp_unsigned_keys_file)
        delete(temp_signed_file)
        delete(temp_unsigned_file)
        delete(@nsec_temp_file)
        delete(domain_file)
      end
    end

    def check_nsec_loop
      # Follow the loop of NSEC3 records in @nsec_temp_file,
      # and make sure that they present a closed loop.

      return if (@config.denial.nsec) # Need to have NSEC loop sorted canonically if we are to follow it!

      # First, sort the @nsec_temp_file
      
      system("#{Commands.sort} #{@nsec_temp_file} > #{@nsec_temp_file}.tmp")
      system("mv #{@nsec_temp_file}.tmp #{@nsec_temp_file}")
      # Then simply follow it line by line.
      next_name = nil
      last_name = nil
      last_line = nil
      zone_name = @soa.name.to_s
      first_name = nil
      IO.foreach(@nsec_temp_file) {|line|
        # @TODO@ Do we need to parse the record to get the next owner name?
        if (next_name)
          compare_val = (next_name <=> line.split()[0])
          if (compare_val > 0)
            # last was greater than we expected - we missed an NSEC
            # print an error
            log(LOG_ERR, "Can't follow #{line.split()[3]} loop from #{last_name} to #{next_name}")
          elsif (compare_val < 0)
            # last was less than we expected - we have an extra nsec
            # print an error
            log(LOG_ERR, "#{line.split()[3]} record left after folowing closed loop : #{line.split()[0]}. Was expecting #{next_name}")
          else
            # All OK
          end
        else
          first_name = line.split()[0]
        end
        next_name = get_next(line) + ".#{zone_name}."
        last_name = line.split()[0]
        last_line = line
      }
      # Now make sure that NSEC points back to the first
      if ((next_name != first_name) && last_line)
        log(LOG_ERR, "Can't follow #{last_line.split()[3]} loop from #{last_name} to #{next_name} - found #{first_name}")
      end
    end

    def get_next(line)
      if (@config.denial.nsec)
        return line.split()[4]
      else
        return line.split()[8]
      end
    end


    def compare_soas(unsigned_soa, signed_soa)
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
    end

    def delete(file)
      begin
        File.delete(file)
      rescue Exception 
      end
    end

    def store_keys_and_keys_used(file)
      delete(file)
      File.open(file, 'w') {|f|
        @keys.each {|key|
          f.write(key.to_s + "\n")
        }
        f.write("USED\n")
        @keys_used.each {|key|
          f.write(key.to_s + "\n")
        }
      }
    end

    def load_keys_and_keys_used(file)
      loading_keys_used = false
      IO.foreach(file) {|line|
        if (line.index("USED"))
          loading_keys_used = true
          next
        end
        if (loading_keys_used)
          @keys_used.push(line.chomp.to_i)
        else
          @keys.push(RR.create(line))
        end
      }
    end

    def load_unsigned_keys(file)
      unsigned_keys = []
      IO.foreach(file) {|line|
        unsigned_keys.push(RR.create(line))
      }
      return unsigned_keys
    end

    class UnsignedZoneScanner
      def initialize(parent, config)
        @parent = parent
        @config = config
        @origin = config.name.to_s + "."
      end

      def scan_unsigned_file(file, temp_file)
        @unsigned_keys = []
        # Only interested in doing this so that we can check the domains of interest
        # Also want to know how many non-DNSSEC RRs there are in unsigned file, so we can check right number is also in signed file.
        # Can we simply track whole lines here? i.e. check what is in and out of comment, keep track of ( and ) and ; to know when new line starts
        continued_line = false
        #        store_this_rr = false
        rr_counter = 0
        need_to_parse = false
        soa = nil
        zone_reader = Dnsruby::ZoneReader.new(@config.name, @config.soa ? @config.soa.minimum : nil,
          @config.soa ? @config.soa.ttl : nil)
        IO.foreach((file.to_s+"").untaint) {|line|
          next if (line[0,1] == ";")
          next if (line.strip.length == 0)
          next if (!line || (line.length == 0))
          if (!continued_line)
            # Now we want to know when the line has ended - need to keep track of brackets, ", ;, etc.
            # If this is a multi-line RR, or even might be, then load the RR up with ZoneReader.
            need_to_parse = (line.index("(") || line.index("\"") || line.index("\'"))
          end
          ret_line = line
          if (need_to_parse || continued_line || ret_line.index("soa") || ret_line.index("SOA") ||
                (line.index("$TTL") == 0) || (line.index("$ORIGIN") == 0))
            # Build up the RR from the input lines until we have the whole thing
            ret_line = zone_reader.process_line(line)
            if (!ret_line)
              continued_line = true
              next
            end
            need_to_parse = false
            continued_line = false
          end
          next if (line.index("$ORIGIN") == 0)
          next if (line.index("$TTL") == 0)
          if (ret_line=~/DNSKEY|RRSIG|NSEC|NSEC3|NSEC3PARAM|TYPE/)
            begin
              rr = RR.create(ret_line)
              if ([Types::RRSIG, Types::DNSKEY, Types::NSEC, Types::NSEC3, Types::NSEC3PARAM].include?rr.type)
                @parent.log(LOG_WARNING, "#{rr.type} present in unsigned file : #{ret_line.chomp}")
                need_to_parse = false
                continued_line = false
                if (rr.type == Types::DNSKEY)
                  @unsigned_keys.push(rr)
                end
                next
              end
            rescue Exception
            end
          end
          if (ret_line.index("soa") || ret_line.index("SOA"))
            rr = RR.create(ret_line)
            if (rr.type == Types::SOA)
              if (soa)
                # Check not more than one SOA in file!
                @parent.log(LOG_ERR, "Multiple SOA records found in signed file")
              end
              soa = ret_line
            end
          end
          need_to_parse = false
          continued_line = false
          # Handle out-of-zone data. 
          # We're interested in non-absolute names which are not in zone.
          rr_name = ret_line.split()[0]
          if (rr_name[rr_name.length-1, 1] != ".") || (rr_name.downcase=~/#{@config.name}\.$/)
            rr_counter += 1
          end
        }
        return rr_counter, soa
      end

      def store_unsigned_keys(parent, file)
        parent.delete(file)
        File.open(file, 'w') {|f|
          @unsigned_keys.each {|key|
            f.write(key.to_s + "\n")
          }
        }
      end

    end

    class SignedZoneScanner
      # We can expect to have one RR per line, and to have an FQDN as the owner name (with only essential escape characters)
      # We can also expect no $TTL, $ORIGIN, etc., directives
      # We can also expect the type to be written as the actual type, unless it really is an RFC3597 unknown type...
      def initialize(parent, config, types_to_find)
        @parent = parent
        @config = config
        @types_to_find = types_to_find
      end
      def scan_signed_file(file, domain_filename)
        @non_dnssec_rr_count = 0
        @algs = []
        #        print "Starting signed zone scan\n"
        pid = fork {
          # Now go through the temp files for the domains of interest, and ensure that they are all good.
          # Use the grep command to find all the domains we're interested in.
          # Write them all out to a single file, and then process that.
          grep_for_domains_of_interest(file, domain_filename)
        }
        first = true
        IO.foreach((file.to_s+"").untaint) {|line|
          next if (line[0,1] == ";")
          next if (line.strip.length == 0)
          if (first)
            first = false
            # Check that SOA record is first record in output zone
            rr = RR.create(line)
            if (rr.type != Types::SOA)
              @parent.log(LOG_ERR, "Expected SOA RR as first record in #{file}, but got RR : #{rr}")
            end
          end
          # Read the line in and split it
          # We know that signed line will always be in canonical form. So, type will always be at line.split()[3]

          # See if it contains an RR type of interest - if so, then process the standard checks that apply for that type
          test_rr_type(line)
        }

        ret_id, ret_status = Process.wait2(pid)
        if (ret_status != 0)
          @parent.log(LOG_WARNING, "Grep failed on #{file} - #{ret_status}")
        else
          scan_temp_domain_files(domain_filename)
        end
        return @non_dnssec_rr_count, @soa
      end

      def grep_for_domains_of_interest(file, domain_filename)
        # Use the parent.domain_list to grep for all the instances of the domains we're after.
        list = @parent.domain_list + @parent.hashed_domain_list
        grep_command = "#{Commands.grep} '"
        first = true
        list.each {|domain|
          if first
            first = false
            grep_command+="^#{domain}"
          else
            grep_command+="\\|^#{domain}"
          end
          break if grep_command.length > 50000
        }
        grep_command= (grep_command + "' #{file}  >> #{domain_filename}").untaint
        system(grep_command)
      end

      DNSSEC_TYPES = ["DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM"]

      def test_rr_type(line)
        # See if the line contains a type of interest.
        type = line.split()[3]
        if (type == "DNSKEY")
          begin
            key_rr = RR.create(line)
            @algs.push(key_rr.algorithm) if !@algs.include?key_rr.algorithm
          rescue Exception => e
          end
        end
        if (type == "SOA" || type == "soa")
          @soa = RR.create(line)
        end
        method = @types_to_find[type]
        if (method)
          # Find the correct test for the RR and then perform it.
          method.call(line)
        end
        if (DNSSEC_TYPES.include?(type))
        else
          @non_dnssec_rr_count += 1
        end
      end


      def scan_temp_domain_files(domain_filename)
        # Now go through the temp files for the domains of interest, and ensure that they are all good.
        @parent.domain_list.each{|domain|
          delegation = false
          rrsets = []
          types = []
          sigs = []
          #          dont_check_hash = false
          # Pick out all the records for that domain
          IO.foreach(domain_filename) {|line|
            if (line.split()[0] == domain)
              begin
                rr = RR.create(line)
              rescue Exception
                next
              end
              if (rr.type == Types::NSEC3 || (rr.type == Types::RRSIG && rr.type_covered == Types::NSEC3))
                #                dont_check_hash = true # It's already a hashed owner name
                types.push(rr.type)
                next
              end
              types.push(Types::RRSIG) if rr.type == Types::RRSIG
              delegation = true if (rr.type == Types::NS)
              found_rrset = false
              rrsets.each {|rrset|
                if (rrset.add(rr))
                  found_rrset = true
                  break
                end
              }
              if (!found_rrset)
                if (rr.type == Types::RRSIG)
                  sigs.push(rr)
                end
                new_rrset = RRSet.new(rr)
                rrsets.push(new_rrset)
                types.push(new_rrset.type)
              end

            end
          }
          sigs.each {|sig|
            # Can we find an rrset?
            rrsets.each {|rrset|
              if (rrset.add(sig))
                sigs.delete(sig)
                break
              end
            }
          }
          rrsets.each {|rrset|
            if (rrset.type == Types::RRSIG)
            end
          }
          # And then check them
          check_domain(rrsets, types, delegation)
          # Now check the hashed owner name
          if (@config.denial.nsec3) #  && !dont_check_hash)
            hashed_owner_name = @parent.get_hashed_owner_name(domain)
            hashed_rrset = RRSet.new
            found = false
            IO.foreach(domain_filename) {|line|
              if (line.split()[0] == hashed_owner_name)
                found = true
                begin
                  rr = RR.create(line)
                rescue Exception => e
                  found = false # Don't try to check this - we can't read a record
                  break
                end
                hashed_rrset.add(rr)
              end
            }
            if (found)
              if (hashed_rrset.type == Types::RRSIG)
                print "\nCAN ONLY FIND NSEC3 RRSIGS FOR #{hashed_owner_name}\n\n"
              end
              check_domain([hashed_rrset], types, delegation)
            else
              # Assume that we have hashed an already hashed owner name
            end
          end
        }
      end


      def check_domain(rrsets, types, delegation)
        # Given an array of resource records for a particular owner name,
        # check that :
        # Each domain has a corresponding NSEC record. [E]
        # Each NSEC record has bits correctly set to indicate the types of RRs associated with the domain. [E]
        # Each NSEC3 record has bits correctly set to indicate the types of RRs associated with the domain. [E]
        #
        # Then, for each RRSet :
        # There is an RRSIG record for each algorithm for which there is a DNSKEY RR (unless the domain is glue, an unsigned delegation or out of zone) [E]
        # The RRSIG record(s) validate the RRset(s) for the domain using one of the keys in the DNSKEY RRset. (Note: except for the zone apex, there should be no RRSIG for NS RRsets, glue records, unsigned delegations or out of zone data.) [E]

        processed_nsec = false
        return if rrsets.length == 0
        is_glue = false

        rrsets.each {|rrset|
          if ([Types::NSEC, Types::NSEC3].include?rrset.type)
            if (rrset.rrs.length > 1)
              # RAISE ERROR - MORE THAN ONE NSEC!
              @parent.log("Multiple NSEC(3) records seen for #{rrset.name}")
            end
            # Process NSEC
            check_nsec_types(rrset.rrs()[0], types)
            processed_nsec = true
          end
          # How do we know if this domain is glue?! We can't, without sorting the zone.
          # So, if there is no RRSIG, then we have to assume that it is glue - should we then ignore it?
          if (rrset.sigs.length > 0)
            check_signature(rrset, delegation)
          else
            is_glue = true
          end
        }
        if (!processed_nsec && @config.denial.nsec && !is_glue)
          # Couldn't find any NSEC record for the domain!!
          # But it might be glue...
          @parent.log(LOG_ERR, "No NSEC record for #{rrsets[0].name}")
        end
        # @TODO@ Check there is an NSEC3 record for the domain!
      end

      # Check the RRSIG for this RRSet
      def check_signature(rrset, delegation)
        if (delegation && ([Types::AAAA, Types::A].include?rrset.type))
          # glue - don't verify
          return
        end
        rrset_sig_types = []
        rrset.sigs.each {|sig| rrset_sig_types.push(sig.algorithm)}
        @algs.each {|alg|
          if !(rrset_sig_types.include?alg)
            if ((rrset.type == Types::NS) && (rrset.name != @soa.name)) # NS RRSet NOT at zone apex is OK
            else
              s = rrset_sig_types.join" "
              @parent.log(LOG_ERR, "RRSIGS should include algorithm #{alg} for #{rrset.name}, #{rrset.type}, have :#{s}")
            end
          end
        }
        #  b) RRSIGs validate for at least one key in DNSKEY RRSet  (Note: except for the zone apex, there should be no RRSIG for NS RRsets.)
        #          print "Verifying RRSIG for #{rrset}\n"
        # @TODO@ Create an RRSET with *only* the RRSIG we are interested in - check that they all verify ok?
        # Check if this is an NS RRSet other than the zone apex - if so, then skip the verify test
        if ((rrset.type == Types::NS) && ((rrset.name != @soa.name)))
          # Skip the verify test
        else
          begin
            #          print "About to verify #{rrset.name} #{rrset.type}, #{rrset.rrs.length} RRs, #{rrset.sigs.length} RRSIGs, #{@keys.length} keys\n"
            Dnssec.verify_rrset(rrset, @parent.keys)
          rescue VerifyError => e
            @parent.log(LOG_ERR, "RRSet (#{rrset.name}, #{rrset.type}) failed verification : #{e}, tag = #{rrset.sigs()[0] ? rrset.sigs()[0].key_tag : 'none'}")
          end
        end
      end

      # Check the types covered by this NSEC record
      def check_nsec_types(nsec, types)
        if ((nsec.type == Types::NSEC && @config.denial.nsec) || (nsec.type == Types::NSEC3 && @config.denial.nsec3))

          nsec.types.each {|type|
            if !(types.include?type)
              @parent.log(LOG_ERR, "#{nsec.type} includes #{type} which is not in rrsets for #{nsec.name}")
            end
            types.delete(type)
          }
          if (types.length > 0)
            # Otherwise, log the missing types
            s = ""
            types.each {|t| s = s + " #{Types.new(t).to_s} "}
            @parent.log(LOG_ERR, "#{s} types not in #{nsec.type} for #{nsec.name}")
          end
        end
      end
    end

    def update_key_stores
      # Use the key_tracker to update and check key stores using
      # the key information in the SOA file.
      @key_tracker = KeyTracker.new(@working, @soa.name.to_s, self, @config, @enforcer_interval)
      @key_tracker.process_key_data(@keys, @keys_used, @soa.serial, @config.soa.ttl)
    end

    def do_basic_nsec_checks(line)
      # Should we have any NSECs in this zone?
      if !(@config.denial.nsec)
        log(LOG_ERR, "NSEC RRs included in NSEC3-signed zone")
        return
      end
      split = line.split
      # Check NSEC TTL
      check_nsec_ttl(split[1], line, "NSEC")
      # Check that following owner names works. In this case, we are best off storing all NSECs
      # in a temporary .nsec file, which we can get the OS to sort once we've done the main pass.
      if (@scan_options.follow_nsec_loop) # It takes time to write the records to file @TODO@ Does it?
        add_to_nsec_file(line)
      end
      # Then, we can quickly scan through the .nsec file to make sure that they form a single closed loop.
    end
    def do_basic_nsec3_checks(line)
      # Should we have any NSEC3s in this zone?
      if (@config.denial.nsec)
        log(LOG_ERR, "NSEC3 RRs included in NSEC-signed zone")
        return
      end
      # Check TTL
      split = line.split
      check_nsec_ttl(split[1], line, "NSEC3")
      # Check that the parameters are the same as those defined in the config
      salt = split[7]
      if (salt != @config.denial.nsec3.hash.salt)
        log(LOG_ERR, "NSEC3 has wrong salt : should be #{@config.denial.nsec3.hash.salt} but was #{salt}")
      end
      iterations = split[6].to_i
      if (iterations != @config.denial.nsec3.hash.iterations)
        log(LOG_ERR, "NSEC3 has wrong iterations : should be #{@config.denial.nsec3.hash.iterations} but was #{iterations}")
      end
      hash_alg = split[4].to_i
      if (hash_alg != @config.denial.nsec3.hash.algorithm)
        log(LOG_ERR, "NSEC3 has wrong algorithm : should be #{@config.denial.nsec3.hash.algorithm} but was #{hash_alg}")
      end
      # Check that following owner names works. In this case, we are best off storing all NSECs
      # in a temporary .nsec file, which we can get the OS to sort once we've done the main pass.
      if (@scan_options.follow_nsec_loop)
        add_to_nsec_file(line)
      end
    end
    # Check the TTL of the NSEC(3) record
    def check_nsec_ttl(nsec_ttl, line, type)
      nsec_ttl = nsec_ttl.to_i
      if (@config.soa && @config.soa.minimum)
        if (nsec_ttl != @config.soa.minimum)
          log(LOG_ERR, "#{type} record should have TTL of #{@config.soa.minimum} from zone policy //Zone/SOA/Minimum, but is #{line.chomp}")
        end
      else
        if (nsec_ttl != @soa.minimum)
          log(LOG_ERR, "#{type} record should have TTL of #{@soa.minimum} from unsigned zone SOA RR minimum, but is #{line.chomp}")
        end
      end
    end

    # Then, we can quickly scan through the .nsec file to make sure that they form a single closed loop.
    def do_basic_nsec3param_checks(line)
      rr = RR.create(line)
      # Should we have any NSEC3PARAMs in this zone?
      if (@config.denial.nsec)
        log(LOG_ERR, "NSEC3PARAM RRs included in NSEC-signed zone")
        return
      end
      # Check NSEC3PARAM flags
      if (rr.flags != 0)
        log(LOG_ERR, "NSEC3PARAM flags should be 0, but were #{rr.flags} for #{rr.name}")
      end
      # Check that we are at the apex of the zone here
      if (rr.name.to_s != @config.name.to_s)
        log(LOG_ERR, "NSEC3PARAM seen at #{rr.name} : should be at zone apex (#{@config.name}")
      end
      # Check that we have not seen an NSEC3PARAM before
      if (!@nsec3param)
        #  Store the NSEC3PARAM parameters for use with the rest of the zones' NSEC3 records
        # We know that no NSECs should have been seen by now, as this record is at the zone apex and NSEC(3) RRs appear at the bottom of the RRSets for the domain
        @nsec3param = rr
      else
        log(LOG_ERR, "Multiple NSEC3PARAM RRs for #{@config.name}")
      end
      #      end
      # Check that the NSEC3PARAMs are the same as those defined in the Config
      if (rr.salt != @config.denial.nsec3.hash.salt)
        log(LOG_ERR, "NSEC3PARAM has wrong salt : should be #{@config.denial.nsec3.hash.salt} but was #{(rr.salt)}")
      end
      if (rr.iterations != @config.denial.nsec3.hash.iterations)
        log(LOG_ERR, "NSEC3PARAM has wrong iterations : should be #{@config.denial.nsec3.hash.iterations} but was #{rr.iterations}")
      end
      if (rr.hash_alg != @config.denial.nsec3.hash.algorithm)
        log(LOG_ERR, "NSEC3PARAM has wrong algorithm : should be #{@config.denial.nsec3.hash.algorithm} but was #{rr.hash_alg.to_i}")
      end
    end

    def do_basic_rrsig_checks(line)
      # @TODO@  Can we check the length of the RRSIG signature here?
      time_now = Time.now.to_i
      split = line.split
      sig_inception = RR::RRSIG.get_time(split[9])
      if (sig_inception > (time_now + @config.signatures.inception_offset))
        log(LOG_ERR, "Inception error for #{split[0].chop}, #{split[4]} : Signature inception is #{sig_inception}, time now is #{time_now}, inception offset is #{@config.signatures.inception_offset}, difference = #{time_now - sig_inception}")
      else
        #                      print "OK : Signature inception is #{sig.inception}, time now is #{time_now}, inception offset is #{@config.signatures.inception_offset}, difference = #{time_now - sig.inception}\n"
      end

      sig_expiration = RR::RRSIG.get_time(split[8])
      #  d) expiration date in future by at least interval specified by config
      refresh = @config.signatures.refresh
      resign = @config.signatures.resign
      # We want to check that there is at least the refresh period left before
      # the signature expires.
      # @TODO@ Probably want to have a WARN level and an ERROR level
      # Expired signatures are caught by the verify_rrset() call above
      if ((time_now <= sig_expiration) && time_now > (sig_expiration - refresh + resign))
        log(LOG_ERR, "Signature expiration (#{sig_expiration}) for #{split[0]}, #{split[4]} should be later than (the refresh period (#{refresh}) - the resign period (#{resign})) from now (#{time_now})")
      else
        #            print "OK : Signature expiration is #{sig.expiration}, time now is #{time_now}, signature validity is #{validity}, difference = #{sig.expiration - time_now}\n"
      end
      # Check signature lifetime :
      # inceptionoffset + validity - jitter ≤ (exception - inception) ≤ inceptionoffset + validity +jitter
      validity = @config.signatures.validity.default
      if (split[4]=~/^NSEC/) && (split[4] != "NSEC3PARAM")
        validity = @config.signatures.validity.denial
      end

      min_lifetime = @config.signatures.inception_offset + validity - @config.signatures.jitter
      max_lifetime = @config.signatures.inception_offset + validity + @config.signatures.jitter
      actual_lifetime = sig_expiration - sig_inception
      if (min_lifetime > actual_lifetime)
        log(LOG_ERR, "Signature lifetime too short - should be at least #{min_lifetime} but was #{actual_lifetime}")
      end
      if (max_lifetime < actual_lifetime)
        log(LOG_ERR, "Signature lifetime too long - should be at most #{max_lifetime} but was #{actual_lifetime}")
      end

      key_tag = split[10]
      @keys_used.push(key_tag) if !@keys_used.include?key_tag

    end

    def do_basic_dnskey_checks(line)
      begin
        key_rr = RR.create(line)
      rescue DecodeError => e
        log(LOG_ERR, "Signed file contains invalid RR : #{line.chomp}, #{e}")
        return
      end
      @keys.push(key_rr)

      #      Auditor.check_key_config(@keys, @unsigned_keys, @key_cache, @config, self)
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

    def add_to_nsec_file(line)
      # Buffer up these lines, and write out when there are a few of them
      # Make sure that the buffer is flushed when the scan is complete!
      @nsec_buffer.push(line)
      if (@nsec_buffer.length > 5000)
        flush_nsec_buffer
      end
    end

    def flush_nsec_buffer
      File.open(@nsec_temp_file, 'a') {|f|
        @nsec_buffer.each {|l|
          f.write(l)
        }
      }
      @nsec_buffer = []
    end


    def get_hash(name)
      return name.hash
    end

    def add_name_to_list(name)
      @domain_list.push(name)
    end

    def name_in_list(name)
      # Return true if the name is on the list
      if (@domain_list.include?name)
        return true
      end
      return false
    end

    def get_hashed_owner_name(name)
      hash = RR::NSEC3.calculate_hash(name, @config.denial.nsec3.hash.iterations,
        RR::NSEC3.decode_salt(@config.denial.nsec3.hash.salt),
        Nsec3HashAlgorithms.new(@config.denial.nsec3.hash.algorithm)) + ".#{@config.name}."
      return hash
    end

    def hashed_domain_list
      ret = []
      if (@config.denial.nsec3)
        @domain_list.each {|domain|
          hash = get_hashed_owner_name(domain)
          ret.push(hash)
        }
      end
      return ret
    end

    def load_domains(signed_file)
      # Fill out the list of domains to look for.

      # Go through the signed file and identify the names of interest
      # For now, just grab the first X names - @TODO@ Fix this
      # @TODO@ Can now do this on main pass through the file - don't need it in a first pass
      counter = 0
      IO.foreach(signed_file) {|line|
        next if (line[0,1]==";")
        name = line.split()[0]
        next if name=~/[\*\(\)\^\[\]\+\$\\]/
        next if !name
        if (!name_in_list(name))
          add_name_to_list(name)
          counter += 1
          break if counter == @scan_options.num_domains
        end
      }
    end
  end
end
