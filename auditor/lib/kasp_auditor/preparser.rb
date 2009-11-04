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
  # This class reads a zone file, and transforms it to a form suitable to be
  # sorted by the OS sort command.
  # For purposes of sorting, each RR should be prepended by the reversed
  # domain name, followed by a separator (each label of the name is preserved
  #  - the labels are simply written in reverse order)
  # This allows the auditor to operate on a zone file which is essentially
  # in canonical order.
  class Preparser

    SORT_SEPARATOR = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" # "\v" Vertical Tab
    
    NAME_SEPARATOR = "\0\0$~$~$~\0\0"
    LABEL_SEPARATOR = "\0\1\0"


    # Call the OS sort command (with the appropriate separator).
    def sort(file1, file2)
      file1=(file1.to_s+"").untaint
      file2=(file2.to_s+"").untaint
      system("sort #{file1} > #{file2}")
    end

    def initialize(config)
      @origin = config.name
      @config = config

      if (!Name.create(@origin).absolute?)
        @origin = @origin + "."
      end
      if (config.soa.minimum && !@last_explicit_ttl)
        @last_explicit_ttl = config.soa.minimum
      else
        @last_explicit_ttl = 0
      end
      @last_explicit_class = Classes.new("IN")
      @last_name = nil
      @continued_line = nil
      @in_quoted_section = false
      @seen_soa = false
    end

    # Take an input zone file ("zonefile") and output a new file ("zonefile.sorted")
    # The output file has each (expanded) line prepended by the labels of the owner
    # name for the RR in reversed order.
    # The type is also prepended to the line - this allows RRSets to be ordered
    # with the RRSIG and NSEC records last.
    def normalise_zone_and_add_prepended_names(infile, outfile)
      # Need to replace any existing files
      infile = (infile.to_s+"").untaint
      outfile = (outfile.to_s+"").untaint
      if  File.exist?(outfile)
        File.delete(outfile)
      end
      @line_num = 0
      begin
        File.open(outfile, File::CREAT|File::RDWR) { |f|
          begin
            IO.foreach(infile) { |line|
              @line_num += 1
              ret = process_line(line)


              if (ret)
                new_line, type = ret
                # Append the domain name and the RR Type here - e.g. "$NS"
                line_to_write = prepare(@last_name) + NAME_SEPARATOR + type.to_s + SORT_SEPARATOR + new_line
                f.write(line_to_write)
              end
            }
          rescue Errno::ENOENT
            KASPAuditor.exit("ERROR - Can't open zone file : #{infile}", 1)
          end
        }
      rescue Errno::ENOENT
        KASPAuditor.exit("ERROR - Can't open temporary output file : #{outfile}", 1)
      end
    end

    def process_line(line)
      return nil if (line.index(';') == 0)
      return nil if (line.strip.length == 0)
      return nil if (!line || (line.length == 0))
      @in_quoted_section = false if !@continued_line

      line = strip_comments(line)

      if ((line.index("SOA")) && (!@seen_soa))
        @seen_soa = true
      end
      if (line.index("$ORIGIN") == 0)
        @origin = line.split()[1].strip #  $ORIGIN <domain-name> [<comment>]
        #                print "Setting $ORIGIN to #{@origin}\n"
        return nil
      end
      if (line.index("$TTL") == 0)
        @last_explicit_ttl = get_ttl(line.split()[1].strip) #  $TTL <ttl>
        #                print "Setting $TTL to #{ttl}\n"
        return nil
      end
      if (@continued_line)
        # Add the next line until we see a ")"
        # REMEMBER TO STRIP OFF COMMENTS!!!
        @continued_line = strip_comments(@continued_line)
        line = @continued_line.strip.chomp + " " + line
        if (line.index(")"))
          # OK
          @continued_line = false
        end
      end
      open_bracket = line.index("(")
      if (open_bracket)
        # Keep going until we see ")"
        index = line.index(")")
        if (index && (index > open_bracket))
          # OK
          @continued_line = false
        else
          @continued_line = line
        end
      end
      return nil if @continued_line

      line = strip_comments(line) + "\n"

      # If SOA, then replace "3h" etc. with expanded seconds
      begin
        return normalise_line(line)
      rescue Exception => e
        print "ERROR parsing line #{@line_num} : #{line}\n"
        return "\n", Types::ANY
      end
    end

    def strip_comments(line)
      last_index = 0
      # Are we currently in a quoted section?
      # Does a quoted section begin or end in this line?
      # Are there any semi-colons?
      # Ary any of the semi-colons inside a quoted section?
      while (next_index = line.index(";", last_index + 1))
        # Have there been any quotes since we last looked?
        process_quotes(line[last_index, next_index - last_index])

        # Now use @in_quoted_section to work out if the ';' terminates the line
        if (!@in_quoted_section)
          return line[0,next_index - last_index]
        end

        last_index = next_index
      end
      # Check out the quote situation to the end of the line
      process_quotes(line[last_index, line.length-1])

      return line
    end

    def process_quotes(section)
      # Look through the section of text and set the @in_quoted_section
      # as it should be at the end of the given section
      last_index = 0
      while (next_index = section.index("\"", last_index + 1))
        @in_quoted_section = !@in_quoted_section
        last_index = next_index
      end
    end

    # Take a domain name, and return the form to be prepended to the RR.
    def prepare(domain)
      # Check if the name contains any escape characters ("\") - If not, then just reverse elements.
      # If it does contain esape characters, then parse it as a proper name.

      if (domain.index("\\"))
        name = Name.create(domain)
        labels = name.labels
        new_name = Name.new(labels.reverse, true)
        return new_name.labels.join(LABEL_SEPARATOR).downcase
      else
        # Simply reverse each label
        return domain.split(".").reverse!.join(LABEL_SEPARATOR).downcase
      end
    end

    # Take a line from the input zone file, and return the normalised form
    def normalise_line(line)
      # Note that a freestanding "@" is used to denote the current origin - we can simply replace that straight away
      # Remove the ( and )
      # Note that no domain name may be specified in the RR - in that case, last_name should be used. How do we tell? Tab or space at start of line.
      if ((line[0,1] == " ") || (line[0,1] == "\t"))
        line = @last_name + " " + line
      end
      line.chomp!
      line.sub!("(", "")
      line.sub!(")", "")
      line.sub!("@ ", "#{@origin} ")
      line.sub!("@\t", "#{@origin} ")
      line.strip!

      
      # o We need to identify the domain name in the record, and then
      split = line.split(' ') # split on whitespace
      name = split[0].strip
      # o add $ORIGIN to it if it is not absolute
      if !(/\.\z/ =~ name)
        new_name = name + "." + @origin
        line.sub!(name, new_name)
        name = new_name
        split = line.split
      end

      # If the second field is not a number, then we should add the TTL to the line
      # Remember we can get "m" "w" "y" here! So need to check for appropriate regexp...
      found_ttl_regexp = (split[1]=~/^[0-9]+[smhdwSMHDW]/)
      if (found_ttl_regexp == 0)
        # Replace the formatted ttl with an actual number
        ttl = get_ttl(split[1])
        line = name + " #{ttl} "
        @last_explicit_ttl = ttl
        (split.length - 2).times {|i| line += "#{split[i+2]} "}
        line += "\n"
        split = line.split
      elsif (((split[1]).to_i == 0) && (split[1] != "0"))
        # Add the TTL
        if (!@last_explicit_ttl)
          # If this is the SOA record, and no @last_explicit_ttl is defined,
          # then we need to try the SOA TTL element from the config. Otherwise,
          # find the SOA Minimum field, and use that.
          # We should also generate a warning to that effect
          # How do we know if it is an SOA record at this stage? It must be, or
          # else @last_explicit_ttl should be defined
          # We could put a marker in the RR for now - and replace it once we know
          # the actual type. If the type is not SOA then, then we can raise an error
          line = name + " %MISSING_TTL% "
        else
          line = name + " #{@last_explicit_ttl} "
        end
        (split.length - 1).times {|i| line += "#{split[i+1]} "}
        line += "\n"
        split = line.split
      else
        @last_explicit_ttl = split[1].to_i
      end

      # Now see if the clas is included. If not, then we should default to the last class used.
      begin
        klass = Classes.new(split[2])
        @last_explicit_class = klass
      rescue ArgumentError
        # Wasn't a CLASS
        # So add the last explicit class in
        line = ""
        (2).times {|i| line += "#{split[i]} "}
        line += " #{@last_explicit_class} "
        (split.length - 2).times {|i| line += "#{split[i+2]} "}
        line += "\n"
        split = line.split
      rescue Error => e
      end

      # Add the type so we can load the zone one RRSet at a time.
      type = Types.new(split[3].strip)
      is_soa = (type == Types::SOA)
      type_was = type
      if (type == Types.RRSIG)
        # If this is an RRSIG record, then add the TYPE COVERED rather than the type - this allows us to load a complete RRSet at a time
        type = Types.new(split[4].strip)
      end

      type_string=prefix_for_rrset_order(type, type_was)
      @last_name = name

      if (is_soa)
        if (@config.soa && @config.soa.ttl)
          # Replace the %MISSING_TTL% text with the SOA TTL from the config
          line.sub!(" %MISSING_TTL% ", " #{@config.soa.ttl} ")
        else
          # Can we try the @last_explicit_ttl?
          if (@last_explicit_ttl)
            line.sub!(" %MISSING_TTL% ", " #{@last_explicit_ttl} ")
          end
        end
        line = replace_soa_ttl_fields(line)
        if (!@last_explicit_ttl)
          soa_rr = Dnsruby::RR.create(line)
          @last_explicit_ttl = soa_rr.minimum
        end
      end

      line = line.split.join(' ').strip
      # We need to fix up any non-absolute names in the RR
      # Some RRs have a single name, at the end of the string -
      #   to do these, we can just check the last character for "." and add the
      #   "." + origin string if necessary
      if ([Types::MX, Types::NS, Types::AFSDB, Types::NAPTR, Types::RT,
            Types::SRV, Types::CNAME, Types::MB, Types::MG, Types::MR,
            Types::PTR].include?type_was)
        if (line[line.length-1, 1] != ".")
          line = line + "." + @origin.to_s
        end
      end
      # Other RRs have several names. These should be parsed by Dnsruby,
      #   and the names adjusted there.
      if ([Types::MINFO, Types::PX, Types::RP].include?type_was)
        parsed_rr = Dnsruby::RR.create(line)
        case parsed_rr.type
        when Types::MINFO
          if (!parsed_rr.rmailbx.absolute?)
            parsed_rr.rmailbx = parsed_rr.rmailbx.to_s + "." + @origin.to_s
          end
          if (!parsed_rr.emailbx.absolute?)
            parsed_rr.emailbx = parsed_rr.emailbx.to_s + "." + @origin.to_s
          end
        when Types::PX
          if (!parsed_rr.map822.absolute?)
            parsed_rr.map822 = parsed_rr.map822.to_s + "." + @origin.to_s
          end
          if (!parsed_rr.mapx400.absolute?)
            parsed_rr.mapx400 = parsed_rr.mapx400.to_s + "." + @origin.to_s
          end
        when Types::RP
          if (!parsed_rr.mailbox.absolute?)
            parsed_rr.mailbox = parsed_rr.mailbox.to_s + "." + @origin.to_s
            if (!parsed_rr.txtdomain.absolute?)
              parsed_rr.txtdomain = parsed_rr.txtdomain.to_s + "." + @origin.to_s
            end
          end
        end
        line = parsed_rr.to_s
      end

      return line + "\n", type_string
    end

    # Get the TTL in seconds from the m, h, d, w format
    def get_ttl(ttl_text_in)
      # If no letter afterwards, then in seconds already
      # Could be e.g. "3d4h12m" - unclear if "4h5w" is legal - best assume it is
      # So, search out each letter in the string, and get the number before it.
      ttl_text = ttl_text_in.downcase
      index = ttl_text.index(/[whdms]/)
      if (!index)
        return ttl_text.to_i
      end
      last_index = -1
      total = 0
      while (index)
        letter = ttl_text[index]
        number = ttl_text[last_index + 1, index-last_index-1].to_i
        new_number = 0
        case letter
        when 115 then # "s"
          new_number = number
        when 109 then # "m"
          new_number = number * 60
        when 104 then # "h"
          new_number = number * 3600
        when 100 then # "d"
          new_number = number * 86400
        when 119 then # "w"
          new_number = number * 604800
        end
        total += new_number
          
        last_index = index
        index = ttl_text.index(/[whdms]/, last_index + 1)
      end
      return total
    end

    def replace_soa_ttl_fields(line)
      # Replace any fields which evaluate to 0
      split = line.split
      4.times {|i|
        x = i + 7
        split[x].strip!
        split[x] = get_ttl(split[x]).to_s
      }
      return split.join(" ") + "\n"
    end

    # Frig the RR type so that NSEC records appear last in the RRSets.
    # Also make sure that DNSKEYs come first (so we have a key to verify
    # the RRSet with!).
    def prefix_for_rrset_order(type, type_was)
      # Now make sure that NSEC(3) RRs go to the back of the list
      if ['NSEC', 'NSEC3'].include?type.string
        if (type_was == Types::RRSIG)
          # Get the RRSIG first
          type_string = "ZZ" + type.string
        else
          type_string = "ZZZ" + type.string
        end
      elsif type == Types::DNSKEY
        type_string = "0" + type.string
      elsif type == Types::NS
        # Make sure that we see the NS records first so we know the delegation status
        type_string = "1" + type.string
      else
        type_string = type.string
      end
      return type_string
    end

  end
end