module KASPAuditor
    # This class reads a zone file, and transforms it to a form suitable to be sorted by the OS sort command.
    # For purposes of sorting, each RR should be prepended by the reversed domain name, followed by a separator.
    #(each label of the name is preserved - the labels are simply written in reverse order)
    # This allows the auditor to operate on a zone file which is essentially in canonical order.
  class Preparser

    # @TODO@ Need to use different separator - difficult, since arbitrary data
    # can be encoded in name labels. Just have to hope we don't find a zone
    # with many vertical tabs in the names!
    SEPARATOR = "\v" # "\v" Vertical Tab



    # We then need to make sure that the auditor skips everything before the separator when it loads the zones
    #   or else we need another method to scan the file again and remove the prepended reversed names ( + separators)

    # Call the OS sort command (with the appropriate separator).
    def sort(file)
      system("sort -t$'#{SEPARATOR}' #{file}.parsed > #{file}.sorted")
    end

    # Take an input zone file ("zonefile") and output a new file ("zonefile.sorted")
    # The output file has each (expanded) line prepended by the labels of the owner
    # name for the RR in reversed order.
    # The type is also prepended to the line - this allows RRSets to be ordered
    # with the RRSIG and NSEC records last.
    def normalise_zone_and_add_prepended_names(infile, outfile)
      print "Writing normalised output to #{outfile}\n"
      origin = ""
      last_name = nil
      continued_line = nil
      count = 0
      # Need to replace any existing files
      if  File.exist?(outfile)
        File.delete(outfile)
      end
      File.open(outfile, File::CREAT|File::RDWR) { |f|
        IO.foreach(infile) { |line|
          count = count + 1
          if (count == 10000)
            print "#{line}"
            count = 0
          end
          next if (line.index(';') == 0)
          next if (!line || (line.length == 0))
          if (line.index("$ORIGIN") == 0)
            origin = line.split()[1].strip #  $ORIGIN <domain-name> [<comment>]
            print "Setting $ORIGIN to #{origin}\n"
            next
          end
          if (continued_line)
            # Add the next line until we see a ")"
            line = continued_line.strip.chomp + line
            if (line.index(")"))
              # OK
              continued_line = false
            end
          end
          open_bracket = line.index("(")
          if (open_bracket)
            # Keep going until we see ")"
            if (line.index(")") > open_bracket)
              # OK
              continued_line = false
            else
              continued_line = line
            end
          end
          next if continued_line
          line, domain, type = normalise_line(line, origin, last_name)
          last_name = domain
          # Append the domain name and the RR Type here - e.g. "$NS"
          line = prepare(domain) + "$" + type + SEPARATOR + line
          f.write(line)
        }
      }
    end

    # Take a domain name, and return the form to be prepended to the RR.
    def prepare(domain)
      # Check if the name contains any escape characters ("\") - If not, then just reverse elements.
      # If it does contain esape characters, then parse it as a proper name.

      if (domain.index("\\"))
        name = Name.create(domain)
        labels = name.labels
        new_name = Name.new(labels.reverse, true)
        return new_name.to_s.downcase
      else
        # Simply reverse each label
        return domain.split(".").reverse!.join(".").downcase
      end
    end

    # Take a line from the input zone file, and return the normalised form
    def normalise_line(line, origin, last_name)
      # Note that a freestanding "@" is used to denote the current origin - we can simply replace that straight away
      line.sub!(" @ ", " #{origin} ")
      # Note that no domain name may be specified in the RR - in that case, last_name should be used. How do we tell? Tab or space at start of line.
      if ((line[0] == " ") || (line[0] == "\t"))
        line = last_name + " " + line
      end
      line.strip
      # o We need to identify the domain name in the record, and then
      split = line.split
      name = split[0].strip
      # Add the type so we can load the zone one RRSet at a time.
      type = Types.new(split[3].strip)
      type_was = type
      if (type == Types.RRSIG)
        # If this is an RRSIG record, then add the TYPE COVERED rather than the type - this allows us to load a complete RRSet at a time
        type = Types.new(split[4].strip)
      end
      # o add $ORIGIN to it if it is not absolute
      if (name[name.length-1] != 46)
        if (origin.length == 0)
          # @TODO@ Log error?
          print "Relative name #{name} set before $ORIGIN encountered!\n"
          #          exit(-1)
        end
        name = name + "." + origin
      end
      # o remove comments?

      type_string=prefix_for_rrset_order(type, type_was)
      
      return line, name, type_string
    end

    # Frig the RR type so that NSEC records appear last in the RRSets.
    # Also make sure that DNSKEYs come first (so we have a key to verify
    # the RRSet with!).
    def prefix_for_rrset_order(type, type_was)
      # Now make sure that NSEC(3) RRs go to the back of the list
      if ['NSEC', 'NSEC3'].include?type.string
        if (type_was == Types.RRSIG)
          # Get the RRSIG first
          type_string = "ZZ" + type.string
        else
          type_string = "ZZZ" + type.string
        end
      elsif type == Types.DNSKEY
        type_string = "0" + type.string
      else
        type_string = type.string
      end
      return type_string
    end

  end
end