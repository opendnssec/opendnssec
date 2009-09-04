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

    # @TODO@ Need to use different separator - difficult, since arbitrary data
    # can be encoded in name labels. Just have to hope we don't find a zone
    # with many vertical tabs in the names!
    SORT_SEPARATOR = "\v" # "\v" Vertical Tab
    
    NAME_SEPARATOR = "\0\0$~$~$~\0\0"
    LABEL_SEPARATOR = "\0\1\0"


    # Call the OS sort command (with the appropriate separator).
    def sort(file1, file2)
      file1=(file1.to_s+"").untaint
      file2=(file2.to_s+"").untaint
      system("sort -f -t'#{SORT_SEPARATOR}' #{file1} > #{file2}")
    end

    # Take an input zone file ("zonefile") and output a new file ("zonefile.sorted")
    # The output file has each (expanded) line prepended by the labels of the owner
    # name for the RR in reversed order.
    # The type is also prepended to the line - this allows RRSets to be ordered
    # with the RRSIG and NSEC records last.
    def normalise_zone_and_add_prepended_names(infile, outfile)
      origin = ""
      last_name = nil
      continued_line = nil
      # Need to replace any existing files
      infile = (infile.to_s+"").untaint
      outfile = (outfile.to_s+"").untaint
      if  File.exist?(outfile)
        File.delete(outfile)
      end
      begin
        File.open(outfile, File::CREAT|File::RDWR) { |f|
          begin
            IO.foreach(infile) { |line|
              next if (line.index(';') == 0)
              next if (!line || (line.length == 0))
              if (line.index("$ORIGIN") == 0)
                origin = line.split()[1].strip #  $ORIGIN <domain-name> [<comment>]
#                print "Setting $ORIGIN to #{origin}\n"
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
              line = prepare(domain) + NAME_SEPARATOR + type + SORT_SEPARATOR + line
              f.write(line)
            }
          rescue Errno::ENOENT
            KASPAuditor.exit("ERROR - Can't open zone file : #{infile}", 1)
          end
        }
      rescue Errno::ENOENT
        KASPAuditor.exit("ERROR - Can't open temporary output file : #{outfile}", 1)
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