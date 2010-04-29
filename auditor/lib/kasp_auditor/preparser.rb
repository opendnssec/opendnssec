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
      system("#{Commands.sort} #{file1} > #{file2}")
    end

    def initialize(config)
      @config = config
      @line_num = 0
      origin = config.name
      soa_minimum = config.soa ? config.soa.minimum : nil
      soa_ttl = config.soa ? config.soa.ttl : nil
      @zone_reader = Dnsruby::ZoneReader.new(origin, soa_minimum, soa_ttl)
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
              ret = process_line(line)
              next if !ret


              if (ret)
                new_line, type, last_name = ret
                # Append the domain name and the RR Type here - e.g. "$NS"
                line_to_write = prepare(last_name) + NAME_SEPARATOR + type.to_s + SORT_SEPARATOR + new_line
                f.write(line_to_write)
              end
            }
          rescue Exception => e
            KASPAuditor.exit("ERROR - Can't open zone file : #{infile.inspect} : #{e}", 1)
          end
        }
      rescue Exception => e
        KASPAuditor.exit("ERROR - Can't open temporary output file : #{outfile.inspect} : #{e}", 1)
      end
    end

    def process_line(line)
      @line_num += 1
      begin
        @zone_reader.process_line(line, true)
      rescue Exception => e
        #        print "ERROR parsing line #{@line_num} : #{line}\n"
        return false # "\n", Types::ANY
      end
    end

    # Take a domain name, and return the form to be prepended to the RR.
    def prepare(domain)
      # Check if the name contains any escape characters ("\") - If not, then just reverse elements.
      # If it does contain escape characters, then parse it as a proper name.

      labels = domain.split(".")
      if (domain.index("\\"))
        name = Name.create(domain)
        labels = name.labels
      end
      # Simply reverse each label
      return labels.reverse!.join(LABEL_SEPARATOR).downcase
    end

  end
end