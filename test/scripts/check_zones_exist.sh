#!/usr/bin/ruby
#
# $Id$
#
# Check if signed zones exist
# usage : check_zones_exist <zone1> <zone2> ...

exit_value = 0
ARGV.each {|zone|
  if (File.exist?("#{ENV['HOME']}/ODS/var/opendnssec/signed/#{zone}"))
    print "Zone #{zone} signed successfully\n"
  else 
    print "Zone #{zone} was not correctly signed\n"
    exit_value = 1
  end
}
exit(exit_value)
