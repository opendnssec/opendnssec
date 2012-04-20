#!/usr/bin/ruby
#
# $Id$
#
# Check if signed zones exist
# usage : check_zones_exist <zone1> <zone2> ...

exit_value = 0
ARGV.each {|zone|
  if (zone[0]==126)
    zone = zone[1, (zone.length() -1)]
    if (!File.exist?("#{ENV['WORKSPACE']}/sandbox/var/opendnssec/signed/#{zone}")
)
      print "Zone #{zone} failed successfully\n"
    else
      print "Zone #{zone} was not correctly failed\n"
      exit_value = 1
    end

  else
    if (File.exist?("#{ENV['WORKSPACE']}/sandbox/var/opendnssec/signed/#{zone}"))
      print "Zone #{zone} signed successfully\n"
    else 
      print "Zone #{zone} was not correctly signed\n"
      exit_value = 1
    end
  end
}
exit(exit_value)
