#!/bin/sh

ruby -I/usr/local/lib/opendnssec -r kasp_auditor.rb -e '
include KASPAuditor

path = ARGV[0] 
pos = 1
zones = []
while (ARGV[pos])
  zones.push(ARGV[pos])
  pos += 1
end
runner = Runner.new
print "Path : #{path}, zones : #{zones}\n"
runner.run(path, zones)' $@
