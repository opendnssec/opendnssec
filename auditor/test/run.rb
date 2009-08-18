require 'kasp_auditor.rb'
include KASPAuditor

path = ARGV[0] 
pos = 1
zones = []
while (ARGV[pos])
  zones.push(ARGV[pos])
  pos += 1
end
runner = Runner.new
runner.run(path, zones)
