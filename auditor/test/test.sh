#!/bin/sh
#
# $Id$

ruby -I/usr/local/lib/opendnssec -r kasp_auditor.rb -e " print 'hello'
include KASPAuditor

# path = ARGV[0] + '/'
#path = $0
path = '/etc/opendnssec/'
runner = Runner.new
runner.run(path)"
