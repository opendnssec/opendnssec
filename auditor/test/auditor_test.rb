require 'test/unit'
require 'kasp_auditor.rb'
include KASPAuditor

# Giving up on getting long-expiry test data.
# Instead, just use the good test data we have, and frig the system time.
module KASPAuditor
  class KASPTime
    def KASPTime.get_current_time
      return 1245393132
    end
  end
end

class AuditorTest < Test::Unit::TestCase

  def test_good_file_nsec
    # Get the auditor to check a known-good zone (with signatures set well into the future)
    # Make sure there are no errors

    stderr = IO::pipe
    path = "test/signer_test_good/"
    filename = "zonelist_nsec.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)

    # Check syslog to ensure no messages left while this test ran
    assert_equal(nil, err = stderr[0].gets, "Didn't expect any messages in syslog from good auditor run, but got : #{err}\n")
  end

  def test_good_file_nsec3
    stderr = IO::pipe
    path = "test/signer_test_good/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)

    # Check syslog to ensure no messages left while this test ran
    assert_equal(nil, err = stderr[0].gets, "Didn't expect any messages in syslog from good auditor run, but got : #{err}\n")
  end

  def test_bad_file_nsec
    # Get a known-bad zone file 
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec.xml"
    run_auditor_with_syslog(path, filename, stderr) 


    remaining_strings = []
    while (line = stderr[0].gets)
      remaining_strings.push(line)
    end
    expected_strings = [
    # Check the errors in the zone which are common to both NSEC and NSEC3
    #  -  non dnssec data : missing data and
    #        extra data
    #  -  bad SEP : no SEP flag set, and
    #  invalid key.
    #  Also bad protocol  and algorithm
    #  -  RRSIG : missing RRSIG for key alg,
    #      bad sig,
    #      bad inception and
    #      bad expiration
    "RRSet (www.tjeb.nl, AAAA) failed verification : Signature record not in validity period, tag = 1390",
    "RRSet (www.tjeb.nl, NSEC) failed verification : Signature record not in validity period, tag = 1390",
    "Inception error for www.tjeb.nl, NSEC : Signature inception is 1275722596, time now is",
    "RRSIGS should include algorithm RSASHA1 for not.there.tjeb.nl, A, have :",
    "non-DNSSEC RRSet A included in Output that was not present in Input : not.there.tjeb.nl.	3600	IN	A	1.2.3.4",
    "RRSet (not.there.tjeb.nl, A) failed verification : No signatures in the RRSet : not.there.tjeb.nl, A, tag = none",
    "contains invalid RR : tjeb.nl.", # DNSKEY
    "No DNSKEY RR with SEP bit set in output zone",


    # Now check the NSEC specific stuff
    # - NSEC3 and NSEC3PARAMs in zone
    # - missing NSEC RR for one domain
    # - wrong ttl for one NSEC
    # - missing and extra RR types for one NSEC
    # - extra NSEC for closed loop of each next domain
    # - missing NSEC for closed loop of each next domain
      "NSEC3PARAM RRs included in NSEC-signed zone",
      "Output zone does not contain out of zone non-DNSSEC RRSet : A, ff.wat.out.of.zones.	143	IN	A	123.123.123.123",
      "No NSEC record for tjeb.nl",
      "NSEC record should have SOA of 3600, but is bla.tjeb.nl.	360	IN	NSEC	dragon.tjeb.nl ( NS RRSIG NSEC )",
      "NSEC includes A which is not in rrsets for dragon.tjeb.nl",
      "RRSIG  types not in NSEC for dragon.tjeb.nl",
      "RRSet (dragon.tjeb.nl, NSEC) failed verification : Signature failed to cryptographically verify, tag = 1390",
      "RRSIGS should include algorithm RSASHA1 for not.there.tjeb.nl, NSEC, have :",
      "RRSet (not.there.tjeb.nl, NSEC) failed verification : No signatures in the RRSet : not.there.tjeb.nl, NSEC, tag = none",
      "Can't follow NSEC loop from www.tjeb.nl to tjeb.nl",
      "Some NSEC records left after folowing closed loop. Details : not.there.tjeb.nl.	3600	IN	NSEC	really.not.there.tjeb.nl ( NSEC A ), End of extra NSEC list"
    ]
    remaining_strings.reverse.each {|line|
      expected_strings.each {|expected|
        if (line.index(expected))
          remaining_strings.delete(line)
          expected_strings.delete(expected)
          break
        end
      }
    }
    success = true
    expected_strings.each {|string|
      print "Couldn't find expected error : #{string}\n"
      success = false
    }
    remaining_strings.each {|line|
      print "Got unexpected error : #{line}\n"
      success= false
    }
    assert(success, "NSEC bad file not audited correctly")
  end

  def test_bad_file_nsec3
    # Get a known-bad zone file 
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr) 


    remaining_strings = []
    while (line = stderr[0].gets)
      remaining_strings.push(line)
    end
    expected_strings = [ # @TODO@ NSEC3 error strings!
    ]
    remaining_strings.reverse.each {|line|
      expected_strings.each {|expected|
        if (line.index(expected))
          remaining_strings.delete(line)
          expected_strings.delete(expected)
          break
        end
      }
    }
    success = true
    expected_strings.each {|string|
      print "Couldn't find expected error : #{string}\n"
      success = false
    }
    remaining_strings.each {|line|
      print "Got unexpected error : #{line}\n"
      success= false
    }
    assert(success, "NSEC3 bad file not audited correctly")
    # Now check the NSEC3 specific stuff
    # - @TODO@ extra NSEC record in zone
    # - @TODO@ two NSEC3PARAMs (one with bad flags and bad hash and salt)
    # - @TODO@ bad NSEC3 - wrong RR types (missing and extra)
    # - @TODO@ extra next_hashed on one NSEC3
    # - @TODO@ one next_hashed NSEC3 missing
    # - @TODO@ opt-out : insert extra NSEC3 for fictional record between NSEC3 and next_hashed
    #
  end

  #  def test_partial_scan_good
  #    fail "Implement good partial scanning test!"
  #    # @TODO@ Is there any need for NSEC(3) versions of these partial test methods?
  #    # Not really - just go with the first type of NSEC(3) seen, and run RR type checks
  #  end
  #
  #  def test_partial_scan_bad
  #    fail "Implement bad partial scanning test!"
  #  end

  def run_auditor_with_syslog(path, filename, stderr, expected_ret = nil)
    runner = Runner.new

    pid = fork {
      stderr[0].close
      STDERR.reopen(stderr[1])
      stderr[1].close

      options = Syslog::LOG_PERROR | Syslog::LOG_NDELAY

      Syslog.open("auditor_test", options) {|syslog|
        ret = runner.run_with_syslog(path, filename, syslog)
      }
      exit!(ret)
    }
    stderr[1].close
    Process.waitpid(pid)
    ret_val = $?.exitstatus
    if (expected_ret)
      assert_equal(expected_ret, ret_val, "Expected return of 0 from successful auditor run")
    else
      assert(ret_val != 0, "Expected error return from auditor")
    end
  end
end
