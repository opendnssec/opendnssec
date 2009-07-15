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

    success = check_syslog(stderr, [])
    assert(success, "NSEC good file not audited correctly")
  end

  def test_good_file_nsec3
    stderr = IO::pipe
    path = "test/signer_test_good/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)

    success = check_syslog(stderr, ["Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used"])
    assert(success, "NSEC3 good file not audited correctly")
  end

  def test_bad_file_nsec
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec.xml"
    run_auditor_with_syslog(path, filename, stderr, 3)


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
      "RRSet (tjeb.nl, RRSIG) failed verification : No RRSet to veryify",
      "contains invalid RR : tjeb.nl.", # DNSKEY
      "Expected SOA RR as first record ",
      #    "No DNSKEY RR with SEP bit set in output zone", # Need this key - or else RRSIGs won't verify


      # Now check the NSEC specific stuff
      # - NSEC3 and NSEC3PARAMs in zone
      # - missing NSEC RR for one domain
      # - wrong ttl for one NSEC
      # - missing and extra RR types for one NSEC
      # - extra NSEC for closed loop of each next domain
      # - missing NSEC for closed loop of each next domain
      "NSEC3PARAM RRs included in NSEC-signed zone",
      "Output zone does not contain out of zone RRSet : A, ff.wat.out.of.zones.	143	IN	A	123.123.123.123",
      "No NSEC record for tjeb.nl",
      "NSEC record should have SOA of 3600, but is bla.tjeb.nl.	360	IN	NSEC	dragon.tjeb.nl ( NS RRSIG NSEC )",
      "NSEC includes A which is not in rrsets for dragon.tjeb.nl",
      "RRSIG  types not in NSEC for dragon.tjeb.nl",
      "RRSet (dragon.tjeb.nl, NSEC) failed verification : Signature failed to cryptographically verify, tag = 1390",
      "RRSIGS should include algorithm RSASHA1 for not.there.tjeb.nl, NSEC, have :",
      "RRSet (not.there.tjeb.nl, NSEC) failed verification : No signatures in the RRSet : not.there.tjeb.nl, NSEC, tag = none",
      "Can't follow NSEC loop from www.tjeb.nl to tjeb.nl",
      "NSEC record left after folowing closed loop : not.there.tjeb.nl",
      "Can't follow NSEC loop from not.there.tjeb.nl to really.not.there.tjeb.nl"
    ]
    success = check_syslog(stderr, expected_strings)
    assert(success, "NSEC bad file not audited correctly")
  end
  
  def test_bad_file_nsec3
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr, 3)
  
    expected_strings = [ # NSEC3 error strings
     "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used",
      #   1. There are no NSEC records in the zone.
      "NSEC RRs included in NSEC3-signed zone",
      "RRSIGS should include algorithm RSASHA1-NSEC3-SHA1 for bla.tjeb.nl, NSEC",
      "RRSet (bla.tjeb.nl, NSEC) failed verification : No signatures in the RRSet : bla.tjeb.nl, NSEC",

      #   2. If an NSEC3PARAM RR is found:
      #         a There is only one NSEC3PARAM record in the zone, and it is present at the apex of the zone
      "Multiple NSEC3PARAM RRs for tjeb.nl",
      "NSEC3PARAM seen at there subdomain : should be at zone apex",
      "RRSIGS should include algorithm RSASHA1-NSEC3-SHA1 for not.there.tjeb.nl, NSEC3PARAM, have :",
      "RRSet (not.there.tjeb.nl, NSEC3PARAM) failed verification : No signatures in the RRSet",
      #         b The flags field of the record must be zero.
      "NSEC3PARAM flags should be 0, but were 1",
      "NSEC3PARAM has wrong salt : should be beefff but was beef",
      "NSEC3PARAM has wrong iterations : should be 4 but was 5",
      "NSEC3PARAM has wrong algorithm : should be 2 but was SHA-1",

      #         c Each NSEC3 record present in the zone has the same hash algorithm iterations and salt parameters.
      "NSEC3 has wrong salt : should be beef but was dead",
      "NSEC3 has wrong iterations : should be 5 but was 10",
      "NSEC3 has wrong algorithm : should be SHA-1 but was",
      "RRSet (cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl, NSEC3) failed verification : Signature failed to cryptographically verify",
      #
      #   3. Each NSEC3 record has bits correctly set to indicate the types of RRs associated with the domain.
      #   @TODO@
      #
      #   4. The "Next Hashed Owner" name field contains the hash of another domain in the zone that has an NSEC3 record associated with it, and that the links form a closed loop.
      "Can't follow NSEC3 loop from cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl to aa35pgoisfecot5i7fratgsu2m4k23lu.tjeb.nl"
      #
      #   5. If an NSEC3 record does not have the opt-out bit set, there are no domain names in the zone for which the hash lies between the hash of this domain name and the value in the "Next Hashed Owner" name field.
      #   @TODO@ this should be easy to implement! But how do we test?
      #
    ]
    success = check_syslog(stderr, expected_strings)
    assert(success, "NSEC3 bad file not audited correctly")
    # Now check the NSEC3 specific stuff
    # - @TODO@ extra next_hashed on one NSEC3
    # - @TODO@ one next_hashed NSEC3 missing
    # - @TODO@ opt-out : insert extra NSEC3 for fictional record between NSEC3 and next_hashed
    #
  end

  def check_syslog(stderr, expected_strings)
    remaining_strings = []
    while (line = stderr[0].gets)
      remaining_strings.push(line)
    end
    expected_strings.push("Auditing tjeb.nl zone :")
    expected_strings.push("Finished auditing tjeb.nl zone")
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
    return success
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

  def run_auditor_with_syslog(path, filename, stderr, expected_ret)
    runner = Runner.new

    pid = fork {
      stderr[0].close
      STDERR.reopen(stderr[1])
      stderr[1].close

      options = Syslog::LOG_PERROR | Syslog::LOG_NDELAY

      Syslog.open("auditor_test", options) {|syslog|
        ret = runner.run_with_syslog(path, [], filename, syslog) # Audit all zones
      }
      exit!(ret)
    }
    stderr[1].close
    Process.waitpid(pid)
    ret_val = $?.exitstatus
    assert_equal(expected_ret, ret_val, "Expected return of #{expected_ret} from successful auditor run")
  end
end
