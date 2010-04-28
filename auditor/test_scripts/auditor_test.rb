require 'test/unit'
require 'kasp_auditor.rb'
include KASPAuditor

@@root_path = ''
if ARGV[0]
  @@root_path = ARGV[0] 
end


# Use the good test data we have, and frig the system time.
class Time # @TODO@ Can't use this to test enable_timeshift
  class << self
    alias_method :original_now, :now
    def now
      if (!@start)
        @start = original_now.to_i
      end
      return 1245393132 + (original_now.to_i - @start)
    end
  end
end

class TestLogger
  def initialize(on)
    @vocal = on
  end
  def log(pri, msg)
    if (@vocal)
      print "#{pri}: #{msg}\n"
    end
  end
end

class AuditorTest < Test::Unit::TestCase

  def test_good_file_nsec
    # Get the auditor to check a known-good zone (with signatures set well into the future)
    # Make sure there are no errors

    path = "test/signer_test_good/"
    zonelist_filename = "zonelist_nsec.xml"
    kasp_filename = "kasp_nsec.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 0, "test/tmp")

    #    success = check_syslog(stderr, [])
    success = check_syslog(r, ["Auditor found no errors"])
    assert(success, "NSEC good file not audited correctly")
  end

  def test_good_file_nsec3
    path = "test/signer_test_good/"
    zonelist_filename = "zonelist_nsec3.xml"
    kasp_filename = "kasp_nsec3.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 0, "test/tmp")

    success = check_syslog(r, ["Auditor found no errors"
      ])
    assert(success, "NSEC3 good file not audited correctly")
  end

  def test_bad_file_nsec
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    path = "test/signer_test_bad/"
    zonelist_filename = "zonelist_nsec.xml"
    kasp_filename = "kasp_nsec.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 3, "test/tmp1")


    expected_strings = [
      "Auditor found errors - check log for details",
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
      "Signature lifetime too short - should be at least 657936300 but was 2219833",
      "Signature lifetime too short - should be at least 657936300 but was 633371846",
      # Taken out next warning, as we already have an error for expired RRSIG for this record
      #      "Signature expiration (962409629) for www.tjeb.nl, AAAA should be later than (the refresh period (120) - the resign period (60)) from now",
      "RRSIGS should include algorithm RSASHA1 for not.there.tjeb.nl, A, have :",
      "non-DNSSEC RRSet A included in Output that was not present in Input : not.there.tjeb.nl.	3600	IN	A	1.2.3.4",
      "RRSet (not.there.tjeb.nl, A) failed verification : No signatures in the RRSet : not.there.tjeb.nl, A, tag = none",
      "RRSet (tjeb.nl, RRSIG) failed verification : No RRSet to verify, tag = 1390",
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
      "Output zone does not contain out of zone RRSet : A, even.more.out.of.bailiwick.	143	IN	A	1.2.3.4",
      "No NSEC record for tjeb.nl",
      "NSEC record should have TTL of 3600 from zone policy //Zone/SOA/Minimum, but is bla.tjeb.nl.",
      "NSEC includes A which is not in rrsets for dragon.tjeb.nl",
      "RRSIG  types not in NSEC for dragon.tjeb.nl",
      "RRSet (dragon.tjeb.nl, NSEC) failed verification : Signature failed to cryptographically verify, tag = 1390",
      "RRSIGS should include algorithm RSASHA1 for not.there.tjeb.nl, NSEC, have :",
      "RRSet (not.there.tjeb.nl, NSEC) failed verification : No signatures in the RRSet : not.there.tjeb.nl, NSEC, tag = none",
      "Can't follow NSEC loop from www.tjeb.nl to tjeb.nl",
      "NSEC record left after folowing closed loop : not.there.tjeb.nl",
      "Can't follow NSEC loop from not.there.tjeb.nl to really.not.there.tjeb.nl",

      # Key lifetime tracking
      #      "Not enough prepublished KSKs! Should be 2 but have 0",
      "Not enough prepublished ZSKs! Should be 2 but have 0",

      "New KSK DNSKEY has incorrect algorithm (was RSASHA1) or alg_length (was 1024)"
      # @TODO@ Check SOA Serial == KEEP

      # @TODO@ Update online spec some time!
    ]
    success = check_syslog(r, expected_strings)
    assert(success, "NSEC bad file not audited correctly")
  end
  
  def test_bad_file_nsec3
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    path = "test/signer_test_bad/"
    zonelist_filename = "zonelist_nsec3.xml"
    kasp_filename = "kasp_nsec3.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 3, "test/tmp2")
  
    expected_strings = [ # NSEC3 error strings
      "Auditor found errors - check log for details",
      "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used",
      #   1. There are no NSEC records in the zone.
      "NSEC RRs included in NSEC3-signed zone",
      "RRSIGS should include algorithm RSASHA1-NSEC3-SHA1 for bla.tjeb.nl, NSEC",
      "RRSet (bla.tjeb.nl, NSEC) failed verification : No signatures in the RRSet : bla.tjeb.nl, NSEC",

      #   2. If an NSEC3PARAM RR is found:
      #         a There is only one NSEC3PARAM record in the zone, and it is present at the apex of the zone
      "Multiple NSEC3PARAM RRs for tjeb.nl",
      "NSEC3PARAM seen at ", #there subdomain : should be at zone apex",
      "RRSIGS should include algorithm RSASHA1-NSEC3-SHA1 for not.there.tjeb.nl, NSEC3PARAM, have :",
      "RRSet (not.there.tjeb.nl, NSEC3PARAM) failed verification : No signatures in the RRSet",
      #         b The flags field of the record must be zero.
      "NSEC3PARAM flags should be 0, but were 1",
      "NSEC3PARAM has wrong salt : should be beefff but was beef",
      "NSEC3PARAM has wrong iterations : should be 4 but was 5",
      "NSEC3PARAM has wrong algorithm : should be 2 but was ", # SHA-1",

      #         c Each NSEC3 record present in the zone has the same hash algorithm iterations and salt parameters.
      "NSEC3 has wrong salt : should be beefff but was dead",
      "NSEC3 has wrong salt : should be beefff but was beef",
      "NSEC3 has wrong iterations : should be 4 but was 10",
      "NSEC3 has wrong iterations : should be 4 but was 5",
      "NSEC3 has wrong algorithm : should be 2 but was", # SHA-1",
      "RRSet (cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl, NSEC3) failed verification : Signature failed to cryptographically verify",
      #
      #   3. Each NSEC3 record has bits correctly set to indicate the types of RRs associated with the domain.
      "expected  MX RRSIG at test.test.tjeb.nl (cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl) but found  A RRSIG",
      "Found RRs for not.there.tjeb.nl (52cd45tiauj3n8vs8vs4mvdsigb34leh.tjeb.nl) which was not covered by an NSEC3 record",
      "Found RRs for bla.tjeb.nl (dsr9s1udf6urti95hvhv1b04tooihn7a.tjeb.nl) which was not covered by an NSEC3 record",

      "SALT LENGTH IS 3, but should be 4",

      # empty nonterminals
      "Can't find NSEC3 for empty nonterminal there.tjeb.nl (should be nvst1l6p3svg11nc8i0upvgmd911mb7p.tjeb.nl",

      #
      #   4. The "Next Hashed Owner" name field contains the hash of another domain in the zone that has an NSEC3 record associated with it, and that the links form a closed loop.
      # - @TODO@ extra next_hashed on one NSEC3
      "Can't follow NSEC3 loop from cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl to aa35pgoisfecot5i7fratgsu2m4k23lu.tjeb.nl"
      #
      #   5. If an NSEC3 record does not have the opt-out bit set, there are no domain names in the zone for which the hash lies between the hash of this domain name and the value in the "Next Hashed Owner" name field.
      #   @TODO@ how do we test? Would need to find a domain whose hash was right... :-/
      #
    ]
    possible_strings = [ # If this is the first time the test is run on the system, then
      # errors will be generated for these newly-seen keys
      "New ZSK DNSKEY has incorrect algorithm (was RSASHA1-NSEC3-SHA1) or alg_length (was 1024)",

      "New KSK DNSKEY has incorrect algorithm (was RSASHA1-NSEC3-SHA1) or alg_length (was 2048)"


    ]
    success = check_syslog(r, expected_strings, true, possible_strings)
    assert(success, "NSEC3 bad file not audited correctly")
  end

  def test_partial_good_file_nsec
    # Get the auditor to check a known-good zone (with signatures set well into the future)
    # Make sure there are no errors

    path = "test/signer_test_good/"
    zonelist_filename = "zonelist_nsec.xml"
    kasp_filename = "kasp_nsec.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 0, "test/tmp", true)

    success = check_syslog(r, ["Auditor found no errors"])
    assert(success, "NSEC good file not audited correctly")
  end

  def test_partial_good_file_nsec3
    path = "test/signer_test_good/"
    zonelist_filename = "zonelist_nsec3.xml"
    kasp_filename = "kasp_nsec3.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 0, "test/tmp", true)

    success = check_syslog(r, ["Auditor found no errors"
      ])
    assert(success, "NSEC3 good file not audited correctly")
  end

  def test_partial_bad_file_nsec
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    path = "test/signer_test_bad/"
    zonelist_filename = "zonelist_nsec.xml"
    kasp_filename = "kasp_nsec.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 3, "test/tmp1", true)


    expected_strings = [
      "Auditor found errors - check log for details",
      "Signature lifetime too short - should be at least 657936300 but was 2219833",
      "Signature lifetime too short - should be at least 657936300 but was 633371846",
      "RRSet (www.tjeb.nl, AAAA) failed verification : Signature record not in validity period, tag = 1390",
      "RRSet (www.tjeb.nl, NSEC) failed verification : Signature record not in validity period, tag = 1390",
      "Inception error for www.tjeb.nl, NSEC : Signature inception is 1275722596, time now is",
      "RRSet (tjeb.nl, RRSIG) failed verification : No RRSet to verify, tag = 1390",
      "contains invalid RR : tjeb.nl.", # DNSKEY
      "Expected SOA RR as first record ",

      "NSEC3PARAM RRs included in NSEC-signed zone",
      "No NSEC record for tjeb.nl",
      "NSEC record should have TTL of 3600 from zone policy //Zone/SOA/Minimum, but is bla.tjeb.nl.",
      "NSEC includes A which is not in rrsets for dragon.tjeb.nl",
      "RRSIG  types not in NSEC for dragon.tjeb.nl",
      "RRSet (dragon.tjeb.nl, NSEC) failed verification : Signature failed to cryptographically verify, tag = 1390",

      # Key lifetime tracking
      #      "Not enough prepublished KSKs! Should be 2 but have 0",
      "Not enough prepublished ZSKs! Should be 2 but have 0",
      # @TODO@ Check SOA Serial == KEEP

      # We added the not.there.tjeb.nl record to the signed zone
      "Number of non-DNSSEC resource records differs : 23 in test/tmp1/tjeb.nl.unsorted, and 24 in test/signer_test_bad/signed_zones/tjeb.nl.nse",

      "New KSK DNSKEY has incorrect algorithm (was RSASHA1) or alg_length (was 1024)"
      # @TODO@ Update online spec some time!
    ]
    success = check_syslog(r, expected_strings)
    assert(success, "NSEC bad file not audited correctly")
  end

  def test_partial_bad_file_nsec3
    # Get a known-bad zone file
    # Make sure that all known errors are caught
    path = "test/signer_test_bad/"
    zonelist_filename = "zonelist_nsec3.xml.partial"
    kasp_filename = "kasp_nsec3_partial.xml"
    r = run_auditor_with_syslog(path, zonelist_filename, kasp_filename, 3, "test/tmp2", true)

    expected_strings = [ # NSEC3 error strings
      "Auditor found errors - check log for details",
      "Zone configured to use NSEC3 but inconsistent DNSKEY algorithm used",
      #   1. There are no NSEC records in the zone.
      "NSEC RRs included in NSEC3-signed zone",

      #   2. If an NSEC3PARAM RR is found:
      #         a There is only one NSEC3PARAM record in the zone, and it is present at the apex of the zone
      #         b The flags field of the record must be zero.
      "NSEC3PARAM flags should be 0, but were 1",
      "NSEC3PARAM has wrong iterations : should be 5 but was 4",
      "NSEC3PARAM has wrong algorithm : should be 1 but was 2",
      "NSEC3PARAM has wrong salt : should be beef but was beefff",
      "NSEC3PARAM seen at",
      "Multiple NSEC3PARAM RRs",


      #         c Each NSEC3 record present in the zone has the same hash algorithm iterations and salt parameters.
      "NSEC3 has wrong salt : should be beef but was dead",
      "NSEC3 has wrong iterations : should be 5 but was 10",
      "NSEC3 has wrong algorithm : should be 1 but was 2",
      "RRSet (cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl, NSEC3) failed verification : Signature failed to cryptographically verify",
      #
      #   3. Each NSEC3 record has bits correctly set to indicate the types of RRs associated with the domain.
      "NSEC3 includes MX which is not in rrsets for cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl",
      "A  types not in NSEC3 for cq435smap43lf2dlg1oe4prs4rrlkhj7.tjeb.nl",

      "SALT LENGTH IS 2, but should be 4",

      #
      #   4. The "Next Hashed Owner" name field contains the hash of another domain in the zone that has an NSEC3 record associated with it, and that the links form a closed loop.
      # - @TODO@ extra next_hashed on one NSEC3
      "NSEC3 record left after folowing closed loop : ht35pgoisfecot5i7fratgsu2m4k23lu.tjeb.nl"
    ]
    success = check_syslog(r, expected_strings)
    assert(success, "NSEC3 bad file not audited correctly")
  end

  def check_syslog(stderr, expected_strings, add_default_msg=true, optional_strings=[])
    remaining_strings = []
    stderr.each {|l|
      remaining_strings.push(l)
    }
    #    while (line = stderr[0].gets)
    #      remaining_strings.push(line)
    #    end
    if (add_default_msg)
      expected_strings.push("Auditor started")
      expected_strings.push("Auditor starting on tjeb.nl")
      expected_strings.push("Auditing tjeb.nl zone :")
      expected_strings.push("Finished auditing tjeb.nl zone")
    end
    remaining_strings.reverse.each {|line|
      expected_strings.each {|expected|
        if (line.index(expected))
          remaining_strings.delete(line)
          expected_strings.delete(expected)
          break
        end
      }
      optional_strings.each {|optional|
        if (line.index(optional))
          remaining_strings.delete(line)
          optional_strings.delete(optional)
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

  def run_auditor_with_syslog(path, zonelist_filename, kasp_filename, expected_ret, working, partial = false)
    path = @@root_path + path

    runner = Runner.new
    if (partial)
      runner.force_partial
    end

    ["test/tmp/tracker/tjeb.nl", "test/tmp1/tracker/tjeb.nl"].each {|f|
      begin
        File.delete(f)
      rescue Exception
      end
    }

    r, w = IO.pipe
    pid = fork {
      r.close
      $stdout.reopen w

      runner.force_partial if partial
      ret = runner.run_with_syslog(path + zonelist_filename, path + kasp_filename, TestLogger.new(false), working, working, 3600) # Audit all zones
      w.close
      exit!(ret)
    }
    w.close
    ret_strings = []
    r.each {|l| ret_strings.push(l)}
    Process.waitpid(pid)
    ret_val = $?.exitstatus
    assert_equal(expected_ret, ret_val, "Expected return of #{expected_ret} from successful auditor run")
    return ret_strings
  end

  def test_key_tracking
    # The auditor tracks which keys it has seen in zones it audits.
    # It tracks them as they are pre-published, used, and retired.
    # If the number of pre-published KSK or ZSKs is less than [ZSK, KSK]->Standby
    # then a warning is generated
    # Check that a single key (KSK or ZSK) is not active longer than
    # (KSK->Lifetime + Enforcer->Interval) or (ZSK->Lifetime + Enforcer->Interval)
    # Again, a warning is generated
    #
    # 
    # Exercise the KeyTracker in isolation - install a new cache, then call
    #    KeyTracker#process_key_data to process keys found during an auditor run.
    #    Then ensure that the cache has been rewritten correctly, and the
    #    expected errors written to syslog.
    begin
      File.delete("test/tmp/tracker/example.com.")
    rescue Exception
    end
    r, w = IO.pipe
    pid = fork {
      r.close
      $stdout.reopen w

      run_keytracker_tests(TestLogger.new(true))
      w.close
    }
    w.close
    ret_strings = []
    r.each {|l| ret_strings.push(l)}

    Process.waitpid(pid)

    # Now check stderr for error strings
    expected_strings=[
      # Not enough pre-published ZSK
      "Not enough prepublished ZSKs! Should be 2 but have 0",
      # Not enough pre-published KSK
      #      "Not enough prepublished KSKs! Should be 2 but have 0",
      # KSK too long in use
      "KSK 51902 in use too long - should be max 1 seconds but has been",
      # ZSK too long in use
      "ZSK 51901 in use too long - should be max 1 seconds but has been",
      # SOA serial checking
      "SOA serial has decreased - used to be 101 but is now 100",
      "Key (56013) has gone straight to active use without a prepublished phase"
    ]
    success = check_syslog(ret_strings, expected_strings, false)
    assert(success, "Keys not correctly tracked over time")
  end

  class FakeAnykey
    attr_accessor :algorithm, :alg_length, :standby, :lifetime
  end

  class FakeKeys
    attr_accessor :ttl, :ksks, :zsks
    def initialize
      @ksks = []
      @zsks = []
    end
  end

  def run_keytracker_tests(syslog)
    # Run the keytracker tests from within the created test environment

    # So, create some keys for testing
    ksk_key1 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::SEP_KEY|RR::DNSKEY::ZONE_KEY,
        :algorithm => 5, :key => "AAAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    key1 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "AAAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    key2 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "EBAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    key3 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "GEAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    key5011 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "BEAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    keynot5011 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "BEAAAAOhdFlVHeivG77Zos6htgLyIkBOn18ujX4Q7Xs6U7SDQdi6FBE5 OQ8754ppfuF3Lg1ywNLHQ5bjibquSG7TuCT6DWL3kw+hESYmWTeEev9K RnxqTA+FVIfhJaPjMh7y+AsX39b8KVQ32IYdttOiz30sMhHHPBvL4dLC 4eCQXwUbinHRWSnKpKDXwuaUUtQkPqkEc4rEy/cZ3ld408vMlcc73OcK t+ttJeyQR1dJ0LoYHvH0WBzIWg3jUPmz/hSWrZ+V2n0TISQz0qdVGzhJ vahGvRstNk4pWG1MjwVgCvnc18+QiEV4leVU7B4XjM9dRpIMzJvLaq+B d8CxiWvjpSu/"})
    sep_key = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5,
        :key => "AAAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})

    # Now load the (empty) cache for the zone, and fill it with data about a
    # fake audit in progress.

    config = KASPAuditor::Config.new(nil, nil, nil, nil, nil)
    # Set up values in the config so that warnings are generated when we
    # have long-running KSK/ZSK, or there are not enough pre-published ZSK/KSK
    keys = FakeKeys.new
    ksk = FakeAnykey.new
    ksk.standby = 2
    ksk.lifetime = 1
    zsk = FakeAnykey.new
    zsk.standby = 2
    zsk.lifetime = 1
    keys.zsks.push(zsk)
    keys.ksks.push(ksk)
    config.keys = keys
    config.audit_tag_present = true

    checker = KASPAuditor::KeyTracker.new("test/tmp", "example.com.", syslog, config, 0)
    assert(checker.cache.inuse.length == 0)
    assert(checker.cache.retired.length == 0)
    assert(checker.cache.prepublished.length == 0)

    checker.process_key_data([ksk_key1, key1, keynot5011, key3],
      [ksk_key1.key_tag, keynot5011.key_tag], 100, 1)
    assert(checker.cache.inuse.length == 2)
    assert(checker.cache.retired.length == 0)
    assert(checker.cache.prepublished.length == 2)

    checker.process_key_data([ksk_key1, key1, keynot5011, key5011],
      [key1.key_tag, ksk_key1.key_tag, key5011.key_tag], 101, 1)
    assert(checker.cache.inuse.length == 3)
    assert(checker.cache.retired.length == 1)
    assert(checker.cache.prepublished.length == 0)

    # Now sleep for over a second and check that the lifetime warnings
    # are emitted
    sleep(2.1)
    key5011.revoked = true
    checker.process_key_data([ksk_key1, key2, key5011, key1],
      [ksk_key1.key_tag, key2.key_tag, key1.key_tag], 100, 1)
    assert(checker.cache.retired.length == 1)
    assert(checker.cache.inuse.length == 3)
    assert(checker.cache.prepublished.length == 0)

  end

  def test_tracker_cache
    begin
      File.delete("test/tmp/tracker/example.com.")
    rescue Exception
    end
    checker = KASPAuditor::KeyTracker.new("test/tmp", "example.com.", nil, nil, 1)
    checker.last_soa_serial = 0
    cache = checker.cache
    time = Time.now.to_i
    k1 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5, :key => "AAAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    k2 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5, :key => "EBAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})
    k3 = RR.create({:name => "example.com.", :type => Types::DNSKEY,
        :protocol => 3, :flags => RR::DNSKEY::ZONE_KEY, :algorithm => 5, :key => "GEAAAAOlWEB+fCWSlxbuwvXf1zt2r6XqvuedrKVWzL+vRj+wy5tQyszg V9wwn+Re2xvlgn66fZs6j6sWylioJF9X5mlpWFkH6QU17CyMvWOMJY94 x/pXY1zjxx7WLUq46raOozQ+bOd2Zn2LzEJ0Sh9T8HXDwVVwsKjSaSx+ 7X5YSVMe3Q=="})

    cache.add_retired_key_with_time(k1, time)
    cache.add_inuse_key_with_time(k2, time)
    cache.add_inuse_key_with_time(k3, time)
    assert(checker.cache.retired.length == 1)
    checker.save_tracker_cache

    new_checker = KASPAuditor::KeyTracker.new("test/tmp", "example.com.", nil, nil,1)
    assert(new_checker.cache.retired.length == 1)
    assert(new_checker.cache.include_retired_key?(k1))
    assert(new_checker.cache.inuse.length == 2)
    assert(new_checker.cache.include_inuse_key?(k2))
    assert(new_checker.cache.include_inuse_key?(k3))
    assert(new_checker.cache.include_inuse_key?(k2))
    assert(new_checker.cache.include_inuse_key?(k3))
    assert(new_checker.cache.include_key?(k1))
    assert(new_checker.cache.include_key?(k2))
    assert(new_checker.cache.include_key?(k3))
    #    assert(new_checker.cache.retired_maybe.length == 0)
    assert(new_checker.cache.prepublished.length == 0)
    new_checker.cache.delete_retired_key(k1)
    new_checker.cache.delete_inuse_key(k2)
    new_checker.cache.delete_inuse_key(k3)
    new_checker.save_tracker_cache

    n_c = KASPAuditor::KeyTracker.new("test/tmp", "example.com.", nil, nil,1)
    assert(n_c.cache.prepublished.length == 0)
    assert(n_c.cache.inuse.length == 0)
    assert(n_c.cache.retired.length == 0)
  end
end
