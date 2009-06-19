require 'test/unit'
require 'lib/kasp_auditor.rb'
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
    assert_equal(nil, stderr[0].gets)
  end

  def test_good_file_nsec3
    stderr = IO::pipe
    path = "test/signer_test_good/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)

    # Check syslog to ensure no messages left while this test ran
    assert_equal(nil, stderr[0].gets)
  end

  def test_bad_file_nsec
    # @TODO@ Get a known-bad zone file (signed well into the future)
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec.xml"
    run_auditor_with_syslog(path, filename, stderr) # @TODO@ Expected return value?


    # Check syslog to ensure no messages left while this test ran
    syslog_string = stderr[0].gets
    # Make sure all the "auditor_test" strings are there
    assert(syslog_string=~/auditor_test/, "Should have written errors to syslog for bad NSEC")
    check_common_bad_data(stderr)
    # @TODO@ Now check the NSEC specific stuff
    # - NSEC3 and NSEC3PARAMs in zone
    # - missing NSEC RR for one domain
    # - wrong ttl for one NSEC
    # - missing and extra RR types for one NSEC
    # - extra NSEC for closed loop of each next domain
    # - missing NSEC for closed loop of each next domain
    #
  end

  def test_bad_file_nsec3
    # @TODO@ Get a known-bad zone file (signed well into the future)
    # Make sure that all known errors are caught
    stderr = IO::pipe
    path = "test/signer_test_bad/"
    filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr) # @TODO@ Expected return value?


    # Check syslog to ensure no messages left while this test ran
    syslog_string = stderr[0].gets
    # Make sure all the "auditor_test" strings are there
    assert(syslog_string=~/auditor_test/, "Should have written errors to syslog for bad NSEC3")
    check_common_bad_data(stderr)
    # @TODO@ Now check the NSEC3 specific stuff
    # - extra NSEC record in zone
    # - two NSEC3PARAMs (one with bad flags and bad hash and salt)
    # - bad NSEC - wrong RR types (missing and extra)
    # - extra next_hashed on one NSEC3
    # - one next_hashed NSEC3 missing
    # - opt-out : insert extra NSEC3 for fictional record between NSEC3 and next_hashed
    #
  end

  def check_common_bad_data(stderr)
    # @TODO@ Check the errors in the zone which are common to both NSEC and NSEC3
    #  - non dnssec data : missing data and extra data
    #  - bad SEP : no SEP flag set, and invalid key. Also bad protocol  and algorithm
    #  -  RRSIG : missing RRSIG for key alg, bad sig, bad inception and bad expiration
    #
    #

    stderr[0].lineno = 0 # Reset the log reader to the start so that the NSEC(3) stuff can be checked
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
        if (expected_ret)
          assert_equal(expected_ret, ret)
        end
      }
      exit!
    }
    stderr[1].close
    Process.waitpid(pid)
  end
end
