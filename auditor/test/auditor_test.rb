require 'test/unit'
require 'lib/kasp_auditor.rb'
include KASPAuditor

class AuditorTest < Test::Unit::TestCase
  def test_good_file_nsec
    # Get the auditor to check a known-good zone (with signatures set well into the future)
    # Make sure there are no errors

    stderr = IO::pipe
    path = "test/signer_test_good/"
      filename = "zonelist_nsec.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)


    # Check syslog to ensure no messages left while this test ran
    syslog_string = stderr[0].gets
    # Make sure there are no "auditor_test" strings there
    assert_equal(false, syslog_string=~/auditor_test/)
  end

  def test_good_file_nsec3
    stderr = IO::pipe
    path = "test/signer_test_good/"
      filename = "zonelist_nsec3.xml"
    run_auditor_with_syslog(path, filename, stderr, 0)


    # Check syslog to ensure no messages left while this test ran
    syslog_string = stderr[0].gets
    # Make sure there are no "auditor_test" strings there
    assert_equal(false, syslog_string=~/auditor_test/)
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
  end

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
