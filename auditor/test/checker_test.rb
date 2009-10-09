require 'test/unit'

class CheckerTest < Test::Unit::TestCase
  def test_good_config
    stderr = run_checker("ods-kaspcheck -c test/kaspcheck_good/conf.xml")
    assert(check_output(stderr, []))
  end

  def test_missing_files
    stderr = run_checker("ods-kaspcheck -c test/kaspcheck_bad/not_there.xml")
    assert(check_output(stderr, [
          'failed to load external entity "test/kaspcheck_bad/not_there.xml"',
          "ERROR: Can't find config file : test/kaspcheck_bad/not_there.xml", 
          "ERROR: KASP configuration file cannot be found"
        ]))
  end

  def test_bad_config
    stderr = run_checker("ods-kaspcheck -c test/kaspcheck_bad/conf.xml")
    # @TODO@ Fill in expected error strings here
    assert(check_output(stderr, [
          # RNG validation errors
          # ---------------------
          "ERROR: test/kaspcheck_bad/conf.xml:13: element UnknownNode: Relax-NG validity error : Did not expect element UnknownNode there",
          "ERROR: test/kaspcheck_bad/conf.xml fails to validate",
          "ERROR: test/kaspcheck_bad/kasp.xml:4: element BadNode: Relax-NG validity error : Did not expect element BadNode there",
          "ERROR: test/kaspcheck_bad/kasp.xml fails to validate",

          # General Checks
          # --------------
        
          # Duration checks in various elements in both files
          "WARNING: In Configuration Y used in duration field for Enforcer/Interval (P1Y) in test/kaspcheck_bad/conf.xml - this will be interpreted as 365 days",
          "WARNING: In policy default,  M used in duration field for Signatures/InceptionOffset (P1M) in test/kaspcheck_bad/kasp.xml - this will be interpreted as 31 days",


          # Uknown paths - e.g. HSM, chdir, etc.

          # Conf.xml checks
          # ---------------

          # User/groups exist

          # Multiple repositories of same type should have unique TokenLabels

          # If repository specifies capacity, it should be greater than 0

          # Check that the shared library (Module) exists

          # Check if two repositories exist with the same name

          # Kasp.xml checks
          # ---------------

          # No policy named "default"

          # Two policies with the same name

          # "Resign" should be less than "refresh"

          # "Default" and "denial" validity periods are greater than the "Refresh" interval

          # Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period.

          # Warn if the InceptionOffset is greater than ten minutes.
          "WARNING: InceptionOffset is higher than expected (2678400 seconds) for default policy in test/kaspcheck_bad/kasp.xml",

          # Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.

          # The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.

          # If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).

          # The key strength should be checked for sanity - warn if less than 1024 or more than 4096

          # Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.

          # Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.

          # Check that the value of the "Serial" tag is valid.

          "Finish writing checks!!"
        ]))
  end

  def run_checker(command)
    stderr = IO::pipe
    pid = fork {
      stderr[0].close
      STDOUT.reopen(stderr[1])
      stderr[1].close

      system(command)
      exit!
    }
    stderr[1].close
    Process.waitpid(pid)
    return stderr
  end

  def check_output(stderr, expected_strings)
    remaining_strings = []
    while (line = stderr[0].gets)
      remaining_strings.push(line)
    end
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
end

