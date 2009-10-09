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

  def test_broken_validation
          # RNG validation errors
          # ---------------------
    stderr = run_checker("ods-kaspcheck -c test/kaspcheck_bad/invalid_conf.xml")
    assert(check_output(stderr, [
          "ERROR: test/kaspcheck_bad/invalid_conf.xml:17: parser error : Opening and ending tag mismatch: Oops line 17 and Facility",
          "ERROR: 			<Syslog><Oops>local0</Facility></Syslog>",
          "CRITICAL: Can't understand test/kaspcheck_bad/invalid_conf.xml - exiting",
          "ERROR:" # Pointer to error in XML
        ]))
    stderr = run_checker("ods-kaspcheck -k test/kaspcheck_bad/invalid_kasp.xml -c test/kaspcheck_good/conf.xml")
    assert(check_output(stderr, [
          "ERROR: test/kaspcheck_bad/invalid_kasp.xml:12: element InvalidNode: Relax-NG validity error : Did not expect element InvalidNode there",
          "ERROR: test/kaspcheck_bad/invalid_kasp.xml fails to validate",
          "ERROR: Can't find Signatures/Jitter in default in test/kaspcheck_bad/invalid_kasp.xml"
        ]))
  end

  def test_bad_config
    stderr = run_checker("ods-kaspcheck -c test/kaspcheck_bad/conf.xml")
    # Fill in expected error strings here
    assert(check_output(stderr, [
          "ERROR: test/kaspcheck_bad/kasp.xml fails to validate",
          # General Checks
          # --------------
        
          # Duration checks in various elements in both files
          "WARNING: In Configuration Y used in duration field for Enforcer/Interval (P1Y) in test/kaspcheck_bad/conf.xml - this will be interpreted as 365 days",
          "WARNING: In policy default,  M used in duration field for Signatures/InceptionOffset (P1M) in test/kaspcheck_bad/kasp.xml - this will be interpreted as 31 days",


          # Uknown paths - e.g. HSM, chdir, etc.

          # Conf.xml checks
          # ---------------

          # @TODO@ User/groups exist

          # @TODO@ Multiple repositories of same type should have unique TokenLabels

          # @TODO@ If repository specifies capacity, it should be greater than 0

          # @TODO@ Check that the shared library (Module) exists

          # @TODO@ Check if two repositories exist with the same name

          # Kasp.xml checks
          # ---------------

          # @TODO@ No policy named "default"

          # @TODO@ Two policies with the same name

          # @TODO@ "Resign" should be less than "refresh"

          # @TODO@ "Default" and "denial" validity periods are greater than the "Refresh" interval

          # @TODO@ Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period.

          # Warn if the InceptionOffset is greater than ten minutes.
          "WARNING: InceptionOffset is higher than expected (2678400 seconds) for default policy in test/kaspcheck_bad/kasp.xml",

          # @TODO@ Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.

          # @TODO@ The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.

          # @TODO@ If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).

          # @TODO@ The key strength should be checked for sanity - warn if less than 1024 or more than 4096

          # @TODO@ Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.

          # @TODO@ Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.

          # @TODO@ Check that the value of the "Serial" tag is valid.
          "ERROR: test/kaspcheck_bad/kasp.xml:54: element Serial: Relax-NG validity error : Error validating value",
          "ERROR: test/kaspcheck_bad/kasp.xml:54: element Serial: Relax-NG validity error : Element Serial failed to validate content"
        ]))
  end

  def run_checker(command)
    stderr = IO::pipe
    pid = fork {
      stderr[0].close
      STDOUT.reopen(stderr[1])
      STDERR.reopen(stderr[1])
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

