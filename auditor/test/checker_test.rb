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
          "ERROR: test/kaspcheck_bad/invalid_conf.xml:15: element InvalidNode: Relax-NG validity error : Did not expect element InvalidNode there",
          "ERROR: test/kaspcheck_bad/invalid_conf.xml fails to validate",

          # If repository specifies capacity, it should be greater than 0
          "ERROR: test/kaspcheck_bad/invalid_conf.xml:11: element Capacity: Relax-NG validity error : Error validating datatype positiveInteger",
          "ERROR: test/kaspcheck_bad/invalid_conf.xml:11: element Capacity: Relax-NG validity error : Element Capacity failed to validate content",
          "ERROR: test/kaspcheck_bad/invalid_conf.xml:11: element Capacity: Relax-NG validity error : Type positiveInteger doesn't allow value '0'",

          # KASP errors
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
          "WARNING: In policy namedtwice,  M used in duration field for Signatures/InceptionOffset (P1M) in test/kaspcheck_bad/kasp.xml - this will be interpreted as 31 days",


          # # @TODO@ Uknown paths - e.g. HSM, chdir, etc.

          # Conf.xml checks
          # ---------------
          "Can't find DB file : test/does_not_exist",
          # User/groups exist
          "ERROR: Group shouldnt_be_here_blah does not exist",
          "ERROR: User lah_de_dah_dafffy_duck does not exist",

          # Multiple repositories of same type should have unique TokenLabels
          "ERROR: Multiple Repositories in test/kaspcheck_bad/conf.xml have the same Module (test/kaspcheck_bad/kasp.xml) and TokenLabel (OpenDNSSEC), for Repository anotherHSM",

          # Check that the shared library (Module) exists
          "ERROR: Module really/really/not/here/promise in Repository softHSM cannot be found",

          # Check if two repositories exist with the same name
          "ERROR: Two repositories exist with the same name (softHSM)",

          # Kasp.xml checks
          # ---------------

          # No policy named "default"
          "WARNING: No policy named 'default' in test/kaspcheck_bad/kasp.xml. This means you will need to refer explicitly to the policy for each zone",

          # Two policies with the same name
          "ERROR: Two policies exist with the same name (namedtwice)",

          # "Resign" should be less than "refresh"
          "ERROR: The Refresh interval (60 seconds) for registry Policy in test/kaspcheck_bad/kasp.xml is less than or equal to the Resign interval (120 seconds)",

          # "Default" and "denial" validity periods are greater than the "Refresh" interval
          "ERROR: Validity/Default (1 seconds) for registry policy in test/kaspcheck_bad/kasp.xml is less than the Refresh interval (60 seconds)",
          "ERROR: Validity/Denial (2 seconds) for registry policy in test/kaspcheck_bad/kasp.xml is less than or equal to the Refresh interval (60 seconds)",

          # Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period.
          "WARNING: Jitter time (43200 seconds) is large compared to Validity/Denial (2 seconds) for registry policy in test/kaspcheck_bad/kasp.xml",

          # Warn if the InceptionOffset is greater than ten minutes.
          "WARNING: InceptionOffset is higher than expected (2678400 seconds) for namedtwice policy in test/kaspcheck_bad/kasp.xml",

          # Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.
          "WARNING: Keys/PublishSafety (1 seconds) in registry policy in test/kaspcheck_bad/kasp.xml is less than 0.1 * TTL (3600 seconds)",
          "WARNING: Keys/RetireSafety (1 seconds) in registry policy in test/kaspcheck_bad/kasp.xml is less than 0.1 * TTL (3600 seconds)",

          # The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.
          "ERROR: In policy registry, incompatible algorithm (5) used for ZSK NSEC3 in test/kaspcheck_bad/kasp.xml - should be 6 or 7",
          "ERROR: In policy namedtwice, incompatible algorithm (7) used for ZSK NSEC in test/kaspcheck_bad/kasp.xml",
          "ERROR: In policy namedtwice, incompatible algorithm (7) used for KSK NSEC in test/kaspcheck_bad/kasp.xml",

          # If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).
          "ERROR: In test/kaspcheck_bad/kasp.xml, policy registry, serial type datecounter used but 720 re-signs requested. No more than 99 re-signs per day should be used with datecounter as only 2 digits are allocated for the version number",

          # The key strength should be checked for sanity - warn if less than 1024 or more than 4096
          "WARNING: Key length of 48 used for KSK in registry policy in test/kaspcheck_bad/kasp.xml. Should probably be 1024 or more",
          "WARNING: Key length of 6048 used for KSK in namedtwice policy in test/kaspcheck_bad/kasp.xml. Should probably be 4096 or less",

          # Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.
          "ERROR: Unknown repository (unknownHSM) defined for KSK in registry policy in test/kaspcheck_bad/kasp.xml",

          # Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.
          "WARNING: KSK minimum lifetime (31536000 seconds) is less than ZSK minimum lifetime (120960000 seconds) for namedtwice Policy in test/kaspcheck_bad/kasp.xml",

          # Check that the value of the "Serial" tag is valid.
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

