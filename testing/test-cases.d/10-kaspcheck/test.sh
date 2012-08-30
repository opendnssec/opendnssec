#!/usr/bin/env bash
#
# Test kaspcheck with different input files - some good, some bad
# This test case only runs kaspcheck, it does not run ods.

ods_reset_env &&

# 1) Test with a good set of xml files
log_this ods-kaspcheck-run-good ods-kaspcheck -c kaspcheck_good/conf.xml &&
log_grep ods-kaspcheck-run-good stdout "INFO: The XML in kaspcheck_good/conf.xml is valid" &&
log_grep ods-kaspcheck-run-good stdout "INFO: The XML in kaspcheck_good/zonelist.xml is valid" &&
log_grep ods-kaspcheck-run-good stdout "INFO: The XML in kaspcheck_good/kasp.xml is valid" &&

# 2) Test with a missing file
! log_this ods-kaspcheck-run-not-there ods-kaspcheck -c kaspcheck_bad/not_there.xml &&
log_grep ods-kaspcheck-run-not-there stderr 'failed to load external entity "kaspcheck_bad/not_there.xml"' &&
log_grep ods-kaspcheck-run-not-there stdout 'ERROR: unable to parse file "kaspcheck_bad/not_there.xml"' &&
log_grep ods-kaspcheck-run-not-there stdout 'ERROR: Configuration file (kaspcheck_bad/not_there.xml) does not exist' &&
log_grep ods-kaspcheck-run-not-there stdout 'ERROR: No location for kasp.xml set' &&

# 3) Test for RNG validation errors: bad form
! log_this ods-kaspcheck-run-bad-form ods-kaspcheck ods-kaspcheck -c kaspcheck_bad/bad_form_conf.xml -k kaspcheck_bad/bad_form_kasp.xml &&
log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_conf.xml:15: element InvalidNode: Relax-NG validity error : Did not expect element InvalidNode there" &&
log_grep ods-kaspcheck-run-bad-form stdout "ERROR: kaspcheck_bad/bad_form_conf.xml fails to validate" &&
# If repository specifies capacity, it should be greater than 0
# NOTE: the Relax-NG validity error strings are modified from the full output for solaris compatibility
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_conf.xml:11: element Capacity: Relax-NG validity error : Error validating datatype positiveInteger" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_conf.xml:11: element Capacity: Relax-NG validity error : Element Capacity failed to validate content" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_conf.xml:11: element Capacity: Relax-NG validity error : Type positiveInteger doesn't allow value '0'" &&
log_grep ods-kaspcheck-run-bad-form stderr "Error validating datatype positiveInteger" &&
log_grep ods-kaspcheck-run-bad-form stderr "Element Capacity failed to validate content" &&
log_grep ods-kaspcheck-run-bad-form stderr "Type positiveInteger doesn't allow value '0'" &&
# KASP errors
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:12: element Jitter: Relax-NG validity error : Type duration doesn't allow value 'bad_text'" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:12: element Jitter: Relax-NG validity error : Error validating datatype duration" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:12: element Jitter: Relax-NG validity error : Element Jitter failed to validate content" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:14: element InvalidNode: Relax-NG validity error : Did not expect element InvalidNode there" &&
log_grep ods-kaspcheck-run-bad-form stderr "Type duration doesn't allow value 'bad_text'" &&
log_grep ods-kaspcheck-run-bad-form stderr "Error validating datatype duration" &&
log_grep ods-kaspcheck-run-bad-form stderr "Element Jitter failed to validate content" &&
log_grep ods-kaspcheck-run-bad-form stderr "Did not expect element InvalidNode there" &&
log_grep ods-kaspcheck-run-bad-form stdout "kaspcheck_bad/bad_form_kasp.xml fails to validate" &&
# Bad serial
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:55: element Serial: Relax-NG validity error : Error validating value" &&
#log_grep ods-kaspcheck-run-bad-form stderr "kaspcheck_bad/bad_form_kasp.xml:55: element Serial: Relax-NG validity error : Element Serial failed to validate content" &&
log_grep ods-kaspcheck-run-bad-form stderr "Error validating value" &&
log_grep ods-kaspcheck-run-bad-form stderr "Element Serial failed to validate content" &&

# 4) Test for RNG validation errors: broken validation
! log_this ods-kaspcheck-run-bad-val ods-kaspcheck ods-kaspcheck -c kaspcheck_bad/invalid_conf.xml &&
log_grep ods-kaspcheck-run-bad-val stdout "INFO: The XML in kaspcheck_bad/invalid_conf.xml is valid" &&
log_grep ods-kaspcheck-run-bad-val stdout "INFO: The XML in kaspcheck_bad/zonelist.xml is valid" &&
log_grep ods-kaspcheck-run-bad-val stdout "ERROR: WorkingDirectory (kaspcheck_bad/nope/not/here) does not exist" &&
log_grep ods-kaspcheck-run-bad-val stdout "INFO: The XML in kaspcheck_bad/invalid_kasp.xml is valid" &&

# 5) Test for bad configuration data
! log_this ods-kaspcheck-run-bad-config ods-kaspcheck ods-kaspcheck -c kaspcheck_bad/conf.xml &&
log_grep ods-kaspcheck-run-bad-config stdout "INFO: The XML in kaspcheck_bad/conf.xml is valid" &&
log_grep ods-kaspcheck-run-bad-config stdout "INFO: The XML in kaspcheck_bad/zonelist.xml is valid" &&
log_grep ods-kaspcheck-run-bad-config stdout "INFO: The XML in kaspcheck_bad/kasp.xml is valid" &&
# General Checks
# --------------
# Duration checks in various elements in both files
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: In Configuration Y used in duration field for Enforcer/Interval (P1Y) in kaspcheck_bad/conf.xml - this will be interpreted as 365 days" &&
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: In policy namedtwice, M used in duration field for Signatures/InceptionOffset (P1M) in kaspcheck_bad/kasp.xml - this will be interpreted as 31 days" &&
# # @TODO@ Uknown paths - e.g. HSM, chdir, etc.
# Conf.xml checks
# ---------------
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: SQLite datastore (really/does_not_exist) does not exist" &&
# User/groups exist
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Group 'shouldnt_be_here_blah' does not exist" &&
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: User 'lah_de_dah_dafffy_duck' does not exist" &&
# Multiple repositories of same type should have unique TokenLabels
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Multiple Repositories (softHSM and anotherHSM) in kaspcheck_bad/conf.xml have the same Module (kaspcheck_bad/kasp.xml) and TokenLabel (OpenDNSSEC)" &&
# Check that the shared library (Module) exists
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Module (really/really/not/here/promise) does not exist" &&
# Check if two repositories exist with the same name
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Two repositories exist with the same name (softHSM)" &&
# Kasp.xml checks
# ---------------
# No policy named "default"
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: No policy named 'default' in kaspcheck_bad/kasp.xml. This means you will need to refer explicitly to the policy for each zone" &&
# Two policies with the same name
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Two policies exist with the same name (namedtwice)" &&
# "Resign" should be less than "refresh"
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: The Refresh interval (60 seconds) for registry Policy in kaspcheck_bad/kasp.xml is less than or equal to the Resign interval (120 seconds)" &&
# "Default" and "denial" validity periods are greater than the "Refresh" interval
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Validity/Default (1 seconds) for registry policy in kaspcheck_bad/kasp.xml is less than or equal to the Refresh interval (60 seconds)" &&
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Validity/Denial (2 seconds) for registry policy in kaspcheck_bad/kasp.xml is less than or equal to the Refresh interval (60 seconds)" &&
# Warn if "Jitter" is greater than 50% of the maximum of the "default" and "Denial" period.
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: Jitter time (43200 seconds) is large compared to Validity/Denial (2 seconds) for registry policy in kaspcheck_bad/kasp.xml" &&
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Jitter time (43200 seconds) is greater than the Default Validity (1 seconds) for registry policy in kaspcheck_bad/kasp.xml" &&
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Jitter time (43200 seconds) is greater than the Denial Validity (2 seconds) for registry policy in kaspcheck_bad/kasp.xml" &&
# Warn if the InceptionOffset is greater than ten minutes.
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: InceptionOffset is higher than expected (2678400 seconds) for namedtwice policy in kaspcheck_bad/kasp.xml" &&
# Warn if the "PublishSafety" and "RetireSafety" margins are less than 0.1 * TTL or more than 5 * TTL.
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: Keys/PublishSafety (1 seconds) is less than 0.1 \* TTL (3600 seconds) for registry policy in kaspcheck_bad/kasp.xml" &&
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: Keys/RetireSafety (1 seconds) is less than 0.1 \* TTL (3600 seconds) for registry policy in kaspcheck_bad/kasp.xml" &&
# The algorithm should be checked to ensure it is consistent with the NSEC/NSEC3 choice for the zone.
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: In policy registry, incompatible algorithm (5) used for ZSK NSEC3 in kaspcheck_bad/kasp.xml." &&
# If datecounter is used for serial, then no more than 99 signings should be done per day (there are only two digits to play with in the version number).
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: In kaspcheck_bad/kasp.xml, policy registry, serial type datecounter used but 720 re-signs requested. No more than 99 re-signs per day should be used with datecounter as only 2 digits are allocated for the version number" &&
# The key strength should be checked for sanity - warn if less than 1024 or more than 4096
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: Key length of 48 used for KSK in registry policy in kaspcheck_bad/kasp.xml. Should probably be 1024 or more" &&
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Key length of 6048 used for KSK in namedtwice policy in kaspcheck_bad/kasp.xml. Should be 4096 or less" &&
# Check that repositories listed in the KSK and ZSK sections are defined in conf.xml.
log_grep ods-kaspcheck-run-bad-config stdout "ERROR: Unknown repository (unknownHSM) defined for KSK in registry policy in kaspcheck_bad/kasp.xml" &&
# Warn if for any zone, the KSK lifetime is less than the ZSK lifetime.
log_grep ods-kaspcheck-run-bad-config stdout "WARNING: KSK minimum lifetime (31536000 seconds) is less than ZSK minimum lifetime (120960000 seconds) for namedtwice Policy in kaspcheck_bad/kasp.xml" &&
return 0

return 1
