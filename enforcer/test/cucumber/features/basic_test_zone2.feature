Feature: BasicTest (Zone2) on ODS wiki passes successfully
    In order to ship OpenDNSSEC
    As a developer
    I want to know that the BasicTest passes

    Background:
        Given a clean DB setup
        And a new zone "Zone1" with policy "Policy1"
        And a new zone "Zone2" with policy "Policy2"
        And keys are generated for policy "Policy1"
        And keys are generated for policy "Policy2"
        And "update conf" is issued


Scenario: Check Zone2 at set times
      When I run enforcer
        And I load new keys for "Zone2"
        Then I should see 1 new active ZSK keys in the "Zone2" signconf
        And I should see 1 new active KSK keys in the "Zone2" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone2" signconf
        And I should see 0 new retired ZSK keys in the "Zone2" signconf
        And I should see 0 new retired KSK keys in the "Zone2" signconf

        Given I move 7 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        Then I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf

        Given I move 28 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 new active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new retired ZSK keys in the "Zone2" signconf

        Given I move 35 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 old retired ZSK keys in the "Zone2" signconf

        Given I move 49 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 2 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new removed ZSK keys in the "Zone2" signconf

        Given I move 56 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 new active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new retired ZSK keys in the "Zone2" signconf

        Given I move 63 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new prepublished ZSK keys in the "Zone2" signconf
        And I should see 1 old retired ZSK keys in the "Zone2" signconf

        Given I move 77 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 2 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new removed ZSK keys in the "Zone2" signconf

        Given I move 84 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 new active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new retired ZSK keys in the "Zone2" signconf

        Given I move 91 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 old retired ZSK keys in the "Zone2" signconf

        Given I move 105 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 2 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new removed ZSK keys in the "Zone2" signconf

        Given I move 112 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 new active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new retired ZSK keys in the "Zone2" signconf

        Given I move 119 minutes into the future from the start of the test
        And I load new keys for "Zone2"
        And I should see 1 old active KSK keys in the "Zone2" signconf
        And I should see 1 old active ZSK keys in the "Zone2" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone2" signconf
        Then I should see 1 new prepublished ZSK keys in the "Zone2" signconf


#    Scenario: Check enforcer every minute
#        When I run enforcer
#        And I sleep for 5 seconds
#        # @TODO@ Condense all this into a single step
#        Then I should see "Zone1" in the "zone list" output
#        And I should see "Zone1" in the "zone list" output
#        And I should see "Zone1" in the "key list" output
#        And I should see "Zone2" in the "key list" output

#        # @TODO@ Condense all this into a single step
#        And I should see 1 ZSK keys in the "Zone1" signconf
#        And I should see 1 KSK keys in the "Zone1" signconf
#        And I should see 1 prepublished keys in the "Zone1" signconf
#        And I should see 1 ZSK keys in the "Zone2" signconf
#        And I should see 1 KSK keys in the "Zone2" signconf
#        And I should see 1 prepublished keys in the "Zone2" signconf

## Next event happens in 7 minutes time. So check each minute for the next 6 minutes
## and make sure that the keys haven't changed
#        Given I move 6 minutes into the future from the start of the test
#        Then the keys should not have changed for "Zone1" or "Zone2", checked at 1 minute intervals

#        # Now check for the 7 minute thing - use absolute times
#        Given I move 7 minutes into the future from the start of the test
#        And I run enforcer
#        Then the keys should not have changed now for "Zone1" or "Zone2"
#        # @TODO@ Actually, they should!
#        # @TODO@ Write more tests!!
#        # @TODO@ Write a step to test that the same keys are maintained every X seconds between explicit checks at key change time.



  #  Scenario: Zone2 KSK
