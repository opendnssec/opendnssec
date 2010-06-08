Feature: BasicTest (zone1) on ODS wiki passes successfully
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

    Scenario: Check Zone1 at set times
      When I run enforcer
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
        And I should see 1 new active KSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf
        And I should see 0 new retired ZSK keys in the "Zone1" signconf
        And I should see 0 new retired KSK keys in the "Zone1" signconf

        Given I move 20 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 0 new retired ZSK keys in the "Zone1" signconf
        And I should see 0 new retired KSK keys in the "Zone1" signconf

        Given I move 25 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf

        Given I move 40 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf

        Given I move 45 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf

       Given I move 50 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf

       Given I move 65 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf

        Given I move 70 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf

       Given I move 75 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf

       Given I move 90 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
#        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf


