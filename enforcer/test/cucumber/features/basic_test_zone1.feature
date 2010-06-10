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
        And I should see 1 "publish" KSK in key list for "Zone1"
        And I should see 1 "dssub" KSK in key list for "Zone1"

        Given I issue ds-seen for all "dssub" KSKs in "Zone1"
        And I move 5 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dspublish" KSK in key list for "Zone1"
        And I should see 1 "ready" KSK in key list for "Zone1"

        Given I issue ds-seen for all "ready" KSKs in "Zone1"
        Given I move 10 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 15 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        # standby key enters dsready state

        Given I move 20 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 0 new retired ZSK keys in the "Zone1" signconf
        And I should see 0 new retired KSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 25 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "publish" KSK in key list for "Zone1"

        Given I move 30 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "ready" KSK in key list for "Zone1"

        Given I issue ds-seen for all "ready" KSKs in "Zone1"
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"


        Given I move 35 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 40 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 45 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 50 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "publish" KSK in key list for "Zone1"

        Given I move 55 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "ready" KSK in key list for "Zone1"

        Given I issue ds-seen for all "ready" KSKs in "Zone1"
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 60 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"


        Given I move 65 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"


        Given I move 70 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 new prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

        Given I move 75 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 new active ZSK keys in the "Zone1" signconf
        And I should see 1 new retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 new active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "publish" KSK in key list for "Zone1"

       Given I move 80 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "ready" KSK in key list for "Zone1"

        Given I issue ds-seen for all "ready" KSKs in "Zone1"
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"


       Given I move 85 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old retired ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 2 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"
        And I should see 1 "retire" KSK in key list for "Zone1"

       Given I move 90 minutes into the future from the start of the test
        And I load new keys for "Zone1"
        Then I should see 1 old active ZSK keys in the "Zone1" signconf
        And I should see 1 old prepublished ZSK keys in the "Zone1" signconf
        And I should see 1 old active KSK keys in the "Zone1" signconf
        And I should see 1 "dsready" KSK in key list for "Zone1"
        And I should see 1 "active" KSK in key list for "Zone1"

