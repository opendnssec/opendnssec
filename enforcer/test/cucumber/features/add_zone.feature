Feature: Add a new zone
  In order to be able to sign zones
  As a user
  I want to be able to add a zone to be signed

  Scenario: Check that a new database is empty
    Given a new KASP database
    Then I should not see "cucumber" in the "zone list" output
    And I should not see any zones in the KASP database

  Scenario: Check that a new zone can be added
    Given a new KASP database
    When I add a new zone "cucumber" with policy "default"
    Then I should see "cucumber" in the "zone list" output
    And I should not see "cucumber" in the "key list" output
    But I should not see "bskdjhs" in the "zone list" output
