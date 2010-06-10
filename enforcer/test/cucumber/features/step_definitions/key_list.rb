# Support for the ods-ksmutil key list output for the cucumber enforcer testing

Then /^I should see (\d+) "([^\"]*)" KSK in key list for "([^\"]*)"$/ do |num, status, zone|
  # Get the key list output for the zone
  output = run_command("key list --zone #{zone}  --verbose")
  count = 0
  # Work out how many keys are of the requested status
  output.each_line {|line|
    if ((line.split().length > 3) && (line.split[1] == "KSK") && (line.split()[2] == status))
      count += 1
    end
  }
  count.should == num.to_i
end

