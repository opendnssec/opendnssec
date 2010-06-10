# MAKE SURE WE DON'T WIPE MAIN KASP.DB!!!!
CONF_XML = " -c c_conf.xml "
KSMUTIL_COMMAND = "ods-ksmutil" + CONF_XML
ENFORCER_COMMAND = "ods-enforcerd" + CONF_XML + "-1 "

def ksmutil(text)
  system(KSMUTIL_COMMAND + text)
end

def run_enforcer
  system(ENFORCER_COMMAND)
  sleep(2)
end

Given /^keys are generated for policy "([^\"]*)"$/ do |policy|
  ksmutil("key generate --interval PT2H  --policy \"#{policy}\" >& /dev/null")
  run_enforcer
end

Given /^keys are generated$/ do
  ksmutil("key generate --interval PT2H --policy \"default\"  >& /dev/null")
  run_enforcer
end

Given /^a new KASP database$/ do
  # Should remove all temp files : e.g. signconf.xml
  # Make tmp folder if not already there
  if !(File.exist?"tmp")
          FileUtils.mkdir_p("tmp")
  end
  system("rm tmp/*")
  system("cp c_zonelist.base.xml tmp/c_zonelist.xml")
  system("echo yes | #{KSMUTIL_COMMAND} setup >& /dev/null")
end

Given /^a new zone "([^\"]*)" with policy "([^\"]*)"$/ do |zone, policy|
  When "I add a new zone \"#{zone}\" with policy \"#{policy}\""
end

Given /^a new zone "([^\"]*)"$/ do |zone|
  When "I add a new zone \"#{zone}\" with policy \"default\""
end

Given /^"([^\"]*)" is issued$/ do |command|
  ksmutil(command)
end

When /^I create a new KASP database$/ do
  Given "I create a new KASP database"
end

When /^I sleep for (\d+ second)s$/ do |x|
  sleep(x.to_i)
end

When /^I run enforcer/ do
  run_enforcer
end

When /^I add a new zone "([^\"]*)" with policy "([^\"]*)"$/ do |zone, policy|
  # @TODO@ Relative path to signerconf
  ksmutil("zone add --zone #{zone} --policy #{policy} --signerconf #{Dir.pwd.to_s + File::SEPARATOR}tmp#{File::SEPARATOR}#{zone}.xml")
end

Then /^I should see "([^\"]*)" in the "([^\"]*)" output$/ do |text, command|
  check_command_output(true, text, command)
end

Then /^I should not see any zones in the KASP database$/ do
  Then "I should not see \"policy\" in the \"zone list\" output"
end

Then /^I should not see "([^\"]*)" in the "([^\"]*)" output$/ do |text, command|
  check_command_output(false, text, command)
end

def run_command(command)
  result = %x[#{KSMUTIL_COMMAND} #{command}]
  return result
end

def check_command_output(should_see, text, command)
  # check the output of zone list to see if the zone is there
  result = run_command(command)
  if should_see
    result.should include text
  else
    result.should_not include text
  end
end