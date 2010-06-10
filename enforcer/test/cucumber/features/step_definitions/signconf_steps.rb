require 'rexml/document'
include REXML
require 'xsd/datatypes'

START_OFFSET = 45

# @TODO@ ADD KSK STATES!! e.g. ds-seen, etc.

def load_keys_for(zone)
  # Load the Keys element from the zone's signconf file
  # @TODO@ Need to fix up relative location of signconf file in sandbox
  @@current_keys = {} if !@@current_keys
  @@previous_keys = {} if !@@previous_keys
  begin
    File.open("tmp/" + zone+".xml", 'r') {|file|
      doc = REXML::Document.new(file)
      e = doc.elements['SignerConfiguration/Zone/Keys/']
      # Store old keys and current keys here
      if (!@@key_states[zone] || (@@key_states[zone] == {}))
        load_first_key_states(zone, e)
      else
        get_new_key_states(zone, @@current_keys[zone], e)
      end
      @@previous_keys[zone] = @@current_keys[zone]
      @@current_keys[zone]=e

#      print e

 #     print_key_states(zone)

      print run_command("key list --zone #{zone} --verbose")
#      load_ksmutil_key_list(zone)
#  check_key_list_output_against_signconf(key_list_text)

      return e
    }
  rescue Errno::ENOENT
    return false
  end
end

Given /^I issue ds\-seen for all "([^\"]*)" KSKs in "([^\"]*)"$/ do |status, zone|
  key_list_text = run_command("key list --zone #{zone} --verbose")

  # Now process the KSKs -
  key_list_text.each_line {|line|
    if (line.split()[0] == zone)
      if (line.split()[1] == "KSK")
        if ((line.split()[2] == status) && line.index("waiting for ds-seen"))
          cka_id = line.split()[line.split().length - 3]
          print "Sending ds-seen for #{cka_id}\n"
          # Send the ds-seen for the key
          run_command("key ds-seen --zone #{zone} --cka_id #{cka_id}")
        end
      end
    end
  }
end


def check_key_list_output_against_signconf(key_list_text)
  # @TODO@ Check that the output of the key list tallies with the signconf.xml
end

def print_key_states(zone)
      # Print out current key_states
      @@key_states[zone].each {|key, data|
        print "Key #{key} is in #{data[0]} state, #{data[1]}, type = #{data[2]}\n"
      }
end

def load_first_key_states(zone, key_elements)
  # This is the first time we have run - load in the key states
  @@key_states[zone] = {}
  key_elements.elements.each('Key') {|key_element|
    id = get_cka_id_from_key_element(key_element)
    state = get_state_from_key_element(key_element)
    flags = get_flags_from_key_element(key_element)
    zsk_ksk = "ZSK"
    if (flags == 257)
      zsk_ksk= "KSK"
    end
    @@key_states[zone][id] = [state, "new", zsk_ksk]
  }
end

def get_new_key_states(zone, old_keys, new_keys)
  @@key_states == {} if !@@key_states
  @@key_states[zone] = {} if !@@key_states[zone]
  # @@key_states['Zone1'] = {key1 -> ["active", "new", "KSK"], key2 -> ["retired", "old", "ZSK"]}

  # Work out new key states!!
  # Compare last and new keys, and
  # generate list of keys in zone, along with their current state, and
  # whether they have newly entered that state.

  # If any keys have been removed from the zone, then keep them in a "removed" state for one cycle

  # How do we identify keys? Best to use CKA_ID - otherwise known as "Locator" in SignConf

  # So, look at each key in key_states, and see how it has changed (or been removed)
  # If key has not changed, then turn status to "old" - otherwise, to "new"
  @@key_states[zone].each {|key, data|
    # If key state is "removed", then remove the key from the list
    if (data[0] == "removed")
      @@key_states[zone].delete(key)
      next
    end
    # Find the key in new_keys
    state = find_state_from_key_element(key, new_keys)
    if (!state)
      # If we can't find it, then mark key "removed", "new"
      @@key_states[zone][key]=["removed", "new", data[2]]
      next
    end
    # Then, work out the current state of the key (need to use old state for this as well)
    # e.g. is the key retired or prepublished?
    if (state == "prepublished")
      # Should this be retired?
      if (data[0] != "prepublished")
        state = "retired"
      end
    end
    # And then update the current key_state
    # Is this old or new?
    new_or_old = "new"
    if (state == @@key_states[zone][key][0])
      new_or_old = "old"
    end
    @@key_states[zone][key]=[state, new_or_old, data[2]]
  }

  # See if there any newly-arrived keys we don't know about yet
  check_for_new_keys(zone, new_keys)
end

def check_for_new_keys(zone, new_keys)
  # If any keys are in new_keys that are not in old_keys, then process them too
  # Go through new_keys, and look at any which we can't find in @@key_states[zone]
  new_keys.elements.each('Key') { |key|
    cka_id = get_cka_id_from_key_element(key)
    if ((!(@@key_states[zone][cka_id])) || @@key_states[zone][cka_id] == [])
      # Add the key as "new" in the relevant state
      state = get_state_from_key_element(key)
      flags = get_flags_from_key_element(key)
      zsk_ksk = "ZSK"
      if (flags == 257)
        zsk_ksk= "KSK"
      end
      if (state != "prepublished") && (flags == 256)
        # It is an error to see a new ZSK in any state other than prepublished
        # (UNLESS this is the first run of the enforcer!) - which it will never be in this method
        raise Exception.new("Should never see new ZSK in any state other than prepublished")
      end
      @@key_states[zone][cka_id] = [state, "new", zsk_ksk]
    end
  }
end

def find_state_from_key_element(key, new_keys)
  new_keys.elements.each('Key') {|k|
    cka_id = get_cka_id_from_key_element(k)
    if (cka_id == key)
      # Found it - return the current state
      return get_state_from_key_element(k)
    end
  }
  return false
end

def get_flags_from_key_element(key)
  # Return the flags
  key.elements.each("Flags") {|f|
    return f.text.to_i
  }
end

def get_state_from_key_element(key)
  # Return the state ("prepublished", "active") element
  # Can only tell "retired" by comparing to previous state!
  ["ZSK", "KSK"].each {|zk|
    key.elements.each(zk) {|l|
      return "active"
    }
  }
  key.elements.each("Publish") {|l|
    return "prepublished"
  }
  return "removed"
end

def get_cka_id_from_key_element(key)
  # Return the Locator element
  key.elements.each("Locator") {|l|
    return l.text
  }
end

Given /^a clean DB setup$/ do
  Given "a new KASP database"
  # There is a need to keep track of the last set of keys seen in the signconf
  @@previous_keys = {}
  @@key_states = {}
  @@current_keys = {}
  @@start_time = Time.now.to_i + START_OFFSET
  @@last_time = Time.now.to_i + START_OFFSET
  set_enforcer_timeshift(Time.now)
end

Then /^I should see (\d+) (\w+) (\w+) (\w+) keys in the "([^\"]*)" signconf$/ do |num, new_old, keystatus, zsk_ksk, zone|

   count = 0
   @@key_states[zone].each {|key, data|
#     print "Checking #{data[0]} against #{keystatus}, #{data[1]} against #{new_old}, #{data[2]} against #{zsk_ksk}\n"
     if (data[2] == zsk_ksk)
       # We have the right type of key for the right zone.
       # Is it in the right state?
       if (data[0] == keystatus)
         # Yep - has it been that way for the right time?
         if (data[1] == new_old)
           count += 1
         end
       end
     end
   }
   count.should == num.to_i
end

Then /^I should not see keys in the "([^\"]*)" signconf$/ do |zone|
  keys = load_keys_for(zone)
  keys.should == false
end

def decode_time_interval(amount, units)
  amount = amount.to_i
  ret = amount
  ret = case units
  when "seconds" then amount
  when "second" then amount
  when "minutes" then amount * 60
  when "minute" then amount * 60
  when "hours" then amount * 3600
  when "hours" then amount * 3600
  when "days" then amount * 24 * 2600
  when "day" then amount * 24 * 2600
  when "week" then amount * 7 * 24 * 3600
  when "weeks" then amount * 7 * 24 * 3600
  when "month" then amount * 31 * 24 * 3600
  when "months" then amount * 31 * 24 * 3600
  when "year" then amount * 365 * 24 * 3600
  when "years" then amount * 365 * 24 * 3600
  end
  return ret
end

Given /^I move (\d+) ([^\"]*) into the ([^\"]*) from the start of the test$/ do |amount, units, direction|
  # Need to store the last time we were at before moving forward
  @@last_time = get_enforcer_timeshift
  timeshift_seconds = decode_time_interval(amount, units)
  print "Moving #{timeshift_seconds} from #{@@start_time}, real time : #{Time.now}\n"
  if (direction == "past")
    timeshift_seconds = -timeshift_seconds
  end
  new_time = Time.at(@@start_time + timeshift_seconds)
  set_enforcer_timeshift(new_time)
  Given "I run enforcer"
end

def set_enforcer_timeshift(new_time)
  ENV['ENFORCER_TIMESHIFT'] = new_time.year.to_s + ("%02d" % new_time.month) +
    ("%02d" % new_time.day) + ("%02d" % new_time.hour) +
    ("%02d" % new_time.min) + ("%02d" % new_time.sec)
  print "Setting time to #{ENV['ENFORCER_TIMESHIFT']}\n"
end

Then /^the keys should not have changed for "([^\"]*)" or "([^\"]*)", checked at (\d+) ([^\"]*) intervals$/ do |zone1, zone2, amount, units|
  check_zones_over_time(amount, units, zone1, zone2)
end

Then /^the keys should not have changed for "([^\"]*)", checked at (\d+) ([^\"]*) intervals$/ do |zone, amount, units|
  check_zones_over_time(amount, units, zone1)
end

Then /^the keys should not have changed now for "([^\"]*)"$/ do |zone|
  check_zones_over_time(1, "second", zone)
  @@last_time = get_enforcer_timeshift
end

Then /^the keys should not have changed now for "([^\"]*)" or "([^\"]*)"$/ do |zone1, zone2|
  check_zones_over_time(1, "second", zone1, zone2)
  @@last_time = get_enforcer_timeshift
end

When /^I load new keys for "([^\"]*)"$/ do |zone|
  load_keys_for(zone)
end

def check_zones_over_time(*args)
  # Need to check from end of last check (or start of test) up until 'current' time
  amount = args[0]
  units = args[1]
  delta = decode_time_interval(amount, units)
  # Move from @@last_time to now in delta increments
  (@@last_time..get_enforcer_timeshift).step(delta) {|time_to_check|
    set_enforcer_timeshift(Time.at(time_to_check))
    run_enforcer
    args[2..args.length()].each {|zone|
      # Then test that the keys haven't changed
      # @TODO@ Could also check that @@key_states[zone] contains no "new" keys
      last_keys = @@previous_keys[zone]
      keys = load_keys_for(zone)
      if (keys.to_s != last_keys.to_s)
        print "Time : #{ENV['ENFORCER_TIMESHIFT']}\n"
        print "Checking #{keys} against #{last_keys}\n"
      end
      keys.to_s.should == last_keys.to_s
    }
  }
end

def get_enforcer_timeshift
  # Returns Time.now.to_i if ENV['ENFORCER_TIMESHIFT'] is not defined
  timeshift = ENV['ENFORCER_TIMESHIFT']
  # If environment variable not present, then ignore
  if (timeshift)
    # Change the time
    year = timeshift[0,4]
    mon = timeshift[4,2]
    day = timeshift[6,2]
    hour = timeshift[8,2]
    min = timeshift[10,2]
    sec = timeshift[12,2]

    return Time.mktime(year, mon, day, hour, min, sec).to_i
  end
  return Time.now.to_i + START_OFFSET
end
