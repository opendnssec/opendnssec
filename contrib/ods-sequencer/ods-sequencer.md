Off-line KSK environments using ods-sequencer
=============================================

This tools allows you to run a signer instance that keeps a zone file
signed even with key-roll overs by replaying signer configurations
that have been pre-prepared earlier.  In this set-up, the function
of OpenDNSSEC will essentially be divided into two parts.  One secure
environment (the "bunker") that has full knowledge of the keys, will
sign the keyset and control the key roll-over.  This is primary the roll
of the enforcer in OpenDNSSEC, but there needs a signer from OpenDNSSEC
as well in order to sign the keyset of the zone.  Otherwise this bunker
environment does not contain the real zone data.

The actual zone signing is performed on the operational environment.
This environment needs access to the zone signing keys, but gets other key
information, amongst which the signed keyset from the bunker.  The same
information will also control how and when to perform key roll-overs.

This information does not need to be transferred life from bunker to
operational side, but can be preprepared in advance for a period of time,
and then a series of such signer configurations can be placed on the
operational side to be "played" out over the real passing of time.

The main installation of the bunker and operational environments is the
same as on a normal installation, there are only slight differences.

# Installation

First, you need from the source distribution the program
"plugins/ods-sequencer".  This is a special script that will take care
of the recording and play-back of signing scenarios.
Install it on both bunker and operational environments in a suitable
location such as "/usr/sbin".

On both sides create directory "/var/opendnssec/sequences", this directory
will contain the future scenarios.  This directory should be writable
by the user that will control OpenDNSSEC.
You should not place any files of your own here, the filenames in this
directory will have meaning.

On the operational side you probably later on will want to install
a periodic running call to ods-sequencer program to keep your signing
configuration up to date.  We suggest that you place it in the crontab of
the user controlling OpenDNSSEC.  We suggest running it every 10 minutes
or so.  It is not heavy program unless there are a lot of scenarios
to play.

    */10 * * * * /usr/sbin/ods-sequencer update

# Configuration

The KSK and ZSK will normally be distributed over two different HSMs /
PKCS#11 providers or stored in separate slots.  Within the bunker this
means that you need to define at least two Repository tags.  One for the
ZSKs and one for the KSKs.  As normal the TokenLabel and PIN should mirror
those when setting up the slots in your PKCS#11 environment.  The name
attribute of each repository tags does not really matter, but should be
the same as later referred to in the kasp.xml configuration file.

Example:
    <RepositoryList>
      <Repository name="KSKs">
        <Module>/usr/lib/softhsm/libsofthsm.so</Module>
        <TokenLabel>KSKs</TokenLabel>
        <PIN>1234</PIN>
      </Repository>
      <Repository name="ZSKs">
        <Module>/usr/lib/softhsm/libsofthsm2.so</Module>
        <TokenLabel>ZSKs</TokenLabel>
        <PIN>1234</PIN>
      </Repository>
    </RepositoryList>

The bunker environment needs some changes to the kasp.xml configuration
file as well.  Although the operational environment does not use the
kasp.xml configuration file at this time, we advice to keep configurations
in sync as much as possible.

There are two changes necessary.  One is the addition of a Keyset element
in KASP/Policy/Signatures/Validity/Keyset.  The validity elements here
define how long the signatures for normal RRs are valid, and how long
the validity of NSEC or NSEC3 RRs are valid.  These should be larger
then the TTLs for these type of records in your zone.  By default the
DNSKEY RR (the keyset) has the same validity period as specified by the
Default entry, but this set-up requires the validity period of DNSKEY
set records to be at least as large as the ZSK lifetime.  This because
DNSKEY RR will not get re-signed in the bunker.

For example:
    <KASP>
      <Policy name="default">
        ...
        <Signatures>
          ...
          <Validity>
            <Default>P1D</Default>
            <Denial>P3D</Denial>
            <Keyset>P2M</Keyset>
          </Validity>
        </Signatures>
        ...
        <Keys>
          ...
          <KSK>
            <Algorithm length="2048">7</Algorithm>
            <Lifetime>P1Y</Lifetime>
            <Repository>KSKs</Repository>
          </KSK>
          <ZSK>
            <Algorithm length="1024">7</Algorithm>
            <Lifetime>P1M</Lifetime>
            <Repository>ZSKs</Repository>
          </ZSK>
        </Keys>

Also notice the Repository tags define the separate repositories for
KSKs and ZSKs as specified in the conf.xml configuration file.

# Setting up both environments

You should not attempt to run the enforcer on the operational side.
Disabling /usr/sbin/ods-enforcerd by removing it or disabling
execution may be a good idea.  It is therefor also not needed to run
"ods-enforcer-db-setup" on the operational side.

Within the bunker environment now prepare the OpenDNSSEC environment to
sign your zone by adding it after heaving started the OpenDNSSEC daemons
using ods-control.  The best way to do this would be to execute:

  ods-enforcer zone add -z example.com -p default

See the OpenDNSSEC wiki for details. The ods-enforcer used to be called
ods-ksmutil, but its workings are essentially the same.  One major
difference it that the enforcer daemon needs to be running before
attempting to call ods-enforcer.

In case of new zones this will be all steps necessary, in case of existing
zones you need to transfer the zone keys into the HSM and bootstrap the
zone state further.

The installed ods-sequencer program needs a few modifiable parameters
to be checked.  Edit this script program and set the entry ZONE_NAME
to the zone name that you have added to the system.  At this time the
script can only handle one zone at the time.
This should be done in both bunker and operational environments.

At this time the bunker is ready for use.  Stop the OpenDNSSEC daemons.
Since we will now be playing out future scenarios, we should not use
ods-control start/stop at this time no more.  It is therefor necessary
not to include OpenDNSSEC in any auto startup sequence of the bunker
environment.  On the operational side you do want to include a start-up
of the signer daemon in the start up sequence.  Since enforcer should
not be started, you can use a call to "ods-signer start" in stead of
"ods-control start".

At this time the bunker environment is ready to use.  The operational
environment also needs to get information on the zones present.
Transfer the file /var/opendnssec/enforcer/zones.xml from the bunker
environment to the operational environment.  The normal unsigned
zone file (in case of file based zone files) would normally go into
/var/opendnssec/unsigned/example.com, but this is part of the normal
set-up of OpenDNSSEC.
This concludes the set-up of both environments.  

# Using ods-sequencer.

The operational environment is not yet able to sign the zones, it needs
instructions which keys are necessary for signing the zone.  In order
to prepare a future set of signing instructions for the operational
environment, you should log into the bunker environment.  You can now
use the command "ods-sequencer scenario" to generate a set of signing
scenarios.  It will take one additional argument which instructs the
program to generate scripts upto the specified time.  For example:

    ods-sequencer scenario 2020-01-01

Will generate (a lot) of signing scenarios upto the beginning of
year 2020.  These signing configurations (signconf's) are placed in
/var/opendnssec/sequences.
When running this command for the first time, it will use the current
time as starting point.  When having created previous snapshots, it will
take off from the last generated signing configuration.
You will notice the signing configurations generated in
    /var/opendnssec/sequences
are prefixed with a unix timestamp.  If you delete a series of signing
configurations at the end of this time-line, you can force the signer
to re-create a set of signing instructions.  This can be useful in
case of an emergency roll over, where you need to intervene and abort
a current scenario.

Transfer the /var/opendnssec/sequences directory from the bunker
environment to the operational environment and place it in the same
location.  Also replicate the ZSK PKCS#11 key repository from the bunker
environment to the operational environment.  It suffices to only replicate
the final key repository from a period to the operational side.

Run the program:
    ods-sequencer update
once and how start the OpenDNSSEC signer daemon using:
    ods-signer start

And it will have picked up the first signing configuration for your zone.
Now periodically run:
    ods-sequencer update
in order to keep the signing configuration up to date.
