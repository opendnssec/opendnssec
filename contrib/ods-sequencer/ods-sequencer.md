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

General Installation Guide
==========================

A typical installation from source can be achieved using:

./configure \
  --prefix=/usr --sysconfdir=/etc --localstatedir=/var --mandir=/usr/man \
  --without-cunit --with-readline
make install

Various operating system distributions use different paths.  This

Then perform a basic installation of 



- installation from source
  - get package
  - configure
  - make, make install
  - post installation preparation
    - user

# Installation from source

Fetch the sources from:
    <URL:https://dist.opendnssec.org/source/testing/opendnssec-2.0.0a6.tar.gz>
Verify the integrity of the distribution using one of the three commands:
* sha256sum opendnssec-2.0.0a6.tar.gz
* sha1sum opendnssec-2.0.0a6.tar.gz
* gpg --verify opendnssec-2.0.0a6.tar.gz.sig

These three should result respectively in:
* "SHA256(opendnssec-2.0.0a6.tar.gz)= 4da0bca47e8d17099a69f10d27f22fb3616fb8c6c2d361301ddf0dfeb0d89758";
* "SHA1(opendnssec-2.0.0a6.tar.gz)= f71a413936dd3f03b80c550bdefe0dde9a73e6b0";
* exit with a success (ie. with a zero execution status).

In order to use GPG you should first have imported the PGP
public signing key of OpenDNSSEC.  This needs to be performed
only once for any future download.  Obtain the PGP public key
from <URL:https://wiki.opendnssec.org/display/OpenDNSSEC/PGP>, in
the quotation box of the most recent distribution key on that page.
Save the key to a file named "opendnssec.asc" and import it
using "gpg --import opendnssec.asc".

OpenDNSSEC is build using automake/autoconf, and thus includes a configure
script to detect the right compilation requirements and configure any
options if needed.  Different operating system distributions and different
requirements may apply.  Therefor there is no one right configuration,
one possible way of configuration would be to install the package as
root using:

    ./configure \
      --prefix=/usr --sysconfdir=/etc --localstatedir=/var --mandir=/usr/man \
      --without-cunit --with-readline
    make install

# Installation as non-root

This installation procedure was performed as root in order to install
everything in the root installation path.  If you wish, you can also install
OpenDNSSEC in some alternate location as a normal user.  There is however a
better solution to install program as root, but have a separate user and group
to control OpenDNSSEC.  With this OpenDNSSEC would initially still be
installed as root with "/" as the main prefix installation path.  But now an
additional user and group are created to use OpenDNSSEC.  You can start the
OpenDNSSEC daemons from the start-up sequencs, and instruct it to lower its
priviledges to this user.

Create an additional unix group to manage opendnssec.  Users which are
members of this group can access the important files and make changes.
We suggest the name "ods" (or "opendnssec") for this.

Under generic Linux this could be accomplished using:

    groupadd ods

Create an additional user to own the important files.  We suggest the
name "ods" (or "opendnssec").  Again under generic Linux this can be
accomplished using:

    useradd --no-create-home --base-dir /var/opendnssec --gid ods \
      --no-log-init --no-create-home --shell /sbin/nologin ods

This user will not directly be used, so you need to actively make other
users member of this group in order to continue.

Now limit the access to OpenDNSSEC to users of the just created group:

    chown -R ods:ods /etc/opendnssec /var/opendnssec \
                     /var/run/opendnssec /usr/bin/ods-* /usr/sbin/ods-*
    chmod -R ug+rwX,o-rwx /etc/opendnssec /var/opendnssec \
                     /var/run/opendnssec /usr/bin/ods-* /usr/sbin/ods-*

Make sure the ods user has access to the PKCS#11 key repository.
Failing to do so will not give any immediate errors, but your zones will
never get signed.  OpenDNSSEC will endlessly keep attempting to access
the interface.

# Initial configuration

First make sure your PKCS#11 implementation is installed, accessible and
initialized.  Both SoftHSM version 1 and 2 may be used with OpenDNSSEC 2,
see also the notes on SoftHSM.

We now assume you have installed OpenDNSSEC and a suitable PKCS#11
with the root directory as installation path.  This means that the main
configuration files go into /etc/opendnssec and the working directory
where OpenDNSSEC saves state is in /var/opendnssec.  Now OpenDNSSEC is
installed, you need a basic configuration set-up.

## Initial configuration conf.xml

The primary configuration file is conf.xml.  There may have been a sample
configuration file pre-installed or one available as conf.xml.sample.
Most configuration is suitable for first use, for details see the
OpenDNSSEC wiki.

The following items do however need checking or amending.

The Configuration/RepositoryList/Repository item needs to match your
PKCS#11 infrastructure.  PKCS#11 interfaces are delivered as shared
libraries that can either be directly linked or dynamically loaded into
the user application.  OpenDNSSEC uses the latter and therefor needs
to know the exact path to the dynamic library that it needs to load.
PKCS#11 interfaces manage multiple stores, protected with a PIN number.
It therefor needs to know the Label (not slot-id) and the PIN number
to use.  When using SoftHSM these should match with the arguments given
to initialize the token store.

Multiple Repository items may be declared.  In the kasp.xml configuration
files they will later be referred by with the name attribute of the
Repository tag.
Each Repository item should define at least:
* Module -- a full path to the shared library (e.g.
  /usr/lib/softhsm/libsofthsm.so or /usr/lib/softhsm/libsofthsm2.so
  for SoftHSM1 and SoftHSM2 respectively);
* TokenLabel -- the name of the token (as specified with the --label
  attribute when initializing SoftHSM)
* PIN -- the user PIN number (not the security officer PIN) to access
  the token store
Other arguments are often not necessary, refer to limited storage
capabilities and can be changed later.

When having installed OpenDNSSEC as root, but using it is non-root,
you should specify the unix user and group name to use.  This allows
for OpenDNSSEC to be started from a startup script on computer restart,
where it will be started with root privileges changing these to the right
credentials.  Failing to do so while still using OpenDNSSEC as root will
give very unexpected results.  Both Configuration/Enforcer/Privileges
and Configuration/Signer/Privileges need to be changed to the same
configuration to indicate the right unix user and group to use.

Configuration/Signer/WorkerThreads should be set to the number of
processor cores to use when signing.  Set this to parallelism available
in your PKCS#11 infrastructure for maximum performance.  When using
SoftHSM this will be equivalent to the number of processor cores.

Other parameters do not need changing at this time.  This gives you
a basic set-up with using file-based zone files without connecting to
other name servers.  It is good to be familiar with this set-up first.

## Initial configuration  addns.xml

File based zone-files without interfacing directly with other name
servers will not require anything from this configuration file.

## Initial configuration zonelist.xml

This file specifies pre-loading of zones.  We now strongly suggest NOT
editing this file yourself ever but using the command line interface to
add zones.  The sample zonelist.xml file should essentially be empty.

## Initial configuration kasp.xml

The key and signing policy file needs to be present and we advice to have
a policy named "default" in there.  The policy dictates how OpenDNSSEC
will behave, when to sign, how to sign, when to change signing keys,
etcetera.  Nearly all parameters will depend on your own needs, therefor
there are no true defaults or guidelines that can be given.

# First time initialization and first start-up

After a minimal of initial configuration, the enforcer database of
OpenDNSSEC needs initialization using:
    ods-enforcer-db-setup
Do not run this command as root when using an alternate user for
further use.

OpenDNSSEC can now be started using
    ods-control start
Policy, zonelist and PKCS#11 files are not loaded automatically.
Initially they need to be loaded using
    ods-enforcer update all

A common mistake would be to think that re-running ods-enforcer-db-setup
would reset the installation.  This is not true as there is still state
kept by the signer.

# Some notes on using SoftHSM

It is outside of the scope of OpenDNSSEC on how to install and
configure the PKCS#11 infrastructure.  Since SoftHSM may be used for
quick installations and testing purpose we provide some hints here.
Both SoftHSM versions 1 and 2 are suitable for OpenDNSSEC, where the
former is better tested at this time.

A common mistake is to initialize SoftHSM as root and then using it as
a different user.  This may give very unexpected results.

For SoftHSM2, when not using OpenDNSSEC as root, remember to change the
ownership of /var/lib/softhsm/tokens to the appropriate user, and have
the configuration file /etc/softhsm2.conf readable for this user.
First time initialization of the token store is performed using the
softhsm2-util command.

    chown -R ods:ods /etc/softhsm2.conf /var/lib/softhsm/tokens
    chmod -R ug+rwX,o-rwx /etc/softhsm2.conf /var/lib/softhsm/tokens
    chmod -R g+s /var/lib/softhsm/tokens
    sudo -u ods softhsm2-util --init-token --label OpenDNSSEC --pin 1234 --so-pin 0000 --slot 0

Note that failing to run softhsm2-util as user ods will give equal
unexpected results.  Token label and pin number will be referenced
from the opendnssec conf.xml configuration file, so these must match up.
You might want to store ZSKs and KSKs separately.  If so, perform multiple
initializations with unique labels and slots specified.

SoftHSM 2 is very picky in ownership of files.  This places a demand
on OpenDNSSEC, where you always need to start OpenDNSSEC daemons as the
target ods user.  So always use "sudo -u ods ods-control start"
Other commands may be given as any user that is member of group ods.
