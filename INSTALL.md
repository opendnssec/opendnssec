General Installation Guide
==========================

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
