# Beta release of OpenDNSSEC Fast Updates

This is a pre-release of the OpenDNSSEC software for the functionality of
Fast Updates.

There are still significant parts of OpenDNSSEC that need work.  Tests for
signing a zone and producing valid output adding/removing and modifying
delegations in the input zone using the web-service calls and some other
general tests pass.  Some existing tests fail because of changes in output
and changes in operation which are hardly applicable.

Fast updates allow the signer to quickly sign zone changes, however
ath the current cost of a full zone initial resign and start up.  This
performance degredation is still under improvement.  The normal operation
of OpenDNSSEC is now faster.

## Building OpenDNSSEC

The prerequisites to OpenDNSSEC have changed.  The following additional
dependencies are needed:

  - libmicrohttpd  (<URL:https://www.gnu.org/software/libmicrohttpd/>)
  - libjansson     (<URL:http://www.digip.org/jansson/>)
  - libyaml        (<URL:https://pyyaml.org/wiki/LibYAML>)

These are normally available on normal distribution sites using yum, get-apt,
slackbuilds, etcetera.  There is no specific version needed.
Apart from these extra dependencies, there are no changes in building
OpenDNSSEC from source.

The actual building process hasn't changed much, it can still be
build using:

  sh autogen.sh
  ./configure --prefix=...
  make all
  make install

This pre-release of OpenDNSSEC now comes with real unit test framework
that allow for faster testing and does not involve a complicated
framework.  The number of tests is somehow limited and only involve the
signer, but better check the correct signing operation.
A working and accessible SoftHSM installation is however required.

Tests are run using:

  make check

The LDNS tools are required to perform full test run.
We do not expect a normal installation to run this.

## Migration

When OpenDNSSEC signer starts, it will try to read a new-style
state file per zone.  In case this is missing, is will try to read a 2.1
style state file and try to use that instead and produce a new style state
file.  Be sure to delete also the old-style state file when you delete
the new-style state file.
There are no changes in the configuration file nor in the signconf files
used by the communication between enforcer and signer.  Command line
interface has no changes.  Configurable parameters for the purpose
of the fast updates are configured in a separate configuration file,
or are fixed for the moment.  It is still under evaluation how these
parameters should be used.

The signer will perform a normal sign - write zone cycle as usual when
not explicitly configured.  This isn't suited for fast updates because
writing the whole zone file every time will take too long.  In order
to perform these tasks periodically, a separate configuration file
opendnssec.conf needs to be created next to the conf.xml configuration
(no longer in the signer directory), with the following content:

  signer:
    output-statefile-period: #2
    output-zonefile-period: #5
    output-ixfr-history: 30

Which means that the statefile (a journal of all actions) will be recreated
every 2 runs, the full signed zone file will be created every 5 runs and IXFRs
for output will be retained for 30 serial increments.    

Apart from providing this new configuration file, no explicit migration is
needed.  Downgrading isn't recommended at this time, without performing a
full resign and incrementing the SOA serial number explicitly.

## Using fast updates

The fast update webservice is enabled by default on port 8000.  An example
to perform an updates:

  deletes a delegation:
    curl --data '{ "apiversion": "20181001", "transaction": "CURL test",
                   "entities": [ ]}' \
      localhost:8000/api/v1/changedelegation/example.com./domain.example.com./
  add or change a delegation:
    curl --data '{ "apiversion": "20181001", "transaction": "CURL test",
                   "entities": [ {"name": "domein.example.com.", "type": "NS",
                                 "ttl": "600", "rdata": "ns.example.com.",
                                 "class" : "IN"}]}'
      localhost:8000/api/v1/changedelegation/example.com./domein.example.com./

