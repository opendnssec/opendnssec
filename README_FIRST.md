This is a pre-release of the OpenDNSSEC software for the functionality of
Fast Updates.

Update 2018-12-04:
- Multiple concurrent fast updates and multiple concurrent output [AI]XFRs.
- Big fixes

Update 2018-11-13:
- Reading signed/state files from earlier 2.1 releases for migration
  purposes should now be functional.
- Signature expiration beyond 2038 was broken which is now fixed.

There are still significant parts of OpenDNSSEC that need work.  Tests for
signing a zone and producing valid output adding/removing and modifying
delegations in the input zone using the web-service calls and some other
general tests pass.  Some existing tests fail because of changes in output
and changes in operation which are hardly applicable.  However, the amount
of testing and code review is on a low level.

The following issues are open (non-exhaustive list):
- There is no signer command to force a full resign or clear zone contents;
  this is however in the making now;
- Key roll changes are not tested, but expected not to reuse signatures
  correctly.

The prerequisites to OpenDNSSEC have changed.  The following additional
dependencies are needed:
  libmicrohttpd  (<URL:https://www.gnu.org/software/libmicrohttpd/>)
  libjansson     (<URL:http://www.digip.org/jansson/>)
  libyaml        (<URL:https://pyyaml.org/wiki/LibYAML>)
These are normally available on normal distribution sites using yum, get-apt,
slackbuilds, etcetera.  There is no specific version needed.
Apart from these extra dependencies, there are no changes in building
OpenDNSSEC from source.

Migration

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
opendnssec.conf needs to be created in the signer directory, with the following
content:

  signer:
    output-statefile-period: #2
    output-zonefile-period: #5
    output-ixfr-history: 30

Which means that the statefile (a journal of all actions) will be recreated
every 2 runs, the full signed zone file will be created every 5 runs and IXFRs
for output will be retained for 30 serial increments.    

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

We are going for an improvement cycle and make a build every week on Tuesday
early morning.
