# OpenDNSSEC

## Introduction

OpenDNSSEC was created as an open-source turn-key solution for DNSSEC. It
secures zone data just before it is published in an authoritative name server.

## More Information

More informnation can be found at the project website available at
http://www.opendnssec.org/ and on the development WIKI at
http://wiki.opendnssec.org/.

Information about announcements, bug reporting and mailing lists can be found
at http://www.opendnssec.org/support/.

## Dependencies

OpenDNSSEC depends on  a number of external packages:

- libxml2 (including xmllint)
- LDNS
- SQLite3

To run OpenDNSSEC, one must have at least one crypto module providing a PKCS#11
library, e.g. SoftHSM (http://www.opendnssec.org/softHSM)

The Auditor has some additional dependencies:

- Ruby
- rubygems
    - syslog
    - openssl
    - dnsruby
    - xsd/datatypes
    - rexml/document

When building from the source code repository, the following dependencies are
also needed:

- A Java runtime environment (JRE/JDK)

## Building from the source code respository

If the code is downloaded directly from the source code respository (git), you
have to prepare the configuration scripts before continuing with build:

1. Install automake, autoconf and libtool.
2. Run the command autogen.sh to build configure scripts etc.
