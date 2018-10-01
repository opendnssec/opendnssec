Testing tools
=============

A collection of testing tools suitable for testing, performance
measurement and evaluating OpenDNSSEC.  It targets testing OpenDNSSEC 2.x
itself, not an installation using OpenDNSSEC.

# libtestpkcs11

This is a drop-in replacement pkcs11 library for testing purposes.

It can forward all calls to a dynamically loaded SoftHSMv2 library
that is not visible for the original calling program.  However it can
delibrerately not forward the sign calls, but instead return a predictable
default value.

This can be used to:
- give predictable output
- speed up tests as signing takes most time
- give an upper-bound on the performance as it simulates an infinite
  speed HSM.
