# $Id$

libexecdir= ${exec_prefix}/libexec/opendnssec

libexec_PROGRAMS= \
	sorter get_serial \
	nseccer nsec3er \
	signer_pkcs11 create_dnskey_pkcs11 \
	finalizer

sorter_SOURCES=			sorter.c util.c
get_serial_SOURCES=		get_serial.c util.c
nseccer_SOURCES=		nseccer.c util.c
nsec3er_SOURCES=		nsec3er.c util.c
signer_pkcs11_SOURCES=		signer_pkcs11.c util.c ldns_pkcs11.c
create_dnskey_pkcs11_SOURCES=	create_dnskey_pkcs11.c util.c ldns_pkcs11.c
finalizer_SOURCES=		finalizer.c util.c

signer_pkcs11_LDADD=		@PKCS11_MODULE@
create_dnskey_pkcs11_LDADD=	@PKCS11_MODULE@
