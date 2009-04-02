AM_CFLAGS = -pedantic -Wall -I@KSM_INCLUDES@

bin_PROGRAMS = keygend
keygend_SOURCES = daemon.c daemon_util.c keygend.c keygend_util.c kaspaccess.c

keygend_LDFLAGS = -L@KSM_LIBS@ -lksmlib


EXTRA_DIST = *.h
