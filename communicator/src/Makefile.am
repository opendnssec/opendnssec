AM_CFLAGS = -pedantic -Wall -I@KSM_INCLUDES@

bin_PROGRAMS = communicated
communicated_SOURCES = daemon.c daemon_util.c kaspaccess.c

keygend_LDFLAGS = -L@KSM_LIBS@ -lksm


EXTRA_DIST = *.h
