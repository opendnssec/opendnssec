AM_CFLAGS = -pedantic -Wall -I../include @CUNIT_INCLUDES@ @DB_INCLUDES@
bin_PROGRAMS = test
test_SOURCES = test.c test_database.c test_datetime.c test_dd_string.c test_di_string.c test_dq_string.c test_du_string.c test_keyword.c test_ksm_key.c test_ksm_key_delete.c test_ksm_parameter.c test_ksm_policy.c test_ksm_purge.c test_ksm_request.c test_ksm_update.c test_ksm_zone.c test_message.c test_routines.c test_routines_cunit.c test_routines_database.c test_string_util.c test_string_util2.c

test_LDFLAGS = @CUNIT_LIBS@ -L../src/.libs -lksm -lncurses