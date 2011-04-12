/* common/config.h.  Generated from config.h.in by configure.  */
/* common/config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if your setregid() is broken */
#define BROKEN_SETREGID 1

/* Define if your setresgid() is broken */
/* #undef BROKEN_SETRESGID */

/* Define if your setresuid() is broken */
/* #undef BROKEN_SETRESUID */

/* Define if your setreuid() is broken */
#define BROKEN_SETREUID 1

/* System cp(3) command */
#define CP_COMMAND "/bin/cp"

/* timeshift debug */
/* #undef ENFORCER_TIMESHIFT */

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have the `arc4random' function. */
#define HAVE_ARC4RANDOM 1

/* Define to 1 if you have the `arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the `atoi' function. */
#define HAVE_ATOI 1

/* Define to 1 if you have the `bzero' function. */
#define HAVE_BZERO 1

/* Define to 1 if you have the `calloc' function. */
#define HAVE_CALLOC 1

/* Define to 1 if your system has a working `chown' function. */
#define HAVE_CHOWN 1

/* Define if you have clock_gettime */
/* #undef HAVE_CLOCK_GETTIME */

/* Define to 1 if you have the `close' function. */
#define HAVE_CLOSE 1

/* Define to 1 if you have the `closelog' function. */
#define HAVE_CLOSELOG 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define if you have dlopen */
#define HAVE_DLOPEN 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the `endpwent' function. */
#define HAVE_ENDPWENT 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `exit' function. */
#define HAVE_EXIT 1

/* Define to 1 if you have the `fclose' function. */
#define HAVE_FCLOSE 1

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `ferror' function. */
#define HAVE_FERROR 1

/* Define to 1 if you have the `fflush' function. */
#define HAVE_FFLUSH 1

/* Define to 1 if you have the `fgetc' function. */
#define HAVE_FGETC 1

/* Define to 1 if you have the `fopen' function. */
#define HAVE_FOPEN 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `fprintf' function. */
#define HAVE_FPRINTF 1

/* Define to 1 if you have the `free' function. */
#define HAVE_FREE 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getpass' function. */
#define HAVE_GETPASS 1

/* Define to 1 if you have the `getpassphrase' function. */
/* #undef HAVE_GETPASSPHRASE */

/* Define to 1 if you have the `getpid' function. */
#define HAVE_GETPID 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `cunit' library (-lcunit). */
/* #undef HAVE_LIBCUNIT */

/* Define to 1 if you have a functional curl library. */
/* #undef HAVE_LIBCURL */

/* Define to 1 if you have the `ldns' library (-lldns). */
#define HAVE_LIBLDNS 1

/* Define to 1 if you have the `sqlite3' library (-lsqlite3). */
#define HAVE_LIBSQLITE3 1

/* Define to 1 if you have the `xml2' library (-lxml2). */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the <libxml/parser.h> header file. */
/* #undef HAVE_LIBXML_PARSER_H */

/* Define to 1 if you have the <libxml/relaxng.h> header file. */
/* #undef HAVE_LIBXML_RELAXNG_H */

/* Define to 1 if you have the <libxml/xmlreader.h> header file. */
/* #undef HAVE_LIBXML_XMLREADER_H */

/* Define to 1 if you have the <libxml/xpath.h> header file. */
/* #undef HAVE_LIBXML_XPATH_H */

/* Define to 1 if you have the `listen' function. */
#define HAVE_LISTEN 1

/* Whether LoadLibrary is available */
/* #undef HAVE_LOADLIBRARY */

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <mysql.h> header file. */
/* #undef HAVE_MYSQL_H */

/* Define to 1 if you have the `openlog' function. */
#define HAVE_OPENLOG 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the `pthread_cond_destroy' function. */
#define HAVE_PTHREAD_COND_DESTROY 1

/* Define to 1 if you have the `pthread_cond_init' function. */
#define HAVE_PTHREAD_COND_INIT 1

/* Define to 1 if you have the `pthread_cond_signal' function. */
#define HAVE_PTHREAD_COND_SIGNAL 1

/* Define to 1 if you have the `pthread_cond_timedwait' function. */
#define HAVE_PTHREAD_COND_TIMEDWAIT 1

/* Define to 1 if you have the `pthread_cond_wait' function. */
#define HAVE_PTHREAD_COND_WAIT 1

/* Define to 1 if you have the `pthread_create' function. */
#define HAVE_PTHREAD_CREATE 1

/* Define to 1 if you have the `pthread_detach' function. */
#define HAVE_PTHREAD_DETACH 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the `pthread_join' function. */
#define HAVE_PTHREAD_JOIN 1

/* Define to 1 if you have the `pthread_mutex_destroy' function. */
#define HAVE_PTHREAD_MUTEX_DESTROY 1

/* Define to 1 if you have the `pthread_mutex_init' function. */
#define HAVE_PTHREAD_MUTEX_INIT 1

/* Define to 1 if you have the `pthread_mutex_lock' function. */
#define HAVE_PTHREAD_MUTEX_LOCK 1

/* Define to 1 if you have the `pthread_mutex_unlock' function. */
#define HAVE_PTHREAD_MUTEX_UNLOCK 1

/* Define to 1 if you have the `pthread_self' function. */
#define HAVE_PTHREAD_SELF 1

/* Define to 1 if you have the `pthread_sigmask' function. */
#define HAVE_PTHREAD_SIGMASK 1

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `setregid' function. */
#define HAVE_SETREGID 1

/* Define to 1 if you have the `setresgid' function. */
/* #undef HAVE_SETRESGID */

/* Define to 1 if you have the `setresuid' function. */
/* #undef HAVE_SETRESUID */

/* Define to 1 if you have the `setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the `sigfillset' function. */
#define HAVE_SIGFILLSET 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <sqlite3.h> header file. */
#define HAVE_SQLITE3_H 1

/* Define to 1 if you have the `stat' function. */
#define HAVE_STAT 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the `strlen' function. */
#define HAVE_STRLEN 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strncat' function. */
#define HAVE_STRNCAT 1

/* Define to 1 if you have the `strncmp' function. */
#define HAVE_STRNCMP 1

/* Define to 1 if you have the `strncpy' function. */
#define HAVE_STRNCPY 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define to 1 if you have the `syslog' function. */
#define HAVE_SYSLOG 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the `time' function. */
#define HAVE_TIME 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unlink' function. */
#define HAVE_UNLINK 1

/* Define to 1 if you have the `va_end' function. */
/* #undef HAVE_VA_END */

/* Define to 1 if you have the `va_start' function. */
/* #undef HAVE_VA_START */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `waitpid' function. */
#define HAVE_WAITPID 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if you have the `xmlCleanupParser' function. */
/* #undef HAVE_XMLCLEANUPPARSER */

/* Define to 1 if you have the `xmlCleanupThreads' function. */
/* #undef HAVE_XMLCLEANUPTHREADS */

/* Define to 1 if you have the `xmlInitParser' function. */
/* #undef HAVE_XMLINITPARSER */

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* Default configuration file. */
#define HSM_DEFAULT_CONFIG "/etc/opendnssec/conf.xml"

/* Defined if libcurl supports AsynchDNS */
/* #undef LIBCURL_FEATURE_ASYNCHDNS */

/* Defined if libcurl supports IDN */
/* #undef LIBCURL_FEATURE_IDN */

/* Defined if libcurl supports IPv6 */
/* #undef LIBCURL_FEATURE_IPV6 */

/* Defined if libcurl supports KRB4 */
/* #undef LIBCURL_FEATURE_KRB4 */

/* Defined if libcurl supports libz */
/* #undef LIBCURL_FEATURE_LIBZ */

/* Defined if libcurl supports NTLM */
/* #undef LIBCURL_FEATURE_NTLM */

/* Defined if libcurl supports SSL */
/* #undef LIBCURL_FEATURE_SSL */

/* Defined if libcurl supports SSPI */
/* #undef LIBCURL_FEATURE_SSPI */

/* Defined if libcurl supports DICT */
/* #undef LIBCURL_PROTOCOL_DICT */

/* Defined if libcurl supports FILE */
/* #undef LIBCURL_PROTOCOL_FILE */

/* Defined if libcurl supports FTP */
/* #undef LIBCURL_PROTOCOL_FTP */

/* Defined if libcurl supports FTPS */
/* #undef LIBCURL_PROTOCOL_FTPS */

/* Defined if libcurl supports HTTP */
/* #undef LIBCURL_PROTOCOL_HTTP */

/* Defined if libcurl supports HTTPS */
/* #undef LIBCURL_PROTOCOL_HTTPS */

/* Defined if libcurl supports IMAP */
/* #undef LIBCURL_PROTOCOL_IMAP */

/* Defined if libcurl supports LDAP */
/* #undef LIBCURL_PROTOCOL_LDAP */

/* Defined if libcurl supports POP3 */
/* #undef LIBCURL_PROTOCOL_POP3 */

/* Defined if libcurl supports RTSP */
/* #undef LIBCURL_PROTOCOL_RTSP */

/* Defined if libcurl supports SMTP */
/* #undef LIBCURL_PROTOCOL_SMTP */

/* Defined if libcurl supports TELNET */
/* #undef LIBCURL_PROTOCOL_TELNET */

/* Defined if libcurl supports TFTP */
/* #undef LIBCURL_PROTOCOL_TFTP */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Path to the OpenDNSSEC kaspcheck binary */
#define ODS_AU_KASPCHECK "/usr/local/bin/ods-kaspcheck"

/* Path to the OpenDNSSEC ods-control binary */
#define ODS_EN_CONTROL "/usr/local/sbin/ods-control enforcer "

/* Path to the OpenDNSSEC auditor binary */
#define ODS_SE_AUDITOR "/usr/local/bin/ods-auditor"

/* Path to the OpenDNSSEC config file */
#define ODS_SE_CFGFILE "/etc/opendnssec/conf.xml"

/* Path to the OpenDNSSEC signer client binary */
#define ODS_SE_CLI "/usr/local/sbin/ods-signer"

/* Path to the OpenDNSSEC signer engine binary */
#define ODS_SE_ENGINE "/usr/local/sbin/ods-signerd -vvv"

/* Path to the OpenDNSSEC signer engine pid file */
#define ODS_SE_PIDFILE "/var/run/opendnssec/signerd.pid"

/* Path to the OpenDNSSEC data files */
#define ODS_SE_RNGDIR "/usr/local/share/opendnssec"

/* Path to the OpenDNSSEC signer engine socket file */
#define ODS_SE_SOCKFILE "/var/run/opendnssec/engine.sock"

/* Path to the OpenDNSSEC signer engine working directory */
#define ODS_SE_WORKDIR ""

/* Path to the OpenDNSSEC signer engine pid file */
#define ODS_ZF_PIDFILE "/var/run/opendnssec/zone_fetcher.pid"

/* Path to the OpenDNSSEC configuration files */
#define OPENDNSSEC_CONFIG_DIR "/etc/opendnssec"

/* Path to the main OpenDNSSEC configuration file */
#define OPENDNSSEC_CONFIG_FILE "/etc/opendnssec/conf.xml"

/* Path to the OpenDNSSEC enforcer pid file */
#define OPENDNSSEC_ENFORCER_PIDFILE "/var/run/opendnssec/enforcerd.pid"

/* Path to the OpenDNSSEC zone fetcher pid file */
#define OPENDNSSEC_FETCH_PIDFILE "/var/run/opendnssec/zone_fetcher.pid"

/* Path to the OpenDNSSEC data files */
#define OPENDNSSEC_SCHEMA_DIR "/usr/local/share/opendnssec"

/* Path to the OpenDNSSEC signer cli */
#define OPENDNSSEC_SIGNER_CLI "/usr/local/sbin/ods-signer"

/* Path to the OpenDNSSEC signer engine */
#define OPENDNSSEC_SIGNER_ENGINE "/usr/local/sbin/ods-signerd"

/* Path to the OpenDNSSEC signer pid file */
#define OPENDNSSEC_SIGNER_PIDFILE "/var/run/opendnssec/signerd.pid"

/* Path to the OpenDNSSEC signer socket */
#define OPENDNSSEC_SIGNER_SOCKET "/var/run/opendnssec/engine.sock"

/* Path to the OpenDNSSEC var directory */
#define OPENDNSSEC_STATE_DIR "/var/opendnssec"

/* Name of package */
#define PACKAGE "opendnssec"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "http://trac.opendnssec.org/newticket"

/* Define to the full name of this package. */
#define PACKAGE_NAME "opendnssec"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "opendnssec 1.2.0b1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "opendnssec"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.2.0b1"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Command to restart a named process */
#define RESTART_ENFORCERD_CMD "/usr/bin/killall -HUP ods-enforcerd"

/* Define to the type of arg 1 for `select'. */
#define SELECT_TYPE_ARG1 int

/* Define to the type of args 2, 3 and 4 for `select'. */
#define SELECT_TYPE_ARG234 (fd_set *)

/* Define to the type of arg 5 for `select'. */
#define SELECT_TYPE_ARG5 (struct timeval *)

/* Define if your platform breaks doing a seteuid before a setuid */
#define SETEUID_BREAKS_SETUID 1

/* Path to the OpenDNSSEC signer engine cli */
#define SIGNER_CLI_UPDATE "/usr/local/sbin/ods-signer update"

/* database binary */
#define SQL_BIN "/usr/bin/sqlite3"

/* database setup script */
#define SQL_SETUP "/usr/local/share/opendnssec/database_create.sqlite3"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* strptime is available from time.h with some defines. */
/* #undef STRPTIME_NEEDS_DEFINES */

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#define VERSION "1.2.0b1"

/* Define to 1 if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
/* # undef _ALL_SOURCE */
#endif

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Use POSIX pthread semantics */
#define _POSIX_PTHREAD_SEMANTICS 1

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Enable extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define curl_free() as free() if our version of curl lacks curl_free. */
/* #undef curl_free */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */


	/* define before includes as it specifies what standard to use. */
	#if (defined(HAVE_PSELECT) && !defined (HAVE_PSELECT_PROTO)) \
	        || !defined (HAVE_CTIME_R_PROTO) \
	        || defined (STRPTIME_NEEDS_DEFINES)
	#  ifndef _XOPEN_SOURCE
	#    define _XOPEN_SOURCE 600
	#  endif
	#  ifndef _POSIX_C_SOURCE
	#    define _POSIX_C_SOURCE 200112
	#  endif
	#  ifndef _BSD_SOURCE
	#    define _BSD_SOURCE 1
	#  endif
	#  ifndef __EXTENSIONS__
	#    define __EXTENSIONS__ 1
	#  endif
	#  ifndef _STDC_C99
	#    define _STDC_C99 1
	#  endif
	#  ifndef _ALL_SOURCE
	#    define _ALL_SOURCE 1
	#  endif
	#endif

	#define ODS_SE_MAXLINE 1024
	#define ODS_SE_SIGNERTHREADS 1
	#define ODS_SE_WORKERTHREADS 8
	#define ODS_SE_STOP_RESPONSE "Engine shut down."
	#define ODS_SE_FILE_MAGIC ";ODSSE1"
	#define ODS_SE_MAX_BACKOFF 3600

