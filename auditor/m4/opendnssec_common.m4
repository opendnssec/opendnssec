# $Id$

AC_DEFUN([OPENDNSSEC_COMMON],[

AC_MSG_NOTICE(Detecting common OpenDNSSEC settings)

full_bindir=`eval eval eval eval eval echo "${bindir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sbindir=`eval eval eval eval eval echo "${sbindir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libexecdir=`eval eval eval eval eval echo "${libexecdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_datadir=`eval eval eval eval eval echo "${datadir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

OPENDNSSEC_BIN_DIR=$full_bindir
OPENDNSSEC_SBIN_DIR=$full_sbindir
OPENDNSSEC_LIB_DIR=$full_libdir/opendnssec
OPENDNSSEC_LIBEXEC_DIR=$full_libexecdir/opendnssec
OPENDNSSEC_DATA_DIR=$full_datadir/opendnssec
OPENDNSSEC_SYSCONF_DIR=$full_sysconfdir/opendnssec
OPENDNSSEC_LOCALSTATE_DIR="$full_localstatedir/opendnssec"
OPENDNSSEC_PID_DIR="$full_localstatedir/run/opendnssec"

AC_SUBST([OPENDNSSEC_BIN_DIR])
AC_SUBST([OPENDNSSEC_SBIN_DIR])
AC_SUBST([OPENDNSSEC_LIB_DIR])
AC_SUBST([OPENDNSSEC_LIBEXEC_DIR])
AC_SUBST([OPENDNSSEC_DATA_DIR])
AC_SUBST([OPENDNSSEC_SYSCONF_DIR])
AC_SUBST([OPENDNSSEC_LOCALSTATE_DIR])
AC_SUBST([OPENDNSSEC_PID_DIR])

OPENDNSSEC_CONFIG_DIR=$OPENDNSSEC_SYSCONF_DIR
OPENDNSSEC_CONFIG_FILE=$OPENDNSSEC_SYSCONF_DIR/conf.xml
OPENDNSSEC_SCHEMA_DIR=$OPENDNSSEC_DATA_DIR
OPENDNSSEC_STATE_DIR=$OPENDNSSEC_LOCALSTATE_DIR

AC_SUBST([OPENDNSSEC_CONFIG_DIR])
AC_SUBST([OPENDNSSEC_CONFIG_FILE])
AC_SUBST([OPENDNSSEC_SCHEMA_DIR])
AC_SUBST([OPENDNSSEC_STATE_DIR])

AC_DEFINE_UNQUOTED(OPENDNSSEC_CONFIG_DIR,  "$OPENDNSSEC_CONFIG_DIR", [Path to the OpenDNSSEC configuration files])
AC_DEFINE_UNQUOTED(OPENDNSSEC_CONFIG_FILE, "$OPENDNSSEC_CONFIG_FILE", [Path to the main OpenDNSSEC configuration file])
AC_DEFINE_UNQUOTED(OPENDNSSEC_SCHEMA_DIR,  "$OPENDNSSEC_SCHEMA_DIR", [Path to the OpenDNSSEC data files])
AC_DEFINE_UNQUOTED(OPENDNSSEC_STATE_DIR,   "$OPENDNSSEC_STATE_DIR", [Path to the OpenDNSSEC var directory])

OPENDNSSEC_SIGNER_PIDFILE=$OPENDNSSEC_PID_DIR/signerd.pid
OPENDNSSEC_ENFORCER_PIDFILE=$OPENDNSSEC_PID_DIR/enforcerd.pid
OPENDNSSEC_FETCH_PIDFILE=$OPENDNSSEC_PID_DIR/zone_fetcher.pid

AC_SUBST([OPENDNSSEC_SIGNER_PIDFILE])
AC_SUBST([OPENDNSSEC_ENFORCER_PIDFILE])
AC_SUBST([OPENDNSSEC_FETCH_PIDFILE])

AC_DEFINE_UNQUOTED(OPENDNSSEC_SIGNER_PIDFILE,   "$OPENDNSSEC_SIGNER_PIDFILE", [Path to the OpenDNSSEC signer pid file])
AC_DEFINE_UNQUOTED(OPENDNSSEC_ENFORCER_PIDFILE, "$OPENDNSSEC_ENFORCER_PIDFILE", [Path to the OpenDNSSEC enforcer pid file])
AC_DEFINE_UNQUOTED(OPENDNSSEC_FETCH_PIDFILE,    "$OPENDNSSEC_FETCH_PIDFILE", [Path to the OpenDNSSEC zone fetcher pid file])

OPENDNSSEC_SIGNER_SOCKET=$OPENDNSSEC_PID_DIR/engine.sock
OPENDNSSEC_SIGNER_ENGINE=$OPENDNSSEC_SBIN_DIR/ods-signerd
OPENDNSSEC_SIGNER_AUDITOR=$OPENDNSSEC_BIN_DIR/ods-auditor
OPENDNSSEC_SIGNER_CLI=$OPENDNSSEC_SBIN_DIR/ods-signer

OPENDNSSEC_AUDITOR_KASPCHECK=$OPENDNSSEC_BIN_DIR/ods-kaspcheck

AC_SUBST([OPENDNSSEC_SIGNER_SOCKET])
AC_SUBST([OPENDNSSEC_SIGNER_ENGINE])
AC_SUBST([OPENDNSSEC_SIGNER_CLI])

AC_DEFINE_UNQUOTED(OPENDNSSEC_SIGNER_SOCKET, "$OPENDNSSEC_SIGNER_SOCKET", [Path to the OpenDNSSEC signer socket])
AC_DEFINE_UNQUOTED(OPENDNSSEC_SIGNER_ENGINE, "$OPENDNSSEC_SIGNER_ENGINE", [Path to the OpenDNSSEC signer engine])
AC_DEFINE_UNQUOTED(OPENDNSSEC_SIGNER_CLI,    "$OPENDNSSEC_SIGNER_CLI",    [Path to the OpenDNSSEC signer cli])

AC_DEFINE_UNQUOTED(ODS_SE_PIDFILE,  ["$OPENDNSSEC_SIGNER_PIDFILE"],    [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(ODS_ZF_PIDFILE,  ["$OPENDNSSEC_FETCH_PIDFILE"],    [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(ODS_SE_SOCKFILE, ["$OPENDNSSEC_SIGNER_SOCKET"],     [Path to the OpenDNSSEC signer engine socket file])
AC_DEFINE_UNQUOTED(ODS_SE_WORKDIR,  ["$OPENDNSSEC_SIGNER_WORKINGDIR"], [Path to the OpenDNSSEC signer engine working directory])
AC_DEFINE_UNQUOTED(ODS_SE_CFGFILE,  ["$OPENDNSSEC_CONFIG_FILE"],       [Path to the OpenDNSSEC config file])
AC_DEFINE_UNQUOTED(ODS_SE_RNGDIR,   ["$OPENDNSSEC_SCHEMA_DIR"],        [Path to the OpenDNSSEC data files])
AC_DEFINE_UNQUOTED(ODS_SE_ENGINE,   ["$OPENDNSSEC_SIGNER_ENGINE -vvv"], [Path to the OpenDNSSEC signer engine binary])
AC_DEFINE_UNQUOTED(ODS_SE_CLI,      ["$OPENDNSSEC_SIGNER_CLI"], [Path to the OpenDNSSEC signer client binary])
AC_DEFINE_UNQUOTED(ODS_SE_AUDITOR,  ["$OPENDNSSEC_SIGNER_AUDITOR"],    [Path to the OpenDNSSEC auditor binary])

AC_DEFINE_UNQUOTED(ODS_AU_KASPCHECK,  ["$OPENDNSSEC_AUDITOR_KASPCHECK"],    [Path to the OpenDNSSEC kaspcheck binary])

])
