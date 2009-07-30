# $Id$
#
# AM_PATH_RUBY([MINIMUM-VERSION], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# ---------------------------------------------------------------------------
# Adds support for distributing Ruby modules and packages.  To
# install modules, copy them to $(rubydir), using the ruby_RUBY 
# automake variable.  To install a package with the same name as the
# automake package, install to $(pkgrubydir), or use the
# pkgruby_RUBY automake variable.
#
# The variables $(rbexecdir) and $(pkgrbexecdir) are provided as
# locations to install ruby extension modules (shared libraries).
# Another macro is required to find the appropriate flags to compile
# extension modules.
#
AC_DEFUN([AM_PATH_RUBY],
 [
  dnl Find a Ruby interpreter.
  m4_define_default([_AM_RUBY_INTERPRETER_LIST],
                    [ruby ruby1.8 ruby1.7 ruby1.6])

  m4_if([$1],[],[
    dnl No version check is needed.
    # Find any Ruby interpreter.
    if test -z "$RUBY"; then
      AC_PATH_PROGS([RUBY], _AM_RUBY_INTERPRETER_LIST, :)
    fi
    am_display_RUBY=ruby
  ], [
    dnl A version check is needed.
    if test -n "$RUBY"; then
      # If the user set $RUBY, use it and don't search something else.
      #AC_MSG_CHECKING([whether $RUBY version >= $1])
      #AM_RUBY_CHECK_VERSION([$RUBY], [$1],
      #                        [AC_MSG_RESULT(yes)],
      #                        [AC_MSG_ERROR(too old)])
      am_display_RUBY=$RUBY
    else
      # Otherwise, try each interpreter until we find one that satisfies
      # VERSION.
      AC_CACHE_CHECK([for a Ruby interpreter with version >= $1],
        [am_cv_pathless_RUBY],[
        for am_cv_pathless_RUBY in _AM_RUBY_INTERPRETER_LIST none; do
          test "$am_cv_pathless_RUBY" = none && break
          #AM_RUBY_CHECK_VERSION([$am_cv_pathless_RUBY], [$1], [break])
          [], [$1], [break])
        done])
      # Set $RUBY to the absolute path of $am_cv_pathless_RUBY.
      if test "$am_cv_pathless_RUBY" = none; then
        RUBY=:
      else
        AC_PATH_PROG([RUBY], [$am_cv_pathless_RUBY])
      fi
      am_display_RUBY=$am_cv_pathless_RUBY
    fi
  ])

  if test "$RUBY" = :; then
  dnl Run any user-specified action, or abort.
    m4_default([$3], [AC_MSG_ERROR([no suitable Ruby interpreter found])])
  else

  dnl Query Ruby for its version number.  Getting [:3] seems to be
  dnl the best way to do this; it's what "site.py" does in the standard
  dnl library.

  AC_CACHE_CHECK([for $am_display_RUBY version], [am_cv_ruby_version],
    [am_cv_ruby_version=`$RUBY -e "print RUBY_VERSION"`])
  AC_SUBST([RUBY_VERSION], [$am_cv_ruby_version])

  dnl Use the values of $prefix and $exec_prefix for the corresponding
  dnl values of RUBY_PREFIX and RUBY_EXEC_PREFIX.  These are made
  dnl distinct variables so they can be overridden if need be.  However,
  dnl general consensus is that you shouldn't need this ability.

  AC_SUBST([RUBY_PREFIX], ['${prefix}'])
  AC_SUBST([RUBY_EXEC_PREFIX], ['${exec_prefix}'])

  dnl At times (like when building shared libraries) you may want
  dnl to know which OS platform Ruby thinks this is.

  AC_CACHE_CHECK([for $am_display_RUBY platform], [am_cv_ruby_platform],
    [am_cv_ruby_platform=`$RUBY -e "print RUBY_PLATFORM"`])
  AC_SUBST([RUBY_PLATFORM], [$am_cv_ruby_platform])


  dnl Set up 4 directories:
  dnl rubydir -- where to install ruby scripts.  
  AC_CACHE_CHECK([for $am_display_RUBY script directory],
    [am_cv_ruby_rubydir],
    [am_cv_ruby_rubydir=`$RUBY -rrbconfig -e "drive = File::PATH_SEPARATOR == ';' ? /\A\w:/ : /\A/; prefix = Regexp.new('\\A' + Regexp.quote(Config::CONFIG[['prefix']])); \\$prefix = Config::CONFIG[['prefix']].sub(drive, ''); \\$archdir = Config::CONFIG[['archdir']].sub(prefix, '\\$(prefix)').sub(drive, ''); print \\$archdir;"`])
  AC_SUBST([rubydir], [$am_cv_ruby_rubydir])

  dnl pkgrubydir -- $PACKAGE directory under rubydir.  
  AC_SUBST([pkgrubydir], [\${rubydir}/$PACKAGE])

  dnl rbexecdir -- directory for installing ruby extension modules
  dnl   (shared libraries)
  AC_CACHE_CHECK([for $am_display_RUBY extension module directory],
    [am_cv_ruby_rbexecdir],
    [am_cv_ruby_rbexecdir=`$RUBY -rrbconfig -e "drive = File::PATH_SEPARATOR == ';' ? /\A\w:/ : /\A/; prefix = Regexp.new('\\A' + Regexp.quote(Config::CONFIG[['prefix']])); \\$prefix = Config::CONFIG[['prefix']].sub(drive, ''); \\$sitearchdir = Config::CONFIG[['sitearchdir']].sub(prefix, '\\$(prefix)').sub(drive, ''); print \\$sitearchdir;" 2>/dev/null || echo "${RUBY_EXEC_PREFIX}/local/lib/site_ruby/${RUBY_VERSION}/${RUBY_PLATFORM}"`])
  AC_SUBST([rbexecdir], [$am_cv_ruby_rbexecdir])

  RUBY_INCLUDES=`$RUBY -r rbconfig -e 'print " -I" + Config::CONFIG[["archdir"]]'`
  AC_SUBST([RUBY_INCLUDES])

  dnl pkgrbexecdir -- $(rbexecdir)/$(PACKAGE)

  AC_SUBST([pkgrbexecdir], [\${rbexecdir}/$PACKAGE])

  dnl Run any user-specified action.
  $2
  fi

])
