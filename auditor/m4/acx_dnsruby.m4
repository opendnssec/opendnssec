# $Id$

AC_DEFUN([ACX_DNSRUBY],[

	AC_MSG_CHECKING([for dnsruby version $1 or greater])
	have_ruby_dnsruby=`$RUBY -e '
		begin
			require "rubygems"
			rescue Exception
		end
		begin
			require "dnsruby"
			rescue Exception => e
				print "no"
		end
		begin
			if (Dnsruby.version >= $1)
				print "yes"
			else
				print "no"
			end
			rescue Exception => e
				print "no"
		end'`

	if test "x$have_ruby_dnsruby" != "xyes"; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([Missing dnsruby version $1 or greater])
	fi

	AC_MSG_RESULT([ok])

])
