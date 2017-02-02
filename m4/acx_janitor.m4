AC_DEFUN([ACX_JANITOR],[
    AC_ARG_ENABLE([janitor],
        AS_HELP_STRING([--disable-janitor], [Disable janitor]))

    AS_IF([test "x$enable_janitor" != "xno"], [
        dnl AC_DEFINE([HAVE_JANITOR], [1], [Define to enable janitor])
    ])
])
