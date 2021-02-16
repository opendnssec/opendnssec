# Check for SSL, original taken from
# http://www.gnu.org/software/ac-archive/htmldoc/check_ssl.html and
# modified for OpenDNSSEC.
AC_DEFUN([ACX_SSL], [
    AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl=pathname],
                [enable SSL (will check /usr/local/ssl
                /usr/lib/ssl /usr/ssl /usr/pkg /usr/sfw /usr/local /usr)]),[
        ],[
            withval="yes"
        ])
    if test x_$withval != x_no; then
        AC_MSG_CHECKING(for SSL)
        if test x_$withval = x_ -o x_$withval = x_yes; then
            withval="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/sfw /usr/local /usr"
        fi
        for dir in $withval; do
            ssldir="$dir"
            if test -f "$dir/include/openssl/ssl.h"; then
                found_ssl="yes";
                AC_DEFINE_UNQUOTED([HAVE_SSL], [], [Define if you have the SSL libraries installed.])
                if test x_$ssldir != x_/usr; then
                    SSL_INCLUDES="$SSL_INCLUDES -I$ssldir/include";
                fi
                break;
            fi
        done
        if test x_$found_ssl != x_yes; then
            AC_MSG_ERROR(Cannot find the SSL libraries in $withval)
        else
            AC_MSG_RESULT(found in $ssldir)
            HAVE_SSL=yes
            if test x_$ssldir != x_/usr; then
                SSL_LIBS="$SSL_LIBS -L$ssldir/lib";
            fi
            if test x_$ssldir = x_/usr/sfw; then
                SSL_LIBS="$SSL_LIBS -R$ssldir/lib";
            fi
            save_LIBS=$LIBS
            AC_CHECK_LIB(crypto, HMAC_CTX_reset, [
                    AC_DEFINE_UNQUOTED([HAVE_SSL_NEW_HMAC], [], [Define if you have the SSL libraries with new HMAC related functions.])
            ], [
                    AC_CHECK_LIB(crypto, HMAC_CTX_init,, [
                            AC_MSG_ERROR([OpenSSL found in $ssldir, but version 0.9.7 or higher is required])
                    ])
            ] )
            SSL_LIBS="$SSL_LIBS -lcrypto";
            LIBS="$SSL_LIBS $LIBS"
            AC_CHECK_FUNCS([EVP_sha1 EVP_sha256])
            LIBS=$saveLIBS
        fi
        AC_SUBST(HAVE_SSL)
        AC_SUBST(HAVE_SSL_NEW_HMAC)
        AC_SUBST(SSL_INCLUDES)
        AC_SUBST(SSL_LIBS)
    fi
])dnl

