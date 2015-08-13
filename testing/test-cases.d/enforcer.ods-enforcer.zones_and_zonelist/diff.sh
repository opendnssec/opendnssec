#!/bin/sh
xsltproc diff.xsl "$1" | xmllint --c14n - | xmllint --format - > "$1~"
xsltproc diff.xsl "$2" | xmllint --c14n - | xmllint --format - > "$2~"
diff -rwq "$1~" "$2~" > /dev/null 2> /dev/null
exit $?
