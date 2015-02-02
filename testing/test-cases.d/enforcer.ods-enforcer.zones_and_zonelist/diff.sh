#!/bin/sh
xmllint --c14n "$1" | xmllint --format - > "$1~"
xmllint --c14n "$2" | xmllint --format - > "$2~"
diff -rwq "$1~" "$2~" > /dev/null 2> /dev/null
exit $?
