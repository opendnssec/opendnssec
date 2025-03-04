// Tested with: gcc -O3 -I ../ test_ods_replace.c ../file.c ../log.c ../duration.c ; ./a.out

#include "../file.h"
#include <assert.h>
#include <string.h>

void check(int res) {
    if (res != 0) {
        printf("FAILED\n");
        exit(1);
    }
}

void main(void) {
    // Arguments are: haystack, needle, replacement
    check(strcmp(ods_replace("", "", ""), ""));
    check(strcmp(ods_replace("", "", "1"), "1"));
    check(strcmp(ods_replace("", "1", ""), ""));
    check(strcmp(ods_replace("", "1", "1"), ""));
    check(strcmp(ods_replace("1", "", ""), "1"));
    check(strcmp(ods_replace("1", "", "1"), "11"));
    check(strcmp(ods_replace("1", "1", ""), ""));
    check(strcmp(ods_replace("1", "1", "1"), "1"));
    check(strcmp(ods_replace("xxx", "notfound", "replacement"), "xxx"));
    check(strcmp(ods_replace("foundatstartxxx", "foundatstart", "replacement"), "replacementxxx"));
    check(strcmp(ods_replace("xxxfoundinmiddlexxx", "foundinmiddle", "replacement"), "xxxreplacementxxx"));
    check(strcmp(ods_replace("xxxfoundatend", "foundatend", "replacement"), "xxxreplacement"));
    check(strcmp(ods_replace("/home/runner/ROOT/var/opendnssec/signer/test-notify-command.sh %zone %zonefile", "%zonefile", "/home/runner/ROOT/var/opendnssec/signed/ods"), "/home/runner/ROOT/var/opendnssec/signer/test-notify-command.sh %zone /home/runner/ROOT/var/opendnssec/signed/ods"));
}
