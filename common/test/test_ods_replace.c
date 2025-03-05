// Tested with: gcc -I ../ test_ods_replace.c ../file.c ../log.c ../duration.c ; ./a.out

#include "../file.h"
#include <assert.h>
#include <string.h>

void main(void) {
    // Arguments are: haystack, needle, replacement
    assert(0 == strcmp(ods_replace("", "", ""), ""));
    assert(0 == strcmp(ods_replace("", "", "1"), "1"));
    assert(0 == strcmp(ods_replace("", "1", ""), ""));
    assert(0 == strcmp(ods_replace("", "1", "1"), ""));
    assert(0 == strcmp(ods_replace("1", "", ""), "1"));
    assert(0 == strcmp(ods_replace("1", "", "1"), "11"));
    assert(0 == strcmp(ods_replace("1", "1", ""), ""));
    assert(0 == strcmp(ods_replace("1", "1", "1"), "1"));
    assert(0 == strcmp(ods_replace("xxx", "notfound", "replacement"), "xxx"));
    assert(0 == strcmp(ods_replace("foundatstartxxx", "foundatstart", "replacement"), "replacementxxx"));
    assert(0 == strcmp(ods_replace("xxxfoundinmiddlexxx", "foundinmiddle", "replacement"), "xxxreplacementxxx"));
    assert(0 == strcmp(ods_replace("xxxfoundatend", "foundatend", "replacement"), "xxxreplacement"));
    assert(0 == strcmp(ods_replace("/home/runner/ROOT/var/opendnssec/signer/test-notify-command.sh %zone %zonefile", "%zonefile", "/home/runner/ROOT/var/opendnssec/signed/ods"), "/home/runner/ROOT/var/opendnssec/signer/test-notify-command.sh %zone /home/runner/ROOT/var/opendnssec/signed/ods"));
}
