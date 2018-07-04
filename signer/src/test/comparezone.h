#ifndef COMPAREZONE_H
#define COMPAREZONE_H

#ifdef __cplusplus
extern "C" {
#endif

#define comparezone_INCL_SOA 0x01

int comparezone(const char* fname1, const char* fname2, int flags);

#ifdef __cplusplus
}
#endif

#endif
