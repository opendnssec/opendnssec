#define VERSION_MAJOR 0
#define VERSION_MINOR 1

#define MAX_SESSION_COUNT 2048
#define MAX_OBJECTS 2000

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>

#include <botan/botan.h>
#include <botan/bigint.h>
#include <botan/randpool.h>
#include <botan/aes.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>
#include <botan/rsa.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/x509_obj.h>
#include <botan/exceptn.h>
using namespace Botan;

#include <pkcs11_unix.h>
#include <pkcs11.h>

class SoftHSMInternal;
class SoftSession;
class SoftObject;
class SoftFind;

#include <SoftHSMInternal.h>
#include <SoftSession.h>
#include <SoftObject.h>
#include <SoftFind.h>
#include <file.h>
