// Version number for SoftHSM
#define VERSION_MAJOR 0
#define VERSION_MINOR 1

// Maximum number of concurrent sessions
#define MAX_SESSION_COUNT 2048

// Maximum number of objects in SoftHSM
#define MAX_OBJECTS 2000

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <time.h>

// C POSIX library header
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>

// Includes for the crypto library
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

// Unix specific. Defined by RSA Lab.
#include <pkcs11_unix.h>
// PKCS11. Defined by RSA Lab.
#include <pkcs11.h>

// Internal classes
class SoftHSMInternal;
class SoftSession;
class SoftObject;
class SoftFind;

// Internal definitions
#include <SoftHSMInternal.h>
#include <SoftSession.h>
#include <SoftObject.h>
#include <SoftFind.h>
#include <file.h>
