#define MAX_SESSION_COUNT 2048
#define MAX_OBJECTS 2000
#define MAX_ATTRIBUTES 20

#include <session.cpp>
#include <object.cpp>

class SoftHSMInternal {
  public:
    SoftHSMInternal();
    ~SoftHSMInternal();
    int getSessionCount();
    CK_RV openSession(CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions();
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV getSession(CK_SESSION_HANDLE hSession, SoftSession *&session);
    bool isLoggedIn();
  private:
    int openSessions;
    SoftSession *sessions[MAX_SESSION_COUNT];
    SoftObject *objects[MAX_OBJECTS];
    char *pin;
};

SoftHSMInternal::SoftHSMInternal() {
  openSessions = 0;

  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    sessions[i] = NULL_PTR;
  }

  for(int i = 0; i < MAX_OBJECTS; i++) {
    objects[i] = NULL_PTR;
  }

  pin = NULL_PTR;
}

SoftHSMInternal::~SoftHSMInternal() {
  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    delete sessions[i];
    sessions[i] = NULL_PTR;
  }

  for(int i = 0; i < MAX_OBJECTS; i++) {
    delete objects[i];
    objects[i] = NULL_PTR;
  }

  free(pin);
  pin = NULL_PTR;
}

int SoftHSMInternal::getSessionCount() {
  return openSessions;
}

CK_RV SoftHSMInternal::openSession(CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  if(openSessions >= MAX_SESSION_COUNT) {
    return CKR_SESSION_COUNT;
  }

  if((flags & CKF_SERIAL_SESSION) == 0) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  if(!phSession) {
    return CKR_ARGUMENTS_BAD;
  }

  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    if(sessions[i] == NULL_PTR) {
      openSessions++;
      sessions[i] = new SoftSession();
      sessions[i]->pApplication = pApplication;
      sessions[i]->Notify = Notify;
      *phSession = (CK_SESSION_HANDLE)(i+1);
      return CKR_OK;
    }
  }

  return CKR_SESSION_COUNT;
}

CK_RV SoftHSMInternal::closeSession(CK_SESSION_HANDLE hSession) {
  if(hSession >= MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  delete sessions[hSession-1];
  sessions[hSession-1] = NULL_PTR;

  openSessions--;

  return CKR_OK;
}

CK_RV SoftHSMInternal::closeAllSessions() {
  for (int i = 0; i < MAX_SESSION_COUNT; i++) {
    delete sessions[i];
    sessions[i] = NULL_PTR;
  }

  openSessions = 0;

  return CKR_OK;
}

CK_RV SoftHSMInternal::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  if(hSession >= MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  if(sizeof(*pInfo) != sizeof(CK_SESSION_INFO)) {
    return CKR_ARGUMENTS_BAD;
  }

  pInfo->slotID = 1;

  if(pin) {
    pInfo->state = CKS_RW_USER_FUNCTIONS;
  } else {
    pInfo->state = CKS_RW_PUBLIC_SESSION;
  }

  pInfo->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  pInfo->ulDeviceError = 0;

  return CKR_OK;
}

CK_RV SoftHSMInternal::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if(hSession >= MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  pin = (char *)malloc(ulPinLen);
  if (!pin) {
    return CKR_DEVICE_MEMORY;
  }
  memcpy(pin, pPin, ulPinLen);

  return CKR_OK;
}

CK_RV SoftHSMInternal::getSession(CK_SESSION_HANDLE hSession, SoftSession *&session) {
  if(hSession >= MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  session = sessions[hSession-1];

  return CKR_OK;
}

bool SoftHSMInternal::isLoggedIn() {
  if(pin) {
    return true;
  } else {
    return false;
  }
}
