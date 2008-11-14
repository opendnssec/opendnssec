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
    CK_RV getObject(CK_OBJECT_HANDLE hObject, SoftObject *&object);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    bool isLoggedIn();
    int addObject(SoftObject *inObject);
    char *pin;
  private:
    int openSessions;
    SoftSession *sessions[MAX_SESSION_COUNT];
    SoftObject *objects[MAX_OBJECTS];
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
    if(sessions[i] != NULL_PTR) {
      delete sessions[i];
      sessions[i] = NULL_PTR;
    }
  }

  for(int i = 0; i < MAX_OBJECTS; i++) {
    if(objects[i] != NULL_PTR) {
      delete objects[i];
      objects[i] = NULL_PTR;
    }
  }

  if(pin != NULL_PTR) {
    free(pin);
    pin = NULL_PTR;
  }
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
  if(hSession > MAX_SESSION_COUNT || hSession < 1) {
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
    if(sessions[i] == NULL_PTR) {
      delete sessions[i];
      sessions[i] = NULL_PTR;
    }
  }

  openSessions = 0;

  return CKR_OK;
}

CK_RV SoftHSMInternal::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
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
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(ulPinLen < 4 || ulPinLen > 8000) {
    return CKR_PIN_INCORRECT;
  }

  pin = (char *)malloc(ulPinLen+1);
  if (!pin) {
    return CKR_DEVICE_MEMORY;
  }
  memset(pin,0,ulPinLen+1);
  memcpy(pin, pPin, ulPinLen);

  return CKR_OK;
}

CK_RV SoftHSMInternal::getSession(CK_SESSION_HANDLE hSession, SoftSession *&session) {
  if(hSession > MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  session = sessions[hSession-1];

  return CKR_OK;
}

CK_RV SoftHSMInternal::getObject(CK_OBJECT_HANDLE hObject, SoftObject *&object) {
  if(hObject > MAX_OBJECTS || hObject < 1 || objects[hObject-1] == NULL_PTR) {
    return CKR_OBJECT_HANDLE_INVALID;
  }

  object = objects[hObject-1];

  return CKR_OK;
}


bool SoftHSMInternal::isLoggedIn() {
  if(pin) {
    return true;
  } else {
    return false;
  }
}

int SoftHSMInternal::addObject(SoftObject *inObject) {
  for(int i = 0; i < MAX_OBJECTS; i++) {
    if(objects[i] == NULL_PTR) {
      objects[i] = inObject;
      return i+1;
    }
  }
  return 0;
}

CK_RV SoftHSMInternal::getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  SoftObject *object;
  result = getObject(hObject, object);

  if(result != CKR_OK) {
    return result;
  }

  result = CKR_OK;
  CK_RV objectResult = CKR_OK;

  for(unsigned int i = 0; i < ulCount; i++) {
    objectResult = object->getAttribute(&pTemplate[i]);
    if(objectResult != CKR_OK) {
      result = objectResult;
    }
  }

  return result;
}

