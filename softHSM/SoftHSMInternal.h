/************************************************************
*
* This class handles the internal state.
* Mainly session and object handling.
*
************************************************************/

class SoftHSMInternal {
  public:
    SoftHSMInternal();
    ~SoftHSMInternal();
    int getSessionCount();
    CK_RV openSession(CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
      CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions();
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, 
      CK_ULONG ulPinLen);
    CK_RV getSession(CK_SESSION_HANDLE hSession, SoftSession *&session);
    CK_RV getObject(CK_OBJECT_HANDLE hObject, SoftObject *&object);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, 
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, 
      CK_ULONG ulCount);
    CK_OBJECT_HANDLE getObjectByNameAndClass(char *labelOrID, CK_OBJECT_CLASS oClass);
    bool isLoggedIn();
    char* getPIN();
    CK_OBJECT_HANDLE addObject(SoftObject *inObject);

    AutoSeeded_RNG *rng;

  private:
    char *pin;
    int openSessions;
    SoftSession *sessions[MAX_SESSION_COUNT];
    int openObjects;
    SoftObject *objects[MAX_OBJECTS];
};
