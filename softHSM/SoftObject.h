class SoftObject {
  public:
    SoftObject();
    ~SoftObject();
    CK_RV addKey(Private_Key *inKey, CK_OBJECT_CLASS oClass, char *pName);
    CK_RV saveKey(SoftHSMInternal *pSoftH);
    CK_RV getAttribute(CK_ATTRIBUTE *attTemplate);
    CK_OBJECT_CLASS getObjectClass();
    CK_KEY_TYPE getKeyType();
    Private_Key* getKey();
    char* getFileName();

  private:
    char *fileName;
    Private_Key *key;
    CK_OBJECT_CLASS objectClass;
    CK_KEY_TYPE keyType;
};
