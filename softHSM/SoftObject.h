/************************************************************
*
* This class defines an object, which contains
* a crypto key, private or public.
*
************************************************************/

class SoftObject {
  public:
    SoftObject();
    ~SoftObject();
    CK_RV addKey(Private_Key *inKey, CK_OBJECT_CLASS oClass, char *pName);
    CK_RV saveKey(SoftHSMInternal *pSoftH);
    CK_RV removeFile(SoftHSMInternal *pSoftH);
    CK_RV addAttributeFromData(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen);
    CK_RV getAttribute(CK_ATTRIBUTE *attTemplate);
    CK_OBJECT_CLASS getObjectClass();
    CK_KEY_TYPE getKeyType();
    int getKeySizeBytes();
    Private_Key* getKey();
    char* getFileName();
    CK_BBOOL matchAttribute(CK_ATTRIBUTE *attTemplate);

  private:
    SoftAttribute *attributes;
    char *fileName;
    Private_Key *key;
    CK_OBJECT_CLASS objectClass;
    CK_KEY_TYPE keyType;
    int keySizeBytes;
};
