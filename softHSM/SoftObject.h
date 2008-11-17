class SoftObject {
  public:
    SoftObject();
    ~SoftObject();
    CK_RV addKey(Private_Key *inKey, bool setPrivateKey, char *pName);
    CK_RV saveKey();
    CK_RV getAttribute(CK_ATTRIBUTE *attTemplate);
    bool isPrivate();
    CK_KEY_TYPE getKeyType();
    Private_Key* getKey();

  private:
    char *fileName;
    Private_Key *key;
    bool privateKey;
    CK_KEY_TYPE keyType;
};
