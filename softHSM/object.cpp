class SoftObject {
  public:
    SoftObject();
    ~SoftObject();
    CK_RV addAttributeFromData(CK_ATTRIBUTE_TYPE type, void *data, CK_ULONG size);
    CK_RV addKey(Private_Key *inKey, bool setPrivateKey);
    bool isPrivate();
    CK_KEY_TYPE getKeyType();
    Private_Key* getKey();

    CK_ATTRIBUTE_PTR attributes[MAX_ATTRIBUTES];
    int attributeCount;
    int fileID;

  private:
    Private_Key *key;
    bool privateKey;
    CK_KEY_TYPE keyType;
};

SoftObject::SoftObject() {
  key = NULL_PTR;
  privateKey = false;
  keyType = CKK_RSA;
  attributeCount = 0;
  fileID = 0;
  
  for(int i = 0; i < MAX_ATTRIBUTES; i++) {
    attributes[i] = NULL_PTR;
  }
}

SoftObject::~SoftObject() {
  for(int i = 0; i < MAX_ATTRIBUTES; i++) {
    free(attributes[i]->pValue);
    free(attributes[i]);
  }
  delete key;
  key = NULL_PTR;
}

CK_RV SoftObject::addAttributeFromData(CK_ATTRIBUTE_TYPE type, void *data, CK_ULONG size) {
  CK_ATTRIBUTE_PTR attribute = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE));

  if(!attribute) {
    return CKR_DEVICE_MEMORY;
  }

  for(int i = 0; i < MAX_ATTRIBUTES; i++) {
    if(attributes[i] == NULL_PTR) {
      attribute->type = type;
      attribute->pValue = malloc(size);
      if(!attribute->pValue) {
        free(attribute);
        return CKR_DEVICE_MEMORY;
      }
      memcpy(attribute->pValue, data, size);
      attribute->ulValueLen = size;
      attributes[i] = attribute;
      return CKR_OK;
    }
  }

  free(attribute);
  return CKR_DEVICE_MEMORY;
}

CK_RV SoftObject::addKey(Private_Key *inKey, bool setPrivateKey) {
  const char *algoName = (dynamic_cast<Public_Key*>(inKey))->algo_name().c_str();

  if(!strcmp(algoName, "RSA")) {
    keyType = CKK_RSA;
  } else if(!strcmp(algoName, "DSA")) {
    keyType = CKK_DSA;
  } else {
    return CKR_GENERAL_ERROR;
  }

  key = inKey;
  privateKey = setPrivateKey;

  return CKR_OK;
}

bool SoftObject::isPrivate() {
  return privateKey;
}

CK_KEY_TYPE SoftObject::getKeyType() {
  return keyType;
}

Private_Key* SoftObject::getKey() {
  return key;
}


/********************************************************************

  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL cktrue = CK_TRUE;
  CK_OBJECT_CLASS objectClass;

  objectClass = CKO_PUBLIC_KEY;
  publicKey->addAttributeFromData(CKA_CLASS, &objectClass, sizeof(objectClass));
  publicKey->addAttributeFromData(CKA_KEY_TYPE, &keyType, sizeof(keyType));
  publicKey->addAttributeFromData(CKA_LOCAL, &cktrue, sizeof(cktrue));

  objectClass = CKO_PRIVATE_KEY;
  privateKey->addAttributeFromData(CKA_CLASS, &objectClass, sizeof(objectClass));
  privateKey->addAttributeFromData(CKA_KEY_TYPE, &keyType, sizeof(keyType));
  privateKey->addAttributeFromData(CKA_LOCAL, &cktrue, sizeof(cktrue));


********************************************************************/
