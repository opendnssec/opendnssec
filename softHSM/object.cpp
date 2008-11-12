class SoftObject {
  public:
    SoftObject();
    ~SoftObject();
    CK_RV addAttributeFromData(CK_ATTRIBUTE_TYPE type, void *data, CK_ULONG size);

    CK_ATTRIBUTE_PTR attributes[MAX_ATTRIBUTES];
    int attributeCount;
    bool privateKey;
    bool store;
    bool changed;
    int fileID;
    Botan::Public_Key *key;
};

SoftObject::SoftObject() {
  attributeCount = 0;
  store = true;
  changed = false;
  privateKey = false;
  fileID = 0;
  key = NULL_PTR;
  
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
