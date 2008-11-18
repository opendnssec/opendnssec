SoftObject::SoftObject() {
  key = NULL_PTR;
  objectClass = CKO_PUBLIC_KEY;
  keyType = CKK_RSA;
  fileName = NULL_PTR;
}

SoftObject::~SoftObject() {
  if(key != NULL_PTR && objectClass == CKO_PRIVATE_KEY) {
    delete key;
  }
  key = NULL_PTR;

  if(fileName != NULL_PTR) {
    free(fileName);
    fileName = NULL_PTR;
  }
}

CK_RV SoftObject::addKey(Private_Key *inKey, CK_OBJECT_CLASS oClass, char *pName) {
  if(pName == NULL_PTR || inKey == NULL_PTR) {
    return CKR_GENERAL_ERROR;
  }

  const char *algoName = (dynamic_cast<Public_Key*>(inKey))->algo_name().c_str();

  if(!strcmp(algoName, "RSA")) {
    keyType = CKK_RSA;
  } else if(!strcmp(algoName, "DSA")) {
    keyType = CKK_DSA;
  } else {
    return CKR_GENERAL_ERROR;
  }

  key = inKey;
  objectClass = oClass;

  int strLength = strlen(pName);
  fileName = (char *)malloc(strLength+1);
  memset(fileName,0,strLength+1);
  strncpy(fileName, pName, strLength);

  return CKR_OK;
}

CK_RV SoftObject::saveKey(SoftHSMInternal *pSoftH) {
  if(objectClass == CKO_PRIVATE_KEY) {
    if(!saveKeyFile(pSoftH, fileName, key)) {
      return CKR_GENERAL_ERROR;
    }
  }

  return CKR_OK;
}

CK_OBJECT_CLASS SoftObject::getObjectClass() {
  return objectClass;
}

CK_KEY_TYPE SoftObject::getKeyType() {
  return keyType;
}

Private_Key* SoftObject::getKey() {
  return key;
}

char* SoftObject::getFileName() {
  return fileName;
}

CK_RV SoftObject::getAttribute(CK_ATTRIBUTE *attTemplate) {
  CK_RV result = CKR_OK;
  CK_BBOOL oTrue = CK_TRUE;
  CK_BBOOL oFalse = CK_FALSE;

  switch(attTemplate->type) {
    case CKA_CLASS:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(objectClass);
      } else if(attTemplate->ulValueLen < sizeof(objectClass)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, &objectClass, sizeof(objectClass));
      }
      break;
    case CKA_KEY_TYPE:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(keyType);
      } else if(attTemplate->ulValueLen < sizeof(keyType)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, &keyType, sizeof(keyType));
      }
      break;
    case CKA_LABEL:
    case CKA_ID:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)strlen(fileName);
      } else if(attTemplate->ulValueLen < strlen(fileName)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, fileName, strlen(fileName));
      }
      break;
    case CKA_LOCAL:
    case CKA_PRIVATE:
    case CKA_TOKEN:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(oTrue);
      } else if(attTemplate->ulValueLen < sizeof(oTrue)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, &oTrue, sizeof(oTrue));
      }
      break;
    case CKA_ENCRYPT:
    case CKA_VERIFY:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(CK_BBOOL);
      } else if(attTemplate->ulValueLen < sizeof(CK_BBOOL)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        CK_BBOOL oBool;
        if(objectClass == CKO_PRIVATE_KEY) {
          oBool = CK_FALSE;
        } else {
          oBool = CK_TRUE;
        }
        memcpy(attTemplate->pValue, &oBool, sizeof(oBool));
      }
      break;
    case CKA_DECRYPT:
    case CKA_SIGN:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(CK_BBOOL);
      } else if(attTemplate->ulValueLen < sizeof(CK_BBOOL)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        CK_BBOOL oBool;
        if(objectClass == CKO_PRIVATE_KEY) {
          oBool = CK_TRUE;
        } else {
          oBool = CK_FALSE;
        }
        memcpy(attTemplate->pValue, &oBool, sizeof(oBool));
      }
      break;
    case CKA_WRAP:
    case CKA_UNWRAP:
    case CKA_MODIFIABLE:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(oFalse);
      } else if(attTemplate->ulValueLen < sizeof(oFalse)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, &oFalse, sizeof(oFalse));
      }
      break;
    case CKA_MODULUS_BITS:
      if(keyType == CKK_RSA) {
        IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(key);
        BigInt bigModulus = ifKey->get_n();
        int bits = bigModulus.bits();

        if(attTemplate->pValue == NULL_PTR) {
          attTemplate->ulValueLen = (CK_LONG)sizeof(int);
        } else if(attTemplate->ulValueLen < sizeof(int)) {
          result = CKR_BUFFER_TOO_SMALL;
          attTemplate->ulValueLen = (CK_LONG)-1;
        } else {
          memcpy(attTemplate->pValue, &bits, sizeof(int));
        }
      } else {
        result = CKR_ATTRIBUTE_TYPE_INVALID;
        attTemplate->ulValueLen = (CK_LONG)-1;
      }
      break;
    // Is this the correct thing to give? X509 public key?
    case CKA_VALUE:
      if(objectClass == CKO_PRIVATE_KEY) {
        result = CKR_ATTRIBUTE_SENSITIVE;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        std::string pemEnc = X509::PEM_encode(*key);
        unsigned int strSize = pemEnc.size();
        if(attTemplate->pValue == NULL_PTR) {
          attTemplate->ulValueLen = strSize;
        } else if(attTemplate->ulValueLen < strSize) {
          result = CKR_BUFFER_TOO_SMALL;
          attTemplate->ulValueLen = (CK_LONG)-1;
        } else {
          memcpy(attTemplate->pValue, pemEnc.c_str(), strSize);
        }
      }
      break;
    // Not tested. The values are correct, but perhaps in reverse order?
    case CKA_MODULUS:
      if(keyType == CKK_RSA) {
        IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(key);
        BigInt bigModulus = ifKey->get_n();
        unsigned int size = bigModulus.bytes();

        if(attTemplate->pValue == NULL_PTR) {
          attTemplate->ulValueLen = (CK_LONG)size;
        } else if(attTemplate->ulValueLen < size) {
          result = CKR_BUFFER_TOO_SMALL;
          attTemplate->ulValueLen = (CK_LONG)-1;
        } else {
          char *buf = (char *)attTemplate->pValue;
          for(unsigned int i = 0; i < size; i++) {
            buf[i] = bigModulus.byte_at(i);
          }
        }
      } else {
        result = CKR_ATTRIBUTE_TYPE_INVALID;
        attTemplate->ulValueLen = (CK_LONG)-1;
      }
      break;
    // Not tested
    case CKA_PUBLIC_EXPONENT:
      if(keyType == CKK_RSA) {
        IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(key);
        BigInt bigModulus = ifKey->get_e();
        unsigned int size = bigModulus.bytes();

        if(attTemplate->pValue == NULL_PTR) {
          attTemplate->ulValueLen = (CK_LONG)size;
        } else if(attTemplate->ulValueLen < size) {
          result = CKR_BUFFER_TOO_SMALL;
          attTemplate->ulValueLen = (CK_LONG)-1;
        } else {
          char *buf = (char *)attTemplate->pValue;
          for(unsigned int i = 0; i < size; i++) {
            buf[i] = bigModulus.byte_at(i);
          }
        }
      } else {
        result = CKR_ATTRIBUTE_TYPE_INVALID;
        attTemplate->ulValueLen = (CK_LONG)-1;
      }
      break;
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
      if(keyType == CKK_RSA && objectClass == CKO_PRIVATE_KEY) {
        result = CKR_ATTRIBUTE_SENSITIVE;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        result = CKR_ATTRIBUTE_TYPE_INVALID;
        attTemplate->ulValueLen = (CK_LONG)-1;
      }
      break;
    default:
      result = CKR_ATTRIBUTE_TYPE_INVALID;
      attTemplate->ulValueLen = (CK_LONG)-1;
      break;
  }

  return result;
}
