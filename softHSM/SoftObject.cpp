/************************************************************
*
* This class defines an object, which contains
* a crypto key, private or public.
*
************************************************************/

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

// Adds a key to the object.
// We only support RSA and DSA storage.

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

// Saves the key to the disk.
// But only if it is a private key.

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

// Get the attribute value for the object.

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
    // The Label and ID is representad by the string fileName.
    // Which is the date/time when the key was created.
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
    case CKA_SENSITIVE:
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
    case CKA_DERIVE:
    case CKA_VERIFY_RECOVER:
    case CKA_SIGN_RECOVER:
      if(attTemplate->pValue == NULL_PTR) {
        attTemplate->ulValueLen = (CK_LONG)sizeof(oFalse);
      } else if(attTemplate->ulValueLen < sizeof(oFalse)) {
        result = CKR_BUFFER_TOO_SMALL;
        attTemplate->ulValueLen = (CK_LONG)-1;
      } else {
        memcpy(attTemplate->pValue, &oFalse, sizeof(oFalse));
      }
      break;
    case CKA_KEY_GEN_MECHANISM:
      if(keyType == CKK_RSA) {
        CK_MECHANISM_TYPE mech = CKM_RSA_PKCS_KEY_PAIR_GEN;

        if(attTemplate->pValue == NULL_PTR) {
          attTemplate->ulValueLen = (CK_LONG)sizeof(mech);
        } else if(attTemplate->ulValueLen < sizeof(mech)) {
          result = CKR_BUFFER_TOO_SMALL;
          attTemplate->ulValueLen = (CK_LONG)-1;
        } else {
          memcpy(attTemplate->pValue, &mech, sizeof(mech));
        }
      } else {
        result = CKR_ATTRIBUTE_TYPE_INVALID;
        attTemplate->ulValueLen = (CK_LONG)-1;
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
    // The values are correct, but perhaps in reverse order?
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
    // The values are correct, but perhaps in reverse order?
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
