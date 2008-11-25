/************************************************************
*
* This class handles an object's attributes.
* It creates a chain of object attributes.
*
************************************************************/

SoftAttribute::SoftAttribute() {
  next = NULL_PTR;
  objectAttribute = NULL_PTR;
}

SoftAttribute::~SoftAttribute() {
  if(next != NULL_PTR) {
    delete next;
    next = NULL_PTR;
  }
  if(objectAttribute != NULL_PTR) {
    if(objectAttribute->pValue != NULL_PTR) {
      free(objectAttribute->pValue);
      objectAttribute->pValue = NULL_PTR;
    }
    free(objectAttribute);
    objectAttribute = NULL_PTR;
  }
}

// Add the attribute if we are the last one in the chain.
// Or else pass it on the next one.

void SoftAttribute::addAttribute(CK_ATTRIBUTE *oAttribute) {
  if(next == NULL_PTR) {
    objectAttribute = oAttribute;
    next = new SoftAttribute();
  } else {
    next->addAttribute(oAttribute);
  }
}

// Search after a given attribute type.

CK_ATTRIBUTE* SoftAttribute::getAttribute(CK_ATTRIBUTE_TYPE type) {
  if(next != NULL_PTR) {
    if(objectAttribute != NULL_PTR && objectAttribute->type == type) {
      return objectAttribute;
    } else {
      return next->getAttribute(type);
    }
  } else {
    return NULL_PTR;
  }
}

CK_BBOOL SoftAttribute::matchAttribute(CK_ATTRIBUTE *attTemplate) {
  if(next != NULL_PTR) {
    if(objectAttribute->type == attTemplate->type &&
       objectAttribute->ulValueLen == attTemplate->ulValueLen &&
       memcmp(objectAttribute->pValue, attTemplate->pValue, 
         objectAttribute->ulValueLen) == 0) {
      return CK_TRUE;
    } else {
      return next->matchAttribute(attTemplate);
    }
  } else {
    return CK_FALSE;
  }
}
