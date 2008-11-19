/************************************************************
*
* This class handles the search results.
* It creates a chain of object handles.
*
************************************************************/

SoftFind::SoftFind() {
  next = NULL_PTR;
  findObject = 0;
}

SoftFind::~SoftFind() {
  if(next != NULL_PTR) {
    delete next;
    next = NULL_PTR;
  }
}

// Add the object handle if we are the last one in the chain.
// Or else pass it on the next one.

void SoftFind::addFind(CK_OBJECT_HANDLE newObject) {
  if(next == NULL_PTR) {
    findObject = newObject;
    next = new SoftFind();
  } else {
    next->addFind(newObject);
  }
}
