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

void SoftFind::addFind(CK_OBJECT_HANDLE newObject) {
  if(next == NULL_PTR) {
    findObject = newObject;
    next = new SoftFind();
  } else {
    next->addFind(newObject);
  }
}
