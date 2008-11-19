/************************************************************
*
* This class defines a session
* It holds the current state of the session
*
************************************************************/

SoftSession::SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;
  readOnly = false;
  findAnchor = NULL_PTR;
  findCurrent = NULL_PTR;
  findInitialized = false;
}

SoftSession::~SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  if(findAnchor != NULL_PTR) {
    delete findAnchor;
    findAnchor = NULL_PTR;
  }

  findCurrent = NULL_PTR;
}

bool SoftSession::isReadOnly() {
  return readOnly;
}
