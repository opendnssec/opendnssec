class SoftSession {
  public:
    SoftSession();
    ~SoftSession();

    bool isReadOnly();

    CK_VOID_PTR pApplication;
    CK_NOTIFY Notify;
  private:
    bool readOnly;
};

SoftSession::SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;
  readOnly = false;
}

SoftSession::~SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;
}

bool SoftSession::isReadOnly() {
  return readOnly;
}
