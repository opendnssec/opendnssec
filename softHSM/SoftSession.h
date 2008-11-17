class SoftSession {
  public:
    SoftSession();
    ~SoftSession();

    bool isReadOnly();
    CK_VOID_PTR pApplication;
    CK_NOTIFY Notify;

    SoftFind *findAnchor;
    SoftFind *findCurrent;
    bool findInitialized;

  private:
    bool readOnly;
};
