/************************************************************
*
* This class defines a session
* It holds the current state of the session
*
************************************************************/

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

    Pipe *digestPipe;
    unsigned int digestSize;
    bool digestInitialized;

    PK_Signer *pkSigner;
    bool signSinglePart;
    unsigned int signSize;
    bool signInitialized;

  private:
    bool readOnly;
};
