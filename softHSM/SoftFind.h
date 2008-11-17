class SoftFind {
  public:
    SoftFind();
    ~SoftFind();

    void addFind(CK_OBJECT_HANDLE newObject);

    SoftFind *next;
    CK_OBJECT_HANDLE findObject;
};
