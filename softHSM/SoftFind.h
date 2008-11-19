/************************************************************
*
* This class handles the search results.
* It creates a chain of object handles.
*
************************************************************/

class SoftFind {
  public:
    SoftFind();
    ~SoftFind();

    void addFind(CK_OBJECT_HANDLE newObject);

    SoftFind *next;
    CK_OBJECT_HANDLE findObject;
};
