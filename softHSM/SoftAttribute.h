/************************************************************
*
* This class handles an object's attributes.
* It creates a chain of object attributes.
*
************************************************************/

class SoftAttribute {
  public:
    SoftAttribute();
    ~SoftAttribute();

    void addAttribute(CK_ATTRIBUTE *objectAttribute);
    CK_ATTRIBUTE* getAttribute(CK_ATTRIBUTE_TYPE type);
    CK_BBOOL matchAttribute(CK_ATTRIBUTE *attTemplate);

  private:
    SoftAttribute *next;
    CK_ATTRIBUTE *objectAttribute;
};
