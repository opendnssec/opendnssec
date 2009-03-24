#include "cryptoki.h"

void InitAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n);
void AddAttribute(CK_ATTRIBUTE_PTR attr, int type, const void *Value, size_t size);
void FlushAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n);

const void* Get_Val(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n);
CK_ULONG Get_Val_ul(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n);
unsigned int Get_Val_Len(CK_ATTRIBUTE_PTR attr,unsigned int type,unsigned int n);
const char* get_rv_str(CK_RV rv);
void check_rv (const char *message,CK_RV rv);
CK_ULONG LabelExists(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label);
CK_ULONG IDExists(CK_SESSION_HANDLE ses, uuid_t uu);
CK_SLOT_ID GetSlot();
void bin2hex (int len, unsigned char *binnum, char *hexnum);
