int PK_LinkLib(char *pklib);
int PK_UnlinkLib();
int PK_Startup(int slot, char *pin);
int PK_Shutdown();
void PK_RemoveObject(uuid_t uuid);
void PK_ListObjects();
void PK_GenerateObject(long keysize);