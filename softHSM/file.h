char* checkHSMDir();
char* getNewFileName();
char* getFilePath(char *fileName);
bool saveKeyFile(SoftHSMInternal *pSoftH, char *fileName, Private_Key *key);
bool removeKeyFile(SoftHSMInternal *pSoftH, char *fileName);
void openAllFiles(SoftHSMInternal *pSoftH);
CK_RV readKeyFile(SoftHSMInternal *pSoftH, char* file);
