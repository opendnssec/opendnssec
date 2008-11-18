char* checkHSMDir();
char* getNewFileName();
char* getFilePath(char *fileName);
bool saveKeyFile(SoftHSMInternal *pSoftH, char *fileName, Private_Key *key);
void openAllFiles(SoftHSMInternal *pSoftH);
CK_RV readKeyFile(SoftHSMInternal *pSoftH, char* file);
