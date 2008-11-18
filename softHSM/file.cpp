char* checkHSMDir() {
  char *homeDir = getenv("HOME");
  char *directory = (char*)malloc(strlen(homeDir) + 10);

  snprintf(directory, strlen(homeDir) + 10, "%s/.softHSM", homeDir);

  struct stat st;
  if(stat(directory, &st) != 0) {
    mkdir(directory, S_IRUSR | S_IWUSR | S_IXUSR);
  }

  return directory;
}

char* getNewFileName() {
  char *fileName = (char *)malloc(19);

  struct timeval now;
  gettimeofday(&now, NULL);
  struct tm *timeinfo = gmtime(&now.tv_sec);

  snprintf(fileName, 19, "%02u%02u%02u%02u%02u%02u%06u", timeinfo->tm_year - 100, timeinfo->tm_mon + 1, timeinfo->tm_mday, 
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, (unsigned int)now.tv_usec);

  return fileName;
}

char* getFilePath(char *fileName) {
  char *directory = checkHSMDir();
  char *filePath = (char *)malloc(strlen(directory) + 24);

  snprintf(filePath, strlen(directory) + 24, "%s/%s.pem", directory, fileName);

  free(directory);
  return filePath;
}

bool saveKeyFile(SoftHSMInternal *pSoftH, char *fileName, Private_Key *key) {
  if(fileName == NULL_PTR || key == NULL_PTR || pSoftH == NULL_PTR || !pSoftH->isLoggedIn()) {
    return false;
  }

  std::ofstream priv(getFilePath(fileName));
  AutoSeeded_RNG *rng = pSoftH->rng;

  if(priv.fail()) {
    return false;
  }

  priv << PKCS8::PEM_encode(*key, *rng, pSoftH->getPIN());
  priv.close();

  return true;
}

void openAllFiles(SoftHSMInternal *pSoftH) {
  DIR *dir = opendir(checkHSMDir());
  struct dirent *entry;
  char *file;
  CK_OBJECT_HANDLE hObject;

  while ((entry = readdir(dir)) != NULL) {
    if(strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      file = strtok(entry->d_name,".");
      hObject = pSoftH->getObjectByNameAndClass(file, CKO_PUBLIC_KEY);
      if(hObject == 0) {
        readKeyFile(pSoftH, file);
      }
    }
  }

  closedir(dir);
}

CK_RV readKeyFile(SoftHSMInternal *pSoftH, char* file) {
  if(!pSoftH->isLoggedIn()) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  Private_Key *privkey;
  AutoSeeded_RNG *rng = pSoftH->rng;
  CK_RV result;

  try {
    privkey = PKCS8::load_key(getFilePath(file), *rng, pSoftH->getPIN());
  }
  catch(Botan::Decoding_Error e) {
    return CKR_USER_NOT_LOGGED_IN;
  }
  catch(Botan::Exception e) {
    return CKR_GENERAL_ERROR;
  }

  SoftObject *privateKey = new SoftObject();
  SoftObject *publicKey = new SoftObject();

  result = privateKey->addKey(privkey, CKO_PRIVATE_KEY, file);
  if(result != CKR_OK) {
    return result;
  }

  result = publicKey->addKey(privkey, CKO_PUBLIC_KEY, file);
  if(result != CKR_OK) {
    return result;
  }

  int privateRef = pSoftH->addObject(privateKey);
  int publicRef = pSoftH->addObject(publicKey);

  if(!publicRef || !privateRef) {
    return CKR_DEVICE_MEMORY;
  }

  return CKR_OK;
}
