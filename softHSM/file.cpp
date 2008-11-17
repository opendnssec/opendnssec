char *checkHSMDir() {
  char *homeDir = getenv("HOME");
  char *directory = (char*)malloc(strlen(homeDir) + 10);

  snprintf(directory, strlen(homeDir) + 10, "%s/.softHSM", homeDir);

  struct stat st;
  if(stat(directory, &st) != 0) {
    mkdir(directory, S_IRUSR | S_IWUSR | S_IXUSR);
  }

  return directory;
}

char *getNewFileName() {
  char *fileName = (char *)malloc(19);

  struct timeval now;
  gettimeofday(&now, NULL);
  struct tm *timeinfo = gmtime(&now.tv_sec);

  snprintf(fileName, 19, "%02u%02u%02u%02u%02u%02u%06u", timeinfo->tm_year - 100, timeinfo->tm_mon + 1, timeinfo->tm_mday, 
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, (unsigned int)now.tv_usec);

  return fileName;
}

char *getFilePath(char *fileName) {
  char *directory = checkHSMDir();
  char *filePath = (char *)malloc(strlen(directory) + 24);

  snprintf(filePath, strlen(directory) + 24, "%s/%s.pem", directory, fileName);

  return filePath;
}

bool saveKeyFile(char *fileName, Private_Key *key) {
  std::ofstream priv(getFilePath(fileName));
  AutoSeeded_RNG *rng = new AutoSeeded_RNG();

  if(priv.fail()) {
    return false;
  }

  priv << PKCS8::PEM_encode(*key, *rng, softHSM->pin);
  priv.close();

  return true;
}
