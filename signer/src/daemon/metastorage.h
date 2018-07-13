#ifndef METASTORAGE_H
#define METASTORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

int metastorage(const char* name, void** item);
int metastorageget(const char* name, void** item);
int metastorageput(void* item);

#ifdef __cplusplus
}
#endif

#endif /* METASTORAGE_H */
