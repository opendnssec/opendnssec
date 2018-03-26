struct item {
    ldns_rr* rr;
};

struct itemsig {
    ldns_rr* rr;
    char* keylocator;
    int keyflags;
};

struct itemset {
    ldns_rr_type rrtype;
    int nitems;
    struct item* items;
    int nsignatures;
    struct itemsig* signatures;
};

struct dictionary_struct {
    ldns_rr* rrname;
    char* name;
    int revision;
    int marker;
    ldns_rr* spanhashrr;
    char* spanhash;
    int nspansignatures;
    struct itemsig* spansignatures;
    int* validupto;
    int* validfrom;
    int* expiry;
    int nitemsets;
    struct itemset* itemsets;
    char* tmpRevision;
    char* tmpNameSerial;
    char* tmpValidFrom;
    char* tmpValidUpto;
    char* tmpExpiry;
};
