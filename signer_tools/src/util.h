#define MAX_LINE_LEN 4096

#include <ldns/ldns.h>

int read_line(FILE *input, char *line);
void rr_list_clear(ldns_rr_list *rr_list);
