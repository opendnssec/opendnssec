/*
 * get_serial
 * 
 * This tool takes a zone file and prints the serial number found
 * in the (first) SOA rr it reads
 * 
 * by default, it will read a zone from stdin
 * if the file is not found, or there is no soa record, 0 will be
 * printed (and non-zero returned)
 */
#include <errno.h>
#include <getopt.h>

#include <ldns/ldns.h>
#include "util.h"

uint32_t get_serial(ldns_rr *rr) 
{
	uint32_t serial = 0;
	if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
		serial = ldns_rdf2native_int32(ldns_rr_rdf(rr, 2));
	}
	return serial;
}

void 
usage(FILE *out)
{
	fprintf(out, "Usage: get_serial [options]\n");
	fprintf(out, "options:\n");
	fprintf(out, "-f <file>: read zone from file instead of stdin\n");
	fprintf(out, "-h: show this text\n");
}

int main(int argc, char **argv)
{
	ldns_rr *cur_rr;
	char line[MAX_LINE_LEN];
	int line_len = 0;
	FILE *input_file = stdin;
	FILE *output_file = stdout;
	ldns_status status;
	uint32_t serial;
	char c;
	
	while ((c = getopt(argc, argv, "f:h")) != -1) {
		switch(c) {
		case 'f':
			input_file = fopen(optarg, "r");
			if (!input_file) {
				fprintf(stderr,
				        "Unable to open %s for reading: %s\n",
				        optarg,
				        strerror(errno));
				fprintf(output_file, "0\n");
				exit(1);
			}
			break;
		case 'h':
			usage(stdout);
			exit(0);
			break;
		}
	}

	while (line_len >= 0) {
		line_len = read_line(input_file, line);
		if (line_len > 0) {
			if (line[0] != ';') {
				status = ldns_rr_new_frm_str(&cur_rr, line, 0, NULL, NULL);
				if (status == LDNS_STATUS_OK) {
					serial = get_serial(cur_rr);
					ldns_rr_free(cur_rr);
					if (serial != 0) {
						fprintf(output_file, "%u\n", (unsigned int) serial);
						return 0;
					}
				}
			}
		}
	}
	fprintf(output_file, "0\n");
	return 1;
}

