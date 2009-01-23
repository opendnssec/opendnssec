/*
 * sorter.c
 *
 * An ldns-based zone sorter
 *
 * Copyright (c) 2008 NLnet Labs
 * Written by Jelte Jansen
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>

#include <ldns/ldns.h>

/*
 * change this to 1 to shave about 10% off memory usage,
 * at the cost of extra realloc() calls
 */
#define DEFAULT_RR_MALLOC 20

struct rr_data_struct {
	ldns_rdf *name;
	ldns_rr_type type;
	ldns_buffer *rr_buf;
};
typedef struct rr_data_struct rr_data;

rr_data *
rr_data_new()
{
	rr_data *rd = LDNS_MALLOC(rr_data);
	rd->name = NULL;
	rd->rr_buf = ldns_buffer_new(DEFAULT_RR_MALLOC);
	return rd;
}

void
rr_data_free(rr_data *rd)
{
	if (!rd) {
		return;
	} else {
		if (rd->name) {
			ldns_rdf_deep_free(rd->name);
		}
		ldns_buffer_free(rd->rr_buf);
	}
	LDNS_FREE(rd);
}

ldns_rbnode_t *
rr_data2node(rr_data *d)
{
	ldns_rbnode_t *new_node;
	new_node = LDNS_MALLOC(ldns_rbnode_t);
	new_node->key = d;
	new_node->data = d;
	return new_node;
}

void
rr_data_node_free(ldns_rbnode_t *n, void *arg)
{
	(void) arg;
	if (n && n->data) {
		rr_data_free((rr_data *)n->data);
		LDNS_FREE(n);
	}
}
    
void
print_rr_data(FILE *out, rr_data *rrd)
{
	ldns_rr *rr = NULL;
	ldns_status status;
	size_t pos = 0;
	
	status = ldns_wire2rr(&rr,
					  rrd->rr_buf->_data,
					  rrd->rr_buf->_capacity,
					  &pos,
					  LDNS_SECTION_ANY_NOQUESTION);
	if (rr) {
		ldns_rr_print(out, rr);
		ldns_rr_free(rr);
	}
}

void
print_rrs(FILE *out, ldns_rbtree_t *rr_tree)
{
	ldns_rbnode_t *cur_node;

	cur_node = ldns_rbtree_first(rr_tree);

	while (cur_node && cur_node != LDNS_RBTREE_NULL) {
		print_rr_data(out, (rr_data *) cur_node->data);
		cur_node = ldns_rbtree_next(cur_node);
	}
}

int
compare_rr_data(const void *a, const void *b)
{
	int result;
	rr_data *ra, *rb;

	ra = (rr_data *) a;
	rb = (rr_data *) b;

	result = ldns_dname_compare(ra->name, rb->name);
	if (result == 0) {
		if (ra->type > rb->type) {
			result = 1;
		} else if (ra->type < rb->type) {
			result = -1;
		} else {
			result = ldns_rr_compare_wire(ra->rr_buf, rb->rr_buf);
		}
	}
	return result;
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: sorter [OPTIONS]\n");
	fprintf(out, "Sorts the zone read from stdin in canonical order.\n");
	fprintf(out, "If -n, -s or -i are given, the rrs are sorted according\n");
	fprintf(out, "to their NSEC3-hashed name.\n");
	fprintf(out, "The NSEC3 RRs are *not* added\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\tRead zone from <file> instead of stdin\n");
	fprintf(out, "-h\t\tShow this help\n");
	fprintf(out, "-n\t\tUse NSEC3 hashing as a sort base\n");
	fprintf(out, "-s <salt>\tUse this salt for NSEC3 hashed name calculation\n");
	fprintf(out, "-t <count>\tUse <count> iterations for NSEC3 hashed name calculation\n");
}

int
main(int argc, char **argv)
{
	/*
	 * Read an RR,
	 * convert it to wiredata
	 * store it along with either its name or its hashed name
	 * in an rbtree
	 */
	ldns_rbtree_t *rr_tree;
	ldns_rr *cur_rr;
	rr_data *cur_rr_data;

	/* options */
	int c;
	FILE *rr_file;
	bool nsec3 = false;
	uint8_t nsec3_algorithm = 1;
	uint16_t nsec3_iterations = 1;
	uint8_t nsec3_salt_length = 0;
	uint8_t *nsec3_salt = NULL;

	/* for readig RRs */
	ldns_status status;
	uint32_t default_ttl = 3600;
	ldns_rdf *origin = NULL;
	ldns_rdf *prev_name = NULL;
	int line_nr = 0;
	
	rr_file = stdin;

	while ((c = getopt(argc, argv, "f:hns:t:")) != -1) {
		switch (c) {
		case 'f':
			if (strncmp(optarg, "-", 2) != 0) {
				rr_file = fopen(optarg, "r");
			}
			if (!rr_file) {
				printf("Error reading %s: %s\n",
					  optarg,
					  strerror(errno));
			}
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 't':
			nsec3 = true;
			nsec3_iterations = atoi(optarg);
			if (nsec3_iterations == 0) {
				fprintf(stderr,
					   "Error parsing number for iterations: %s\n",
					   optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			nsec3 = true;
			break;
		case 's':
			if (strlen(optarg) % 2 != 0) {
				fprintf(stderr, "Salt value is not valid hex data, ");
				fprintf(stderr, "not a multiple of 2 characters\n");
				exit(EXIT_FAILURE);
			}
			nsec3_salt_length = (uint8_t) strlen(optarg) / 2;
			nsec3_salt = LDNS_XMALLOC(uint8_t, nsec3_salt_length);
			for (c = 0; c < (int) strlen(optarg); c += 2) {
				if (isxdigit(optarg[c]) && isxdigit(optarg[c+1])) {
					nsec3_salt[c/2] = 
						(uint8_t) ldns_hexdigit_to_int(optarg[c]) * 16 +
						ldns_hexdigit_to_int(optarg[c+1]);
				} else {
					fprintf(stderr,
						   "Salt value is not valid hex data.\n");
					exit(EXIT_FAILURE);
				}
			}

			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Error: extraneous arguments\n");
		usage(stderr);
		exit(EXIT_FAILURE);
	}


	rr_tree = ldns_rbtree_create(&compare_rr_data);

	status = ldns_rr_new_frm_fp_l(&cur_rr,
							rr_file,
							&default_ttl, 
							&origin,
							&prev_name,
							&line_nr);

	while (status == LDNS_STATUS_OK ||
		  status == LDNS_STATUS_SYNTAX_ORIGIN ||
		  status == LDNS_STATUS_SYNTAX_TTL) {
		if (status == LDNS_STATUS_OK) {
			cur_rr_data = rr_data_new();
			if (!nsec3) {
				cur_rr_data->name = ldns_rdf_clone(ldns_rr_owner(cur_rr));
			} else {
				cur_rr_data->name = ldns_nsec3_hash_name(
								    ldns_rr_owner(cur_rr),
								    nsec3_algorithm,
								    nsec3_iterations,
								    nsec3_salt_length,
								    nsec3_salt);
			}
			cur_rr_data->type = ldns_rr_get_type(cur_rr);
			
			status = ldns_rr2buffer_wire(cur_rr_data->rr_buf,
								    cur_rr,
								    LDNS_SECTION_ANY_NOQUESTION);
			
			
			ldns_rbtree_insert(rr_tree,
						    rr_data2node(cur_rr_data));
			
			ldns_rr_free(cur_rr);
			cur_rr = NULL;
		}

		status = ldns_rr_new_frm_fp_l(&cur_rr,
								rr_file,
								&default_ttl, 
								&origin,
								&prev_name,
								&line_nr);
	}
	if (status == LDNS_STATUS_OK && cur_rr) {
		ldns_rr_free(cur_rr);
	} else if (status != LDNS_STATUS_SYNTAX_EMPTY && 
			 status != LDNS_STATUS_SYNTAX_TTL &&
			 status != LDNS_STATUS_SYNTAX_ORIGIN) {
		fprintf(stderr, "Parse error in input line %d: %s\n",
			   line_nr,
			   ldns_get_errorstr_by_id(status));
		exit(EXIT_FAILURE);
	}

	/*printf("Final status: %s\n", ldns_get_errorstr_by_id(status));*/

	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (nsec3_salt) {
		LDNS_FREE(nsec3_salt);
	}

	print_rrs(stdout, rr_tree);

	/* free all tree entries */
	ldns_traverse_postorder(rr_tree,
					    rr_data_node_free,
					    NULL);

	ldns_rbtree_free(rr_tree);
	
	if (rr_file != stdin) {
		fclose(rr_file);
	}

	return 0;
}
