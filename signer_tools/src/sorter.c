/*
 * sorter.c
 *
 * An ldns-based zone sorter
 * It also marks empty non-terminals, glue and out-of-zone data, and
 * converts those to comments.
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
#include "util.h"

/*
 * change this to 1 to shave about 10% off memory usage,
 * at the cost of extra realloc() calls
 */
#define DEFAULT_RR_MALLOC 20

struct rr_data_struct {
	ldns_rdf *name;
	ldns_rr_type type;
	ldns_buffer *rr_buf;
	ldns_rr *ent_for;
	int glue;
	int ooz;
};
typedef struct rr_data_struct rr_data;

rr_data *
rr_data_new()
{
	rr_data *rd = LDNS_MALLOC(rr_data);
	rd->name = NULL;
	rd->rr_buf = ldns_buffer_new(DEFAULT_RR_MALLOC);
	rd->ent_for = NULL;
	rd->glue = 0;
	rd->ooz = 0;
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
	if (rd->ent_for) {
		ldns_rr_free(rd->ent_for);
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

int
node_for_rr_name(ldns_rr *rr, ldns_rbnode_t *node)
{
	rr_data *cur_data;
	ldns_rr *cur_rr;
	size_t pos = 0;
	ldns_status status;
	
	cur_data = (rr_data *) node->data;
	if (!cur_data->ent_for) {
		status = ldns_wire2rr(&cur_rr,
								cur_data->rr_buf->_data,
								cur_data->rr_buf->_capacity,
								&pos,
								LDNS_SECTION_ANY_NOQUESTION);
		if (status == LDNS_STATUS_OK &&
			ldns_dname_compare(ldns_rr_owner(rr),
							   ldns_rr_owner(cur_rr)) == 0) {
				ldns_rr_free(cur_rr);
				return 1;
		}
		ldns_rr_free(cur_rr);
	}
	return 0;
}

int
ent_for_ns_only(ldns_rr *rr, ldns_rbtree_t *tree)
{
	ldns_rbnode_t *cur_node;
	rr_data *cur_data;

	/* find the rr in the tree, and check all rrs with the same (hashed)
	 * name to have the ns type
	 */
	cur_node = ldns_rbtree_first(tree);
	while (cur_node != LDNS_RBTREE_NULL) {
		if (node_for_rr_name(rr, cur_node)) {
			while (cur_node != LDNS_RBTREE_NULL) {
				cur_data = (rr_data *) cur_node->data;
				if (cur_data->type != LDNS_RR_TYPE_NS) {
					return 0;
				}
				if (!node_for_rr_name(rr, cur_node)) {
					return 1;
				}
				cur_node = ldns_rbtree_next(cur_node);
			}
			return 1;
		}
		cur_node = ldns_rbtree_next(cur_node);
	}
	return 0;
}
    
void
print_rr_data(FILE *out, rr_data *rrd, ldns_rbtree_t *tree)
{
	ldns_rr *rr = NULL;
	ldns_rdf *dname;
	ldns_status status;
	size_t pos = 0;
	
	if (rrd->ooz) {
		printf("; Out-of-zone data: ");
	} else if (rrd->glue) {
		printf("; Glue: ");
	}
	if (rrd->ent_for) {
		pos = 0;
		status = ldns_wire2dname(&dname, rrd->rr_buf->_data, rrd->rr_buf->_capacity, &pos);
		if (status != LDNS_STATUS_OK) {
			return;
		}
		if (ldns_rr_get_type(rrd->ent_for) == LDNS_RR_TYPE_NS &&
		    ent_for_ns_only(rrd->ent_for, tree)
		) {
			printf("; Empty non-terminal to NS: ");
		} else {
			printf("; Empty non-terminal: ");
		}
		ldns_rdf_print(stdout, dname);
		printf("\n");
		ldns_rdf_deep_free(dname);
	} else {
		status = ldns_wire2rr(&rr,
						  rrd->rr_buf->_data,
						  rrd->rr_buf->_capacity,
						  &pos,
						  LDNS_SECTION_ANY_NOQUESTION);
		if (rr) {
			ldns_rr_print(out, rr);
			ldns_rr_free(rr);
		} else {
			fprintf(stderr, "error parsing rr\n");
		}
	}
}

/* hmz, can we do this more efficiently? since we may be sorting
 * in nsec3 space, we cannot simply go to the previous node in the
 * tree... */
/* rr_data should be of type A or AAAA, and ent_for must have been
 * checked for not NULL */
void
mark_possible_glue(rr_data *rrd, ldns_rbtree_t *rr_tree, ldns_rdf *origin)
{
	ldns_rbnode_t *cur_node;
	rr_data *cur_data;
	ldns_rr *rr, *cur_rr;
	size_t pos = 0;
	(void) ldns_wire2rr(&rr,
					  rrd->rr_buf->_data,
					  rrd->rr_buf->_capacity,
					  &pos,
					  LDNS_SECTION_ANY_NOQUESTION);
	if (!rr || !ldns_dname_is_subdomain(ldns_rr_owner(rr), origin)) {
		return;
	}
	cur_node = ldns_rbtree_first(rr_tree);
	while (cur_node != LDNS_RBTREE_NULL) {
		cur_data = (rr_data *) cur_node->data;
		if (cur_data->type == LDNS_RR_TYPE_NS) {
			pos = 0;
			(void) ldns_wire2rr(&cur_rr,
							  cur_data->rr_buf->_data,
							  cur_data->rr_buf->_capacity,
							  &pos,
							  LDNS_SECTION_ANY_NOQUESTION);
			if (cur_rr && !ldns_dname_compare(ldns_rr_owner(cur_rr), origin) == 0) {
				if (ldns_dname_is_subdomain(ldns_rr_owner(rr),
				                            ldns_rr_owner(cur_rr))) {
					rrd->glue = 1;
				}
			}
		}
		cur_node = ldns_rbtree_next(cur_node);
	}
}

void
print_rrs(FILE *out, ldns_rbtree_t *rr_tree, ldns_rdf *origin)
{
	ldns_rbnode_t *cur_node;
	rr_data *cur_data;

	cur_node = ldns_rbtree_first(rr_tree);

	while (cur_node && cur_node != LDNS_RBTREE_NULL) {
		cur_data = (rr_data *) cur_node->data;
		/* mark glue */
		if (!cur_data->ent_for &&
		     (cur_data->type == LDNS_RR_TYPE_A ||
		      cur_data->type == LDNS_RR_TYPE_AAAA)) {
			mark_possible_glue(cur_data, rr_tree, origin);
		}
		print_rr_data(out, (rr_data *) cur_node->data, rr_tree);
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
	fprintf(out, "-o <file>\tWrite sorted zone to <file> instead of stdout\n");
	fprintf(out, "-h\t\tShow this help\n");
	fprintf(out, "-n\t\tUse NSEC3 hashing as a sort base\n");
	fprintf(out, "-s <salt>\tUse this salt for NSEC3 hashed name calculation\n");
	fprintf(out, "-t <count>\tUse <count> iterations for NSEC3 hashed name calculation\n");
}

/* hmm, this might be a good contender for inclusion in ldns */
/* nonterms will be malloced, and must be freed */
/* freeing of the dname rdfs in it is also for the caller */
int
find_empty_nonterminals(ldns_rdf *zone_name,
                        ldns_rdf *cur_name,
                        ldns_rdf *next_name,
                        ldns_rdf **nonterminals)
{
	uint16_t i, cur_label_count, next_label_count;
	uint16_t zone_label_count;
	ldns_rdf *l1, *l2;
	int lpos;
	ldns_rdf *new_name;
	int count = 0;
	
	/* Since the names are in canonical order, we can
	 * recognize empty non-terminals by their labels;
	 * every label after the first one on the next owner
	 * name is a non-terminal if it either does not exist
	 * in the current name or is different from the same
	 * label in the current name (counting from the end)
	 */
	zone_label_count = ldns_dname_label_count(zone_name);
	cur_label_count = ldns_dname_label_count(cur_name);
	next_label_count = ldns_dname_label_count(next_name);

	//*nonterminals = malloc(sizeof(ldns_rdf *) * next_label_count);
	for (i = 1; i < next_label_count - zone_label_count; i++) {
		lpos = cur_label_count - next_label_count + i;
		if (lpos >= 0) {
			l1 = ldns_dname_label(cur_name, lpos);
		} else {
			l1 = NULL;
		}
		l2 = ldns_dname_label(next_name, i);

		if (!l1 || ldns_dname_compare(l1, l2) != 0) {
			/* We have an empty nonterminal, add it to the
			 * list
			 */
			new_name = ldns_dname_clone_from(next_name, i);
			if (!new_name) {
				return -1;
			}
			
			nonterminals[count] = new_name;
			count++;
		}
		ldns_rdf_deep_free(l1);
		ldns_rdf_deep_free(l2);
	}
	return count;
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
	ldns_rr *cur_rr, *prev_rr;
	rr_data *cur_rr_data;
	
	/* empty nonterminal detection */
	ldns_rdf *empty_nonterminals[100];
	int empty_nonterminal_count, eni;

	/* options */
	int c;
	FILE *rr_file;
	FILE *out_file;
	bool nsec3 = false;
	uint8_t nsec3_algorithm = 1;
	uint16_t nsec3_iterations = 1;
	uint8_t nsec3_salt_length = 0;
	uint8_t *nsec3_salt = NULL;

	/* for readig RRs */
	ldns_status status = LDNS_STATUS_OK;
	uint32_t default_ttl = 3600;
	ldns_rdf *origin = NULL;
	ldns_rdf *prev_name = NULL;
	int line_nr = 0;
	
	int line_len;
	char line[MAX_LINE_LEN];
	
	rr_file = stdin;
	out_file = stdout;

	while ((c = getopt(argc, argv, "a:f:hno:s:t:")) != -1) {
		switch (c) {
		case 'a':
			nsec3_algorithm = (uint8_t) atoi(optarg);
			if (nsec3_algorithm != 1) {
				fprintf(stderr, "Error, only SHA1 is supported for NSEC3 hashing\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'f':
			if (strncmp(optarg, "-", 2) != 0) {
				rr_file = fopen(optarg, "r");
			}
			if (!rr_file) {
				printf("Error reading %s: %s\n",
					  optarg,
					  strerror(errno));
				exit(1);
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
		case 'o':
			origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, optarg);
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
	
	if (!origin) {
		fprintf(stderr, "Error, no origin specified (-o)\n");
		exit(EXIT_FAILURE);
	}

	rr_tree = ldns_rbtree_create(&compare_rr_data);

	prev_rr = NULL;

	line_len = 0;
	while (line_len >= 0) {
		line_len = read_line(rr_file, line);
		if (line_len > 0) {
			if (line[0] == '$') {
				/* ignore directives for now */
				continue;
			} else if (line[0] == ';') {
				/* pass through comments */
				fprintf(stdout, "%s\n", line);
			} else {
				status = ldns_rr_new_frm_str(&cur_rr,
				                             line,
				                             default_ttl,
				                             origin,
				                             &prev_name);
				if (status == LDNS_STATUS_OK) {
					cur_rr_data = rr_data_new();

					if (!(ldns_dname_compare(ldns_rr_owner(cur_rr), origin) == 0 ||
					      ldns_dname_is_subdomain(ldns_rr_owner(cur_rr), origin))) {
						cur_rr_data->ooz = 1;
					} else if (prev_rr && nsec3) {
						empty_nonterminal_count = find_empty_nonterminals(origin,
												   ldns_rr_owner(prev_rr),
												   ldns_rr_owner(cur_rr),
												   empty_nonterminals);
						for (eni = 0; eni < empty_nonterminal_count; eni++) {
							cur_rr_data->name = ldns_nsec3_hash_name(
												empty_nonterminals[eni],
												nsec3_algorithm,
												nsec3_iterations,
												nsec3_salt_length,
												nsec3_salt);
							ldns_dname_cat(cur_rr_data->name, origin);
							cur_rr_data->type = LDNS_RR_TYPE_NSEC3;
							cur_rr_data->ent_for = ldns_rr_clone(cur_rr);
							/* original name */
							status = ldns_rdf2buffer_wire(cur_rr_data->rr_buf,
														  empty_nonterminals[eni]);
							ldns_rbtree_insert(rr_tree, rr_data2node(cur_rr_data));
							cur_rr_data = rr_data_new();
							ldns_rdf_deep_free(empty_nonterminals[eni]);
						}
					}

					if (!nsec3) {
						cur_rr_data->name = ldns_rdf_clone(ldns_rr_owner(cur_rr));
					} else {
						cur_rr_data->name = ldns_nsec3_hash_name(
											ldns_rr_owner(cur_rr),
											nsec3_algorithm,
											nsec3_iterations,
											nsec3_salt_length,
											nsec3_salt);
						ldns_dname_cat(cur_rr_data->name, origin);
					}
					cur_rr_data->type = ldns_rr_get_type(cur_rr);
					
					status = ldns_rr2buffer_wire(cur_rr_data->rr_buf,
											cur_rr,
											LDNS_SECTION_ANY_NOQUESTION);
					
					ldns_rbtree_insert(rr_tree,
									rr_data2node(cur_rr_data));
					
					ldns_rr_free(prev_rr);
					prev_rr = cur_rr;
					cur_rr = NULL;
				}
			}
		line_nr++;
		}
	}
	if (status == LDNS_STATUS_OK) {
		if (cur_rr) {
			ldns_rr_free(cur_rr);
		}
	} else if (status != LDNS_STATUS_SYNTAX_EMPTY && 
	           status != LDNS_STATUS_SYNTAX_TTL &&
	           status != LDNS_STATUS_SYNTAX_ORIGIN) {
		fprintf(stderr, "Parse error in input line %d: %s\n",
			    line_nr,
			    ldns_get_errorstr_by_id(status));
		exit(EXIT_FAILURE);
	}

	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (nsec3_salt) {
		LDNS_FREE(nsec3_salt);
	}
	if (prev_rr) {
		ldns_rr_free(prev_rr);
	}

	print_rrs(out_file, rr_tree, origin);

	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	/* free all tree entries */
	ldns_traverse_postorder(rr_tree,
					    rr_data_node_free,
					    NULL);

	ldns_rbtree_free(rr_tree);
	
	if (rr_file != stdin) {
		fclose(rr_file);
	}
	if (out_file != stdout) {
		fclose(out_file);
	}

	return 0;
}
