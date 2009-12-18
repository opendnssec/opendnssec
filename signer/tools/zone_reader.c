/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This tool reads sorted zone files.
 * It resorts the zone according in the needed order (either canonical
 * or in NSEC3 order)
 * It also marks empty non-terminals, glue and out-of-zone data, and
 * converts those to comments. For NSEC3, it adds an NSEC3PARAM RR if
 * not present. NSEC3PARAMS with other parameters are removed.
 * RRSIG records will be sorted right after the RRset they cover
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>

#include <ldns/ldns.h>
#include "util.h"

/* maximum depth of $INCLUDE directives */
#define MAX_FILES 10

/*
 * change this to 1 to shave about 10% off memory usage,
 * at the cost of extra realloc() calls
 */
#define DEFAULT_RR_MALLOC 20

struct rr_data_struct {
	ldns_rdf *name;
	ldns_rdf *orig_name; /* set in case of NSEC3 where name is hashed */
	ldns_rr_type type;
	ldns_rr_type type_covered; /* set in case of RRSIG */
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
	rd->orig_name = NULL;
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
	}
	if (rd->name) {
		ldns_rdf_deep_free(rd->name);
	}
	if (rd->orig_name) {
		ldns_rdf_deep_free(rd->orig_name);
	}
	ldns_buffer_free(rd->rr_buf);
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

ldns_rbnode_t *
dname2node(ldns_rdf *d)
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
rr_dname_node_free(ldns_rbnode_t *n, void *arg)
{
	(void) arg;
	if (n) {
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

int
ent_for_glue(ldns_rr *rr, ldns_rbtree_t *tree)
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
				if (cur_data->glue) {
					return 1;
				}
				if (!node_for_rr_name(rr, cur_node)) {
					return 0;
				}
				cur_node = ldns_rbtree_next(cur_node);
			}
			return 0;
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
		fprintf(out, "; Out-of-zone data: ");
	} else if (rrd->glue) {
		fprintf(out, "; Glue: ");
	}

	if (rrd->ent_for) {
		pos = 0;
		status = ldns_wire2dname(&dname, rrd->rr_buf->_data, rrd->rr_buf->_capacity, &pos);
		if (status != LDNS_STATUS_OK) {
			return;
		}
		if (ldns_rr_get_type(rrd->ent_for) == LDNS_RR_TYPE_NS &&
		    ent_for_ns_only(rrd->ent_for, tree)) {
			fprintf(out, "; Empty non-terminal to NS: ");
			ldns_rdf_print(out, dname);
			fprintf(out, "\n");
		} else if (!ent_for_glue(rrd->ent_for, tree)) {
			fprintf(out, "; Empty non-terminal: ");
			ldns_rdf_print(out, dname);
			fprintf(out, "\n");
		}
		ldns_rdf_deep_free(dname);
	} else {
		status = ldns_wire2rr(&rr,
						  rrd->rr_buf->_data,
						  rrd->rr_buf->_capacity,
						  &pos,
						  LDNS_SECTION_ANY_NOQUESTION);
		if (status == LDNS_STATUS_OK) {
			ldns_rr_print(out, rr);

			/* really need to fflush? */
			fflush(out);
			ldns_rr_free(rr);
		} else {
			fprintf(stderr, "error parsing rr: %s\n", ldns_get_errorstr_by_id(status));
			exit(1);
		}
	}
}

/* hmz, can we do this more efficiently? since we may be sorting
 * in nsec3 space, we cannot simply go to the previous node in the
 * tree... */
/* rr_data should be of type A or AAAA, and ent_for must have been
 * checked for not NULL */
void
mark_possible_glue(rr_data *rrd, ldns_rbtree_t *ns_tree, ldns_rdf *origin)
{
	ldns_rr *rr;

	ldns_rdf *cur_dname, *prev_dname = NULL;
	size_t c_lcount, o_lcount;

	size_t pos = 0;

	(void) ldns_wire2rr(&rr,
					  rrd->rr_buf->_data,
					  rrd->rr_buf->_capacity,
					  &pos,
					  LDNS_SECTION_ANY_NOQUESTION);
	if (!rr || !ldns_dname_is_subdomain(ldns_rr_owner(rr), origin)) {
		if (rr) ldns_rr_free(rr);
		return;
	}

	o_lcount = ldns_dname_label_count(origin);
	cur_dname = ldns_rdf_clone(ldns_rr_owner(rr));
	c_lcount = ldns_dname_label_count(cur_dname);
	while (c_lcount > 0 && c_lcount > o_lcount) {
		if (ldns_rbtree_search(ns_tree, cur_dname)) {
			rrd->glue = 1;
		}
		prev_dname = cur_dname;
		cur_dname = ldns_dname_left_chop(prev_dname);
		ldns_rdf_deep_free(prev_dname);
		c_lcount = ldns_dname_label_count(cur_dname);
	}
	ldns_rdf_deep_free(cur_dname);
	ldns_rr_free(rr);
}

void
mark_possible_ooz(rr_data *rrd, ldns_rbtree_t *ns_tree, ldns_rdf *origin)
{
	ldns_rr *rr;

	ldns_rdf *cur_dname, *prev_dname = NULL;
	size_t c_lcount, o_lcount;

	size_t pos = 0;

	(void) ldns_wire2rr(&rr,
					  rrd->rr_buf->_data,
					  rrd->rr_buf->_capacity,
					  &pos,
					  LDNS_SECTION_ANY_NOQUESTION);
	if (!rr || !ldns_dname_is_subdomain(ldns_rr_owner(rr), origin)) {
		if (rr) ldns_rr_free(rr);
		return;
	}

	o_lcount = ldns_dname_label_count(origin);
	cur_dname = ldns_rdf_clone(ldns_rr_owner(rr));
	c_lcount = ldns_dname_label_count(cur_dname);
	while (c_lcount > 0 && c_lcount > o_lcount) {
		if (ldns_rbtree_search(ns_tree, cur_dname)) {
			rrd->ooz = 1;
		}
		prev_dname = cur_dname;
		cur_dname = ldns_dname_left_chop(prev_dname);
		ldns_rdf_deep_free(prev_dname);
		c_lcount = ldns_dname_label_count(cur_dname);
	}
	ldns_rdf_deep_free(cur_dname);
	ldns_rr_free(rr);
}

void
print_rrs(FILE *out, ldns_rbtree_t *rr_tree, ldns_rbtree_t *ns_tree, ldns_rdf *origin)
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
			mark_possible_glue(cur_data, ns_tree, origin);
		} else if (!cur_data->ent_for && cur_data->type != LDNS_RR_TYPE_NS &&
		    cur_data->type != LDNS_RR_TYPE_DS) {
			mark_possible_ooz(cur_data, ns_tree, origin);
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
		if (ra->type == LDNS_RR_TYPE_RRSIG &&
			rb->type != LDNS_RR_TYPE_RRSIG) {
			if (ra->type_covered > rb->type) {
				result = 1;
			} else if (ra->type_covered < rb->type) {
				result = -1;
			} else {
				/* we want the sig behind the set, so return
				 * 1 instead of 0 here */
				result = 1;
			}
		} else
		if (rb->type == LDNS_RR_TYPE_RRSIG &&
			ra->type != LDNS_RR_TYPE_RRSIG) {
			if (ra->type > rb->type_covered) {
				result = 1;
			} else if (ra->type < rb->type_covered) {
				result = -1;
			} else {
				/* we want the sig behind the set, so return
				 * -1 instead of 0 here */
				result = -1;
			}
		} else
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

int
compare_dname(const void *a, const void *b)
{
	ldns_rdf *ra, *rb;

	ra = (ldns_rdf *) a;
	rb = (ldns_rdf *) b;

	return ldns_dname_compare(ra, rb);
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: zone_reader [OPTIONS]\n");
	fprintf(out, "Sorts the zone read from stdin in canonical order.\n");
	fprintf(out, "If -n, -s or -i are given, the rrs are sorted according\n");
	fprintf(out, "to their NSEC3-hashed name.\n");
	fprintf(out, "The NSEC3 RRs are *not* added\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-o <origin>\tZone origin\n");
	fprintf(out, "-f <file>\tRead zone from <file> instead of stdin\n");
	fprintf(out, "-k <class>\tZone class\n");
	fprintf(out, "-w <file>\tWrite sorted zone to <file> instead of stdout\n");
	fprintf(out, "-h\t\tShow this help\n");
	fprintf(out, "-n\t\tUse NSEC3 hashing as a sort base\n");
	fprintf(out, "-p\t\tDon't add NSEC3PARAM record when using NSEC3\n");
	fprintf(out, "-s <salt>\tUse this salt for NSEC3 hashed name calculation\n");
	fprintf(out, "-t <count>\tUse <count> iterations for NSEC3 hashed name calculation\n");
	fprintf(out, "-a <algo>\tUse <algo> as the NSEC3 hash algorithm number\n");
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

	/* *nonterminals = malloc(sizeof(ldns_rdf *) * next_label_count); */
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
	/* we put ns records in a separate tree, to make glue recognition
	 * a lot simpler */
	ldns_rbtree_t *ns_tree;
	ldns_rr *cur_rr, *prev_rr;
	rr_data *cur_rr_data;

	/* empty nonterminal detection */
	ldns_rdf *empty_nonterminals[100];
	int empty_nonterminal_count, eni;

	/* options */
	int c;
	FILE *rr_files[MAX_FILES];
	/* actually, the *real* count would be file_count +1, but
	 * then we would have to use -1 everywhere in the code */
	int file_count = 0;
	FILE *out_file;
	bool nsec3 = false;
	bool no_nsec3_param = false;
	uint8_t nsec3_algorithm = 1;
	uint16_t nsec3_iterations = 1;
	uint8_t nsec3_salt_length = 0;
	uint8_t *nsec3_salt = NULL;
	char *out_file_name = NULL;
	ldns_rr_class klass = LDNS_RR_CLASS_IN;
	ldns_rr *my_nsec3params = NULL;

	/* for readig RRs */
	ldns_status status = LDNS_STATUS_OK;
	ldns_rdf *zone_name = NULL, *origin = NULL;
	ldns_rdf *prev_name = NULL;
	int line_nr = 0;

	int line_len;
	char line[MAX_LINE_LEN];

	rr_files[0] = stdin;
	out_file = stdout;

	while ((c = getopt(argc, argv, "a:f:hk:no:ps:t:w:")) != -1) {
		switch (c) {
		case 'a':
			nsec3_algorithm = (uint8_t) atoi(optarg);
			if (nsec3_algorithm != 1) {
				fprintf(stderr, "Error, only SHA1 is supported for NSEC3 hashing\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'f':
			if (rr_files[0] != stdin) {
				fprintf(stderr, "Error: only one -f file can be given");
				exit(1);
			}
			if (strncmp(optarg, "-", 2) != 0) {
				rr_files[file_count] = fopen(optarg, "r");
			}
			if (!rr_files[file_count]) {
				fprintf(stderr, "Error reading %s: %s\n",
				        optarg, strerror(errno));
				exit(1);
			}
			break;
		case 'k':
			klass = (ldns_rr_class) atoi(optarg);
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 't':
			nsec3 = true;
			nsec3_iterations = atoi(optarg);
			if (nsec3_iterations == 0 && !isdigit(optarg[0])) {
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
			zone_name = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, optarg);
			break;
		case 'p':
			no_nsec3_param = true;
			break;
		case 's':
			if (strlen(optarg) % 2 != 0) {
				fprintf(stderr, "Salt value is not valid hex data, ");
				fprintf(stderr, "not a multiple of 2 characters\n");
				exit(EXIT_FAILURE);
			}
			if (strlen(optarg) >= 512) {
				fprintf(stderr, "Error: salt too long (max 256 bytes)\n");
				exit(EXIT_FAILURE);
			}
			nsec3_salt_length = (uint8_t) (strlen(optarg) / 2);
			nsec3_salt = LDNS_XMALLOC(uint8_t, nsec3_salt_length);
			if (!nsec3_salt) {
				fprintf(stderr,
				        "Error allocating %u bytes of memory for salt",
				        nsec3_salt_length);
				exit(1);
			}
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
		case 'w':
			out_file_name = optarg;
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Error: extraneous arguments\n");
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	if (!zone_name) {
		fprintf(stderr, "Error, no zone name specified (-o)\n");
		exit(EXIT_FAILURE);
	}

	if (out_file_name) {
		out_file = fopen(out_file_name, "w");
		if (!out_file) {
			printf("Error opening %s for writing: %s\n",
				  out_file_name,
				  strerror(errno));
			exit(2);
		}
	}

	if (nsec3) {
		my_nsec3params = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
		ldns_rr_set_class(my_nsec3params, klass);
		ldns_rr_set_owner(my_nsec3params, ldns_rdf_clone(zone_name));
		ldns_nsec3_add_param_rdfs(my_nsec3params,
		                          nsec3_algorithm,
		                          0,
		                          nsec3_iterations,
		                          nsec3_salt_length,
		                          nsec3_salt);
		/* always set bit 7 of the flags to zero, according to
		 * rfc5155 section 11 */
		ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(my_nsec3params, 1)), 7, 0);
	}

	rr_tree = ldns_rbtree_create(&compare_rr_data);
	ns_tree = ldns_rbtree_create(&compare_dname);

	prev_rr = NULL;

	origin = ldns_rdf_clone(zone_name);
	line_len = 0;
	while (line_len >= 0) {
		line_len = read_line(rr_files[file_count], line, 1, 0);
		if (line_len > 0) {
			/* no directives possible */
			if (line[0] == ';') {
				/* pass through comments, except comments made by me,
				 * i.e. "Empty non-terminal" */
				if (strncmp(line, "; Empty non-terminal", 20) != 0) {
					fprintf(out_file, "%s\n", line);
				}
			} else if (line[0] == '\n') {
				/* skip empty lines */
			} else {
				status = ldns_rr_new_frm_str(&cur_rr,
				                             line,
				                             0, /* sorter already gave all RRs explicit TTL */
				                             origin,
				                             &prev_name);
				if (status == LDNS_STATUS_OK) {
					/* iff nsec3 and this rr is an nsec3params record with
					 * *other* params than here; remove it.
					 * We will add a new one at the end.
					 * it with the right one. (if there was no nsec3params
					 * rr in the source zone it will be added then as well
					 */
					if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC3PARAMS) {
						if (nsec3 &&
						    ldns_rr_compare(cur_rr,
						                    my_nsec3params) == 0) {
							/* same one, unremember our own */
							ldns_rr_free(my_nsec3params);
							my_nsec3params = NULL;
						} else {
							/* ok it is different or we don't do nsec3.
							 * skip it */
							ldns_rr_free(cur_rr);
							cur_rr = NULL;
							continue;
						}
					}

					if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC ||
					    ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC3) {
						/* remove all nsec and nsec3 records. These
						 * will be re-added by nsec(3)er.*/
						ldns_rr_free(cur_rr);
						cur_rr = NULL;
						continue;
					}
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
							if (!cur_rr_data->name) {
								fprintf(stderr, "Error creating NSEC3 name\n");
								exit(1);
							}
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
						cur_rr_data->orig_name = ldns_rdf_clone(ldns_rr_owner(cur_rr));
						cur_rr_data->name = ldns_nsec3_hash_name(
											ldns_rr_owner(cur_rr),
											nsec3_algorithm,
											nsec3_iterations,
											nsec3_salt_length,
											nsec3_salt);
						if (!cur_rr_data->name) {
							fprintf(stderr, "Error creating NSEC3 name\n");
							exit(1);
						}
						ldns_dname_cat(cur_rr_data->name, origin);
					}
					cur_rr_data->type = ldns_rr_get_type(cur_rr);
					if (cur_rr_data->type == LDNS_RR_TYPE_RRSIG) {
						cur_rr_data->type_covered =
						    ldns_rdf2rr_type(
							     ldns_rr_rrsig_typecovered(cur_rr));
						/* since we removed NSEC and NSEC3, also remove
						 * their RRSIGS */
						if (cur_rr_data->type_covered == LDNS_RR_TYPE_NSEC ||
						    cur_rr_data->type_covered == LDNS_RR_TYPE_NSEC3) {
							ldns_rr_free(cur_rr);
							cur_rr = NULL;
							rr_data_free(cur_rr_data);
							continue;
						}
					}

					status = ldns_rr2buffer_wire(cur_rr_data->rr_buf,
											cur_rr,
											LDNS_SECTION_ANY_NOQUESTION);

					ldns_rbtree_insert(rr_tree,
									rr_data2node(cur_rr_data));
					if (cur_rr_data->type == LDNS_RR_TYPE_NS) {
						if (nsec3) {
							if (!ldns_rbtree_search(ns_tree, cur_rr_data->orig_name)) {
								ldns_rbtree_insert(ns_tree, dname2node(cur_rr_data->orig_name));
							}
						} else {
							if (!ldns_rbtree_search(ns_tree, cur_rr_data->name)) {
								ldns_rbtree_insert(ns_tree, dname2node(cur_rr_data->name));
							}
						}
					}

					ldns_rr_free(prev_rr);
					prev_rr = cur_rr;
					cur_rr = NULL;
				} else {
					if (status != LDNS_STATUS_SYNTAX_EMPTY) {
						fprintf(stderr, "Warning: %s:\n", ldns_get_errorstr_by_id(status));
						fprintf(stderr, "%i: %s\n", line_nr, line);
						/* we are going to quit. read and drop rest of
						 * input if it is stdin, so the calling process does
						 * not write to a nonexisting pipe */
						while (line_len >= 0) {
							line_len = read_line(rr_files[file_count], line, 1, 0);
						}
						/* unlink the output file if it is not stdout, we do not
						 * want partial output going to the next tool */
						if (out_file != stdout) {
							fclose(out_file);
							unlink(out_file_name);
						}
						exit(EXIT_FAILURE);
					}
				}
			}
			line_nr++;
		} else if (line_len < 0) {
			/* end of current file */
			if (file_count > 0) {
				fclose(rr_files[file_count]);
				file_count--;
				line_len = 0;
			} else {
				if (rr_files[0] != stdin) {
					fclose(rr_files[0]);
				}
			}
		}
	}

	if (status == LDNS_STATUS_OK) {
		if (cur_rr) {
			ldns_rr_free(cur_rr);
			cur_rr = NULL;
		}
	} else if (status != LDNS_STATUS_SYNTAX_EMPTY &&
	           status != LDNS_STATUS_SYNTAX_TTL &&
	           status != LDNS_STATUS_SYNTAX_ORIGIN) {
		fprintf(stderr, "Parse error in input line %d: %s\n",
			    line_nr,
			    ldns_get_errorstr_by_id(status));
		/* unlink the output file if it is not stdout, we do not
		 * want partial output going to the next tool */
		if (out_file != stdout) {
			fclose(out_file);
			unlink(out_file_name);
		}
		exit(EXIT_FAILURE);
	}

	/* if we haven't found the right NSEC3PARAM RR in the zone,
	 * add it here */
	if (nsec3 && my_nsec3params && !no_nsec3_param) {
		cur_rr_data = rr_data_new();
		cur_rr_data->name = ldns_nsec3_hash_name(ldns_rr_owner(my_nsec3params),
		                                         nsec3_algorithm,
		                                         nsec3_iterations,
		                                         nsec3_salt_length,
		                                         nsec3_salt);
		ldns_dname_cat(cur_rr_data->name, origin);
		cur_rr_data->orig_name = ldns_rdf_clone(ldns_rr_owner(my_nsec3params));
		cur_rr_data->type = LDNS_RR_TYPE_NSEC3PARAMS;
		status = ldns_rr2buffer_wire(cur_rr_data->rr_buf,
		                             my_nsec3params,
		                             LDNS_SECTION_ANY_NOQUESTION);
		ldns_rbtree_insert(rr_tree, rr_data2node(cur_rr_data));
	}

	print_rrs(out_file, rr_tree, ns_tree, origin);

	if (zone_name) {
		ldns_rdf_deep_free(zone_name);
	}
	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (my_nsec3params) {
		ldns_rr_free(my_nsec3params);
	}
	if (nsec3_salt) {
		LDNS_FREE(nsec3_salt);
	}
	if (prev_rr) {
		ldns_rr_free(prev_rr);
	}

	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	/* free all tree entries */
	ldns_traverse_postorder(ns_tree,
					    rr_dname_node_free,
					    NULL);
	ldns_rbtree_free(ns_tree);
	ldns_traverse_postorder(rr_tree,
					    rr_data_node_free,
					    NULL);

	ldns_rbtree_free(rr_tree);

	if (out_file != stdout) {
		fclose(out_file);
	}

	return 0;
}
