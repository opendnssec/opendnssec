/*
 * $Id: sorter.c 1816 2009-09-17 09:48:15Z matthijs $
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
 * This tool reads input zone files.
 * It sorts the zone in canonical order
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
	ldns_rr_type type;
	ldns_rr *rr;
};
typedef struct rr_data_struct rr_data;

rr_data *
rr_data_new()
{
	rr_data *rd = LDNS_MALLOC(rr_data);
	rd->name = NULL;
	rd->type = 0;
	rd->rr = NULL;
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
	if (rd->rr) {
		ldns_rr_free(rd->rr);
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

	cur_data = (rr_data *) node->data;
	if (ldns_dname_compare(ldns_rr_owner(rr),
					   ldns_rr_owner(cur_data->rr)) == 0) {
		return 1;
	}
	return 0;
}

void
print_rr_data(FILE *out, rr_data *rrd)
{
	ldns_rr_print(out, rrd->rr);
	fflush(out);
}

void
print_rrs(FILE *out, ldns_rbtree_t *rr_tree)
{
	ldns_rbnode_t *cur_node;
	rr_data *cur_data;

	cur_node = ldns_rbtree_first(rr_tree);

	while (cur_node && cur_node != LDNS_RBTREE_NULL) {
		cur_data = (rr_data *) cur_node->data;
		print_rr_data(out, (rr_data *) cur_node->data);
		cur_node = ldns_rbtree_next(cur_node);
	}
}

int
compare_rr_data(const void *a, const void *b)
{
	rr_data *ra, *rb;

	ra = (rr_data *) a;
	rb = (rr_data *) b;

	return ldns_rr_compare(ra->rr, rb->rr);
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
	fprintf(out, "Usage: sorter [OPTIONS]\n");
	fprintf(out, "Sorts the zone read from stdin in canonical order.\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-o <origin>\tZone origin\n");
	fprintf(out, "-f <file>\tRead zone from <file> instead of stdin\n");
	fprintf(out, "-w <file>\tWrite sorted zone to <file> instead of stdout\n");
	fprintf(out, "-h\t\tShow this help\n");
}

/* if the line is '$ORIGIN <name>', the name is returned
 * in a newly allocated ldns_rdf. If the line contains anything
 * else, NULL is returned. The returned rdf must be freed with
 * ldns_rdf_deep_free() */
static ldns_rdf *
directive_origin(const char *line)
{
	size_t len, pos;
	ldns_rdf *new_origin;
	if (!line) return NULL;
	len = strlen(line);
	if (len > 8 && strncmp(line, "$ORIGIN ", 8) == 0) {
		pos = 8;
		/* skip whitespace */
		while (pos < len && (line[pos] == ' ' || line[pos] == '\t' ||
		       line[pos] == '\n')) {
			pos++;
		}
		if (pos >= len) {
			/* bad directive, no name given */
			return NULL;
		} else {
			new_origin = ldns_dname_new_frm_str(&line[pos]);
			return new_origin;
		}
	}
	return NULL;
}

/* returns 1 if the line is '$TTL <int>', 0 otherwise */
/* We cannot directly return atol(int), because then we wouldn't
 * be able to use the directive $TTL 0 */
static int
is_directive_ttl(const char *line) {
	size_t len, pos;
	if (!line) return 0;
	len = strlen(line);
	if (len > 5 && strncmp(line, "$TTL ", 5) == 0) {
		pos = 5;
		/* skip whitespace */
		while (pos < len && (line[pos] == ' ' || line[pos] == '\t' ||
		       line[pos] == '\n')) {
			pos++;
		}
		if (pos < len && isdigit(line[pos])) return 1;
	}
	return 0;
}

/* returns the ttl from $TTL */
static uint32_t
directive_ttl(const char *line) {
	size_t len, pos;
	const char *endptr;
	if (!line) return 0;
	len = strlen(line);
	pos = 5;
	if (len > 5 && strncmp(line, "$TTL ", 5) == 0) {
		pos = 5;
		/* skip whitespace */
		while (pos < len && (line[pos] == ' ' || line[pos] == '\t' ||
		       line[pos] == '\n')) {
			pos++;
		}
		if (pos < len && isdigit(line[pos]))
			return ldns_str2period(&line[pos], &endptr);
	}
	return 0;
}

/* automatically handles include, and returns 1 if this is a correct
 * $INCLUDE directive. Returns 0 otherwise */
static int
directive_include(const char *line, FILE *rr_files[], int *file_count)
{
	size_t len, pos;
	if (!line || !file_count) return 0;
	len = strlen(line);
	if (len > 9 && strncmp(line, "$INCLUDE ", 9) == 0) {
		pos = 9;
		/* skip whitespace */
		while (pos < len && (line[pos] == ' ' || line[pos] == '\t' ||
		       line[pos] == '\n')) {
			pos++;
		}
		if (pos < len) {
			if (*file_count >= MAX_FILES - 1) {
				fprintf(stderr, "Error: maximum depth of $INCLUDE "
				                "reached. Stopping at %s\n", line);
				return 0;
			}
			(*file_count)++;
			rr_files[*file_count] = fopen(&line[pos], "r");
			if (!rr_files[*file_count]) {
				fprintf(stderr, "Error opening %s for reading: %s\n",
				        &line[pos], strerror(errno));
				(*file_count)--;
				return 0;
			} else {
				return 1;
			}
		} else {
			return 0;
		}
	}
	return 0;
}

static int
line_contains_space_only(char* line, int line_len)
{
	int i;

	for (i=0; i<line_len; i++) {
		if (line[i] != ' ' &&
			line[i] != '\t' &&
			line[i] != '\n' &&
			line[i] != '\0')
			return 0;
	}
	return 1;
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
	ldns_rbtree_t *rr_tree = NULL;
	ldns_rr *cur_rr = NULL, *prev_rr = NULL;
	rr_data *cur_rr_data = NULL;

	/* options */
	int c;
	FILE *rr_files[MAX_FILES];
	/* actually, the *real* count would be file_count +1, but
	 * then we would have to use -1 everywhere in the code */
	int file_count = 0;
	FILE *out_file;
	char *out_file_name = NULL;

	/* for readig RRs */
	ldns_status status = LDNS_STATUS_OK;
	uint32_t default_ttl = 3600;
	ldns_rdf *zone_name = NULL, *origin = NULL, *tmp;
	ldns_rdf *prev_name = NULL;
	int line_nr = 0;

	int line_len;
	char line[MAX_LINE_LEN];

	rr_files[0] = stdin;
	out_file = stdout;

	while ((c = getopt(argc, argv, "f:ho:w:")) != -1) {
		switch (c) {
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
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 'o':
			zone_name = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, optarg);
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

	rr_tree = ldns_rbtree_create(&compare_rr_data);
	prev_rr = NULL;
	origin = ldns_rdf_clone(zone_name);
	line_len = 0;
	while (line_len >= 0) {
		line_len = read_line(rr_files[file_count], line, 1, 0);
		if (line_len >= 0 && !line_contains_space_only(line, line_len)) {
			if (line[0] == '$') {
				tmp = directive_origin(line);
				if (tmp) {
					ldns_rdf_deep_free(origin);
					origin = tmp;
				} else if (is_directive_ttl(line)) {
					default_ttl = directive_ttl(line);
				} else if (directive_include(line, rr_files,
				                             &file_count)) {
					/* Handled automatically by directive_include() */
				} else {
					fprintf(stderr, "Error in directive %s\n", line);
				}
				continue;
			} else if (line[0] == ';') {
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
				                             default_ttl,
				                             origin,
				                             &prev_name);
				if (status == LDNS_STATUS_OK) {
					if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC ||
					    ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC3) {
						/* remove all nsec and nsec3 records. These
						 * will be re-added by nsec(3)er.*/
						ldns_rr_free(cur_rr);
						cur_rr = NULL;
						continue;
					}
					cur_rr_data = rr_data_new();
					cur_rr_data->name = ldns_rdf_clone(ldns_rr_owner(cur_rr));
					cur_rr_data->type = ldns_rr_get_type(cur_rr);
					cur_rr_data->rr = ldns_rr_clone(cur_rr);

					ldns_rbtree_insert(rr_tree,
									rr_data2node(cur_rr_data));

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
						}
						if (out_file_name) {
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
		}
		if (out_file_name) {
			unlink(out_file_name);
		}
		exit(EXIT_FAILURE);
	}

	print_rrs(out_file, rr_tree);

	if (zone_name) {
		ldns_rdf_deep_free(zone_name);
	}
	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (prev_rr) {
		ldns_rr_free(prev_rr);
	}
	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	/* free all tree entries */
	ldns_traverse_postorder(rr_tree,
					    rr_data_node_free,
					    NULL);
	ldns_rbtree_free(rr_tree);

	if (out_file != stdout) {
		fclose(out_file);
	}

	return 0;
}
