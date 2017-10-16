#ifndef PROTO_H
#define PROTO_H

/*
 * Definitions relating to an iterator.  An iterator is a object handle that
 * allows you to loop over the elements contained in some abstract data
 * structure.  The properties are dictated by the data structure, e.g. if the
 * data structure guarantees a certain order, then the elements are returned
 * in order, and whether the elements may be modified is also governed by
 * the data structure.  An iterator is obtained from the data structure
 * related functions.  The iterator functions only hide the implementation
 * details of the data structure, so that you do not faced whether to follow
 * a next pointer or other method to traverse the abstract data structure.
 * 
 * An iterator is a cursor into a set of items.  Initial, the cursor is
 * placed on the first item.  The entire set of items must be iterated over,
 * or the end() call must be used to terminate the iteration of elements,
 * however it should be assumed performance is directly proportionally with
 * the number of items in the set, NOT the actual number of items iterated
 * over.  Additionally obtaining an iterator should be assumed to have a
 * significant performance impact.  With both assumptions in mind, you
 * should get the right type of iteration in place, which retrieved indeed
 * the set of items needed, rather than just one every time or all of the
 * items in the data structure.
 * 
 * Two typical usaged could be:
 *     struct mystruct* item;
 *     iterator iter = getiterator(...);
 *     if(iterate(&iter, &item)) {
 *         printf("%s",item->myname);
 *         while(advance(&iter, &item)) {
 *             printf(",%s", item->myname);
 *             if(need_bail_out()) {
 *                 end(&iter);
 *                 break;
 *             }
 *         }
 *         printf("\n");
 *     } else
 *         printf("There are no items\n");
 * Or:
 *     for(iter=getiterator(...); iterate(&iter, &item); advance(&iter,NULL))
 *         printf("%s\n",item->myname);
 * 
 * The iterate() call returns whether the cursor is not yet beyond the end of
 * the set of items in the iteration.  If the second argument is not the NULL
 * pointer, the current item is returned in it.
 * 
 * The advance() call advances the cursor to the next element in the list.
 * If the cursor advances past the last item, the end() call is implicitly
 * executed.  If the second argument is not NULL, the item pointed to by the
 * cursor after advancing is returned in it.
 * 
 * The end() call terminates the iteration prematurely and releases any
 * memory or locks implied by the iterator.  If will always return
 * successful.
 */
typedef struct names_iterator_struct* names_iterator;

int names_iterate(names_iterator*iter, void* item);
int names_advance(names_iterator*iter, void* item);
int names_end(names_iterator*iter);

/* A dictionary is an abstract data structure capable of storing key
 * value pairs, where each value is again a dictionary.
 * A (sub)dictionary can also have a name.
 * 
 * The purpose is for the moment as placeholder and to be replaced with
 * the domain structure, containing the denial, rrset, etcetera structures.
 */

typedef struct dictionary_struct* dictionary;

dictionary create(char**name);
dictionary copy(dictionary d);
void dispose(dictionary d);
dictionary get(dictionary d, const char* name);
char* getname(dictionary d, const char* name);
int has(dictionary d, char* name, ...);
int del(dictionary d, char* name);
void* add(dictionary d, char* name);
void set(dictionary d, const char* name, char* value);
names_iterator all(dictionary dict);

typedef struct names_index_struct* names_index_type;

int names_indexcreate(names_index_type*, const char* keyname);
dictionary names_indexlookup(names_index_type, char* keyvalue);
int names_indexremove(names_index_type, dictionary);
int names_indexremovekey(names_index_type,char* keyvalue);
void names_indexinsert(names_index_type, dictionary);
void names_indexdestroy(names_index_type);
names_iterator names_indexiterator(names_index_type);
names_iterator names_indexrange(names_index_type,char* selection,...);

/* Table structures are used internally by views to record changes made in
 * the view.  A table is a set of changes, also dubbed a changelog.
 * The table* functions are not to be used outside of the scope of the
 * names_ module.
 */

typedef struct names_table_struct* names_table_type;

names_table_type names_tablecreate(void);
void names_tabledispose(names_table_type table);
void* names_tableget(names_table_type table, char* name);
int names_tabledel(names_table_type table, char* name);
void** names_tableput(names_table_type table, char* name);
void names_tableconcat(names_table_type* list, names_table_type item);
names_iterator names_tableitems(names_table_type table);

/* The changelog_ functions are also not to be used directly, they
 * extend the table functionality in combination with the views.
 */

struct names_changelogchain;
names_table_type names_changelogpop(struct names_changelogchain* views, int viewid);
int names_changelogsubscribe(struct names_changelogchain**);
void names_changelogsubmit(struct names_changelogchain* views, int viewid, names_table_type changelog);
void names_changelogrelease(struct names_changelogchain* views, names_table_type changelog);

typedef struct names_view_struct* names_view_type;

void own(names_view_type view, dictionary* record);
void* place(names_view_type store, char* name);
void* take(names_view_type view, int index, char* name);
void delete(names_view_type view, dictionary record);
names_view_type names_viewcreate(names_view_type base, const char** keynames);
names_iterator viewiterator(names_view_type view, int index);

int names_viewcommit(names_view_type view);
void names_viewreset(names_view_type view);

#endif
