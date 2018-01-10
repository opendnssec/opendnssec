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

names_iterator generic_iterator(size_t size);
void generic_add(names_iterator i, void* ptr);

struct marshall_struct;
typedef struct marshall_struct* marshall_handle;

marshall_handle marshallcopy(int fd);
marshall_handle marshallinput(int fd);
marshall_handle marshalloutput(int fd);
marshall_handle marshallprint(FILE* fp);
void marshallclose(marshall_handle h);
int marshallself(marshall_handle h, void* member);
int marshallbyte(marshall_handle h, void* member);
int marshallinteger(marshall_handle h, void* member);
int marshallstring(marshall_handle h, void* member);
int marshallstringarray(marshall_handle h, void* member);
int marshalling(marshall_handle h, char* name, void* members, int *membercount, size_t membersize, int (*memberfunction)(marshall_handle,void*));

extern int* marshall_OPTIONAL;

/* A dictionary is an abstract data structure capable of storing key
 * value pairs, where each value is again a dictionary.
 * A (sub)dictionary can also have a name.
 * 
 * The purpose is for the moment as placeholder and to be replaced with
 * the domain structure, containing the denial, rrset, etcetera structures.
 */

typedef struct dictionary_struct* dictionary;
typedef struct names_index_struct* names_index_type;
typedef struct names_table_struct* names_table_type;
typedef struct names_view_struct* names_view_type;

void composestring(char* dst, char* src, ...);
int composestring2(char** ptr, char* src, ...);
int composestringf(char** ptr, char*fmt,...);
int getset(dictionary d, const char* name, const char** get, char** set);

dictionary create(char**name);
void annotate(dictionary, const char* apex);
void names_recorddestroy(dictionary);
dictionary copy(dictionary);
void dispose(dictionary);
char* getname(dictionary, const char* name);
int names_recordcompare_namerevision(dictionary a, dictionary b);
int names_recordhasdata(dictionary, char* name, char* data);
void names_recordadddata(dictionary, char* name, char* data);
void names_recorddeldata(dictionary, char* name, char* data);
names_iterator names_recordalltypes(dictionary);
names_iterator names_recordallvalues(dictionary, char*name);
int names_recordhasvalidupto(dictionary);
int names_recordgetvalidupto(dictionary);
void names_recordsetvalidupto(dictionary, int value);
int names_recordhasvalidfrom(dictionary);
int names_recordgetvalidfrom(dictionary);
void names_recordsetvalidfrom(dictionary, int value);
int names_recordhasexpiry(dictionary);
int names_recordgetexpiry(dictionary);
void names_recordsetexpiry(dictionary, int value);
int names_recordmarshall(marshall_handle h, void* d);

struct dual {
    dictionary src;
    dictionary dst;
};

int names_indexcreate(names_index_type*, const char* keyname);
dictionary names_indexlookup(names_index_type, dictionary);
dictionary names_indexlookupkey(names_index_type, char* keyvalue);
int names_indexremove(names_index_type, dictionary);
int names_indexremovekey(names_index_type,const char* keyvalue);
int names_indexinsert(names_index_type, dictionary);
void names_indexdestroy(names_index_type, void (*userfunc)(void* arg, void* key, void* val), void* userarg);
int names_indexaccept(names_index_type, dictionary);
names_iterator names_indexiterator(names_index_type);
names_iterator names_indexrange(names_index_type,char* selection,...);

names_iterator noexpiry(names_view_type);
names_iterator neighbors(names_view_type);
names_iterator expiring(names_view_type);

/* Table structures are used internally by views to record changes made in
 * the view.  A table is a set of changes, also dubbed a changelog.
 * The table* functions are not to be used outside of the scope of the
 * names_ module.
 */

names_table_type names_tablecreate(void);
void names_tabledispose(names_table_type table, void (*userfunc)(void* arg, void* key, void* val), void* userarg);
void* names_tableget(names_table_type table, char* name);
int names_tabledel(names_table_type table, char* name);
void** names_tableput(names_table_type table, const char* name);
void names_tableconcat(names_table_type* list, names_table_type item);
names_iterator names_tableitems(names_table_type table);

/* The changelog_ functions are also not to be used directly, they
 * extend the table functionality in combination with the views.
 */

struct names_changelogchain;

void names_changelogdestroy(names_table_type changelog);
void names_changelogdestroyall(struct names_changelogchain* views, marshall_handle* store);
names_table_type names_changelogpoppush(struct names_changelogchain* views, int viewid, names_table_type* mychangelog);
int names_changelogsubscribe(names_view_type view, struct names_changelogchain**);
void names_changelogrelease(struct names_changelogchain* views, names_table_type changelog);
void names_changelogpersistincr(struct names_changelogchain* views, names_table_type changelog);
void names_changelogpersistsetup(struct names_changelogchain* views, marshall_handle store);
int names_changelogpersistfull(struct names_changelogchain* views, names_iterator* iter, int viewid, marshall_handle store, marshall_handle* oldstore);
void names_restore(int basefd, char* filename, struct names_changelogchain* views, names_view_type view, int viewid);
void names_persist(names_view_type view, int basefd, char* filename);

void names_own(names_view_type view, dictionary* record);
void names_amend(names_view_type view, dictionary record);
void* names_place(names_view_type store, char* name);
void* names_take(names_view_type view, int index, char* name);
void names_remove(names_view_type view, dictionary record);
names_view_type names_viewcreate(names_view_type base, const char** keynames);
void names_viewdestroy(names_view_type view);
names_iterator names_viewiterator(names_view_type view, int index);
int names_viewcommit(names_view_type view);
void names_viewreset(names_view_type view);
int names_viewpersist(names_view_type view, int basefd, char* filename);
int names_viewrestore(names_view_type view, const char* apex, int basefd, char* filename);

void names_dumprecord(FILE*, dictionary record);
void names_dumpviewinfo(names_view_type view, char* preamble);
void names_dumpviewfull(FILE*, names_view_type view);

#define CHECK(CMD) do { if(CMD) { if(errno!=0) fprintf(stderr,"%s (%d)\n",strerror(errno),errno); assert(!#CMD); } } while(0)

#endif
