#ifndef _LIST_H
#define	_LIST_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


#define TRUE    1
#define FALSE   0

#define min(a, b)       ((a<=b)?a:b)
#define max(a, b)       ((a>=b)?a:b)  
//#include <idips_release/lib/lib.h>

struct list_entry_t {
	void * data;
	struct list_entry_t * previous;
	struct list_entry_t * next;
};

struct list_t {
	struct list_entry_t head;
	struct list_entry_t tail;
	unsigned int count;
};

/**
 * Create a new empty list 
 */
struct list_t * list_init();

/**
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DANGER, spec change returne the pointer now!
 * Insert the entry with value data in list in the order specified by
 * entry_cmp_fct.
 * 
 * Definition of int entry_cmp_fct(void * data, void * entry_data):
 *      data is the data to insert, entry_data is a data in the list
 *      data is inserted in the list such that any entry E before data in
 *      the list has entry_cmp_fct(data, E) > 0 and any entry E after data in
 *      the list has entry_cmp_fct(data, E) <= 0
 *      The following entry_cmp_fct implementation keep the list ordered for
 *      integers:
 *
 *      int _simple_list_entry_cmp(void * data, void * entry){
 *              int _a;
 *              int _b;
 *              _a = *(int *)data;
 *              _b = *(int *)entry_data;
 *
 *              return (_a - _b); //use (_b - _a) for reverse order
 *      }
 *
 *      then the list [1 3 4] becomes [1 2 3 4] after the insertion of the 
 *      integer 2
 *
 *      entry_cmp_fct defined the order of the list. If defined to NULL, new
 *      entries are always appended.

 */
struct list_entry_t * list_insert(struct list_t * list, void * data, int (*entry_cmp_fct)(void *, void *));


int list_remove(struct list_t * list, struct list_entry_t * entry, int (* destroy_fct)(void *));

/**
 * Destroy list and clean all the memory used by her. To clean the memory
 * used for each entry data, function destroy_fct is called on the data
 *
 * Definition of int (* destroy_fct)(void * data):
 * 	data is the data associate to the entry to remove. On succes, a 1 is
 * 	returned. Otherwise, a 0 is returned.
 * 	The following is an example of destroy_fct implementation:
 *
 * 	int (* destroy_fct)(void * data){
 * 		free(data);
 * 		return 1;
 * 	}
 */
int list_destroy(struct list_t * list, int (* destroy_fct)(void *));

/**
 * Call foreach_fct on each data entry in the list.
 *
 * definition of int (* foreach_fct)(void * data, void * _context)
 * 	data is the data for the entry, _context is the pointer context used
 * 	to simulate state. On success, a 0 is returned. Otherwise, a code > 0
 * 	is returned. The codes determine the error. The list_foreach returned
 * 	value is the maximum error code observed on the entries
 *
 * 	For example, the following foreach_fct computes the sum of all the
 * 	integer data in the list
 *
 * 	int _foreach_fct(void * data, void * _context){
 * 		*(int*)_context += *(int *)data;
 * 		return (0);
 * 	}
 */
int list_foreach(struct list_t * list, \
		int (* foreach_fct)(void *, void *), \
		void * context);

#endif
