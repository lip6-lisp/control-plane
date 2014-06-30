#include  "list.h"


	struct list_t *
list_init(int (*entry_cmp_fct)(void *, void *))
{
	struct list_t * list;
	
	list = (struct list_t *)calloc(1, sizeof(struct list_t));

	list->head.next = &list->tail;
	list->head.previous = NULL;
	list->tail.previous = &list->head;
	list->tail.next = NULL;
	
	return (list);
}

	struct list_entry_t * 
list_insert(struct list_t * list, void * data, \
		int (*entry_cmp_fct)(void *, void *)) 
{
	struct list_entry_t * entry = NULL;
	struct list_entry_t * c;

	entry = (struct list_entry_t *)calloc(1, sizeof(struct list_entry_t));
	if (!entry) {
		return (entry);
	}
	entry->data = data;

	if (NULL == entry_cmp_fct) {
		c = &list->tail;
	}
	else{
		c = list->head.next;

		while (c != &list->tail) {
			if (entry_cmp_fct(data, c->data) <= 0) {
				break;
			}
			c = c->next;
		}
	}
	entry->previous = c->previous;
	entry->next = c;
	c->previous->next = entry;
	c->previous = entry;

	list->count++;

	return (entry);
}

	int
list_destroy(struct list_t * list, int (* destroy_fct)(void *))
{
	struct list_entry_t * entry;
	struct list_entry_t * old;

	if (!list) {
		return (FALSE);
	}

	entry = list->head.next;
	while (list->count > 0) {
		old = entry;
		entry = entry->next;
		if (old->data && destroy_fct) {
			destroy_fct(old->data);
		}
		free(old);
		list->count--;
	}
	free(list);

	return (TRUE);
}

	int
list_remove(struct list_t * list, struct list_entry_t * entry, \
		int (* destroy_fct)(void *))
{
	if (!list || !entry || 0 == list->count)
		return (FALSE);

	entry->previous->next = entry->next;
	entry->next->previous = entry->previous;
	list->count--;

	if (destroy_fct) {
		destroy_fct(entry->data);
	}
	free(entry);

	return (TRUE);
}

	int
list_foreach(struct list_t * list, \
		int (* foreach_fct)(void *, void *), \
		void * context)
{
	struct list_entry_t * entry;
	int ret = 0;

	entry = list->head.next;

	while (entry != &list->tail) {
		ret = max(ret, foreach_fct(entry->data, context));
		entry = entry->next;
	}

	return (ret);
}

	struct list_entry_t *
list_search(struct list_t * list, void * data, \
		int (*entry_cmp_fct)(void *, void *))
{	
	struct list_entry_t * c;

	c = list->head.next;

	while (c != &list->tail) {
		if (entry_cmp_fct(data, c->data) == 0) {
			return c;
		}
		c = c->next;		
	}
	return NULL;		
}
		
