
/* BGP routing table
   Copyright (C) 1998, 2001 Kunihiro Ishiguro

   This file is part of GNU Zebra.

   GNU Zebra is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   GNU Zebra is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Zebra; see the file COPYING.  If not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* Zebra common header.
   Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002 Kunihiro Ishiguro

   This file is part of GNU Zebra.

   GNU Zebra is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   GNU Zebra is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Zebra; see the file COPYING.  If not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */


/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */


/*
 * Prefix related functions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "db.h"
#include "db_prefix.h"
#include "db_table.h"

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

	void
prefix_copy (struct prefix *dest, const struct prefix *src)
{
	dest->family = src->family;
	dest->prefixlen = src->prefixlen;

	if (src->family == AF_INET){
		dest->u.prefix4 = src->u.prefix4;
	}
#ifdef HAVE_IPV6
	else if (src->family == AF_INET6){
		dest->u.prefix6 = src->u.prefix6;
	}
#endif /* HAVE_IPV6 */
	else
	{
		assert (0);
	}
}




/* If n includes p prefix then return 1 else return 0. */
	int
prefix_match (const struct prefix *n, const struct prefix *p)
{
	int offset;
	int shift;

	/* Set both prefix's head pointer. */
	const u_char *np = (const u_char *)&n->u.prefix;
	const u_char *pp = (const u_char *)&p->u.prefix;

	/* If n's prefix is longer than p's one return 0. */
	if (n->prefixlen > p->prefixlen)
		return 0;

	offset = n->prefixlen / PNBBY;
	shift =  n->prefixlen % PNBBY;

	if (shift)
		if (maskbit[shift] & (np[offset] ^ pp[offset]))
			return 0;

	while (offset--)
		if (np[offset] != pp[offset])
			return 0;
	return 1;
}


/* bgp_table.c */

    void 
db_table_free (struct db_table *rt);


	struct db_table *
db_table_init (void (*remove_fct)(void * ))
{
	struct db_table *rt;

	rt = calloc(1, sizeof (struct db_table));

	rt->remove_fct = remove_fct;

	return rt;
}

	void
db_table_finish (struct db_table *rt)
{
	db_table_free (rt);
}

	static struct db_node *
db_node_create ()
{
	struct db_node *rn;

	rn = (struct db_node *) calloc(1, sizeof(struct db_node));
	return rn;
}

/* Allocate new route node with prefix set. */
	static struct db_node *
db_node_set (struct db_table *table, struct prefix *prefix)
{
	struct db_node *node;

	node = db_node_create ();

	prefix_copy (&node->p, prefix);
	node->table = table;

	return node;
}

/* Free route node. */
	static void
db_node_free (struct db_node *node)
{
	if(node && node->table && node->table->remove_fct){
		node->table->remove_fct(node->info);
	}
	free(node);
}

/* Free route table. */
	void
db_table_free (struct db_table *rt)
{
	struct db_node *tmp_node;
	struct db_node *node;

	if (rt == NULL)
		return;

	node = rt->top;

	while (node)
	{
		if (node->l_left)
		{
			node = node->l_left;
			continue;
		}

		if (node->l_right)
		{
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		if (node != NULL)
		{
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;

			db_node_free (tmp_node);
		}
		else
		{
			db_node_free (tmp_node);
			break;
		}
	}

	free(rt);
	return;
}

/* Common prefix route genaration. */
	static void
route_common (struct prefix *n, struct prefix *p, struct prefix *new)
{
	int i;
	u_char diff;
	u_char mask;

	u_char *np = (u_char *)&n->u.prefix;
	u_char *pp = (u_char *)&p->u.prefix;
	u_char *newp = (u_char *)&new->u.prefix;

	for (i = 0; i < p->prefixlen / 8; i++)
	{
		if (np[i] == pp[i])
			newp[i] = np[i];
		else
			break;
	}

	new->prefixlen = i * 8;

	if (new->prefixlen != p->prefixlen)
	{
		diff = np[i] ^ pp[i];
		mask = 0x80;
		while (new->prefixlen < p->prefixlen && !(mask & diff))
		{
			mask >>= 1;
			new->prefixlen++;
		}
		newp[i] = np[i] & maskbit[new->prefixlen % 8];
	}
}

/* Check bit of the prefix. */
	static int
check_bit (u_char *prefix, u_char prefixlen)
{
	int offset;
	int shift;
	u_char *p = (u_char *)prefix;

	assert (prefixlen <= 128);

	offset = prefixlen / 8;
	shift = 7 - (prefixlen % 8);

	return (p[offset] >> shift & 1);
}

	static void
set_link (struct db_node *node, struct db_node *new)
{
	int bit;

	bit = check_bit (&new->p.u.prefix, node->p.prefixlen);

	assert (bit == 0 || bit == 1);

	node->link[bit] = new;
	new->parent = node;
}

/* Lock node. */
	struct db_node *
db_lock_node (struct db_node *node)
{
	node->lock++;
	return node;
}

/* Unlock node. */
	void
db_unlock_node (struct db_node *node)
{
	node->lock--;

	if (node->lock == 0)
		db_node_delete (node);
}

/* Find matched prefix. */
	struct db_node *
db_node_match (struct db_table *table, struct prefix *p)
{
	struct db_node *node;
	struct db_node *matched;

	matched = NULL;
	node = table->top;

	assert(node->p.family == p->family);

	/* Walk down tree.  If there is matched route then store it to
	   matched. */
	while (node && node->p.prefixlen <= p->prefixlen && 
			prefix_match (&node->p, p))
	{
		if (node->info)
			matched = node;
		node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
	}

	/* If matched route found, return it. */
	if (matched)
		return db_lock_node (matched);

	return NULL;
}

/* Find matched prefix. */
	struct db_node *
db_node_match_prefix (struct db_table *table, struct prefix *p)
{
	struct db_node *node;
	struct db_node *matched;

	matched = NULL;
	node = table->top;

	assert(node->p.family == p->family);
	/* char buf[512];
	inet_ntop(p->family, (void *)&p->u.prefix, buf, 512);
	printf("P: %s/%d\n", buf, p->prefixlen ); 
 */	/* Walk down tree.  If there is matched route then store it to
	   matched. */
	while (node && node->p.prefixlen <= p->prefixlen && 
			prefix_match (&node->p, p))
	{
		matched = node;
		//printf("node::%p::%p::%p\n",node, node->l_left, node->l_right);
		//printf("node->link[0] = %p, node->link[1]=%p\n",node->link[0],node->link[1]);
		node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
	}
	
	if (matched)
		return db_lock_node (matched);

	return NULL;
}

	struct db_node *
db_node_match_ipv4 (struct db_table *table, struct in_addr *addr)
{
	struct prefix_ipv4 p;

	memset (&p, 0, sizeof (struct prefix_ipv4));
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_PREFIXLEN;
	p.prefix = *addr;

	return db_node_match (table, (struct prefix *) &p);
}

#ifdef HAVE_IPV6
	struct db_node *
db_node_match_ipv6 (struct db_table *table, struct in6_addr *addr)
{
	struct prefix_ipv6 p;

	memset (&p, 0, sizeof (struct prefix_ipv6));
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_PREFIXLEN;
	p.prefix = *addr;

	return db_node_match (table, (struct prefix *) &p);
}
#endif /* HAVE_IPV6 */

/* Lookup same prefix node.  Return NULL when we can't find route. */
	struct db_node *
db_node_match_exact(struct db_table *table, struct prefix *p)
{
	struct db_node *node;

	node = table->top;

	assert(node->p.family == p->family);

	while (node && node->p.prefixlen <= p->prefixlen && 
			prefix_match (&node->p, p))
	{
		if (node->p.prefixlen == p->prefixlen && node->info)
			return db_lock_node (node);

		node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
	}

	return NULL;
}

/* Add node to routing table. */
	struct db_node *
db_node_get (struct db_table *table, struct prefix *p)
{
	struct db_node *new;
	struct db_node *node;
	struct db_node *match;

	match = NULL;
	node = table->top;

	assert((node && node->p.family == p->family) || !node);

	while (node && node->p.prefixlen <= p->prefixlen && 
			prefix_match (&node->p, p))
	{
		if (node->p.prefixlen == p->prefixlen)
		{
			db_lock_node (node);
			return node;
		}
		match = node;
		node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
	}

	if (node == NULL)
	{
		new = db_node_set (table, p);
		if (match)
			set_link (match, new);
		else{
			//printf("new root:%p\n",new);
			table->top = new;
		}
	}
	else
	{
		new = db_node_create ();
		route_common (&node->p, p, &new->p);
		new->p.family = p->family;
		new->table = table;
		set_link (new, node);

		if (match)
			set_link (match, new);
		else
			table->top = new;

		if (new->p.prefixlen != p->prefixlen)
		{
			match = new;
			new = db_node_set (table, p);
			set_link (match, new);
			table->count++;
		}
	}
	table->count++;
	db_lock_node (new);

	return new;
}

/* Delete node from the routing table. */
	void
db_node_delete (struct db_node *node)
{
	struct db_node *child;
	struct db_node *parent;

	assert (node->lock == 0);
	assert (node->info == NULL);

	if (node->l_left && node->l_right)
		return;

	if (node->l_left)
		child = node->l_left;
	else
		child = node->l_right;

	parent = node->parent;

	if (child)
		child->parent = parent;

	if (parent)
	{
		if (parent->l_left == node)
			parent->l_left = child;
		else
			parent->l_right = child;
	}
	else
		node->table->top = child;

	node->table->count--;

	db_node_free (node);

	/* If parent node is stub then delete it also. */
	if (parent && parent->lock == 0)
		db_node_delete (parent);
}

/* Get fist node and lock it.  This function is useful when one want
   to lookup all the node exist in the routing table. */
	struct db_node *
db_table_top (struct db_table *table)
{
	/* If there is no node in the routing table return NULL. */
	if (table->top == NULL)
		return NULL;

	/* Lock the top node and return it. */
	db_lock_node (table->top);
	return table->top;
}

/* Unlock current node and lock next node then return it. */
	struct db_node *
db_route_next (struct db_node *node)
{
	struct db_node *next;
	struct db_node *start;

	/* Node may be deleted from db_unlock_node so we have to preserve
	   next node's pointer. */

	if (node->l_left)
	{
		next = node->l_left;
		db_lock_node (next);
		db_unlock_node (node);
		return next;
	}
	if (node->l_right)
	{
		next = node->l_right;
		db_lock_node (next);
		db_unlock_node (node);
		return next;
	}

	start = node;
	while (node->parent)
	{
		if (node->parent->l_left == node && node->parent->l_right)
		{
			next = node->parent->l_right;
			db_lock_node (next);
			db_unlock_node (start);
			return next;
		}
		node = node->parent;
	}
	db_unlock_node (start);
	return NULL;
}

/* Unlock current node and lock next node until limit. */
	struct db_node *
db_route_next_until (struct db_node *node, struct db_node *limit)
{
	struct db_node *next;
	struct db_node *start;

	/* Node may be deleted from db_unlock_node so we have to preserve
	   next node's pointer. */

	if (node->l_left)
	{
		next = node->l_left;
		db_lock_node (next);
		db_unlock_node (node);
		return next;
	}
	if (node->l_right)
	{
		next = node->l_right;
		db_lock_node (next);
		db_unlock_node (node);
		return next;
	}

	start = node;
	while (node->parent && node != limit)
	{
		if (node->parent->l_left == node && node->parent->l_right)
		{
			next = node->parent->l_right;
			db_lock_node (next);
			db_unlock_node (start);
			return next;
		}
		node = node->parent;
	}
	db_unlock_node (start);
	return NULL;
}

	unsigned long
db_table_count (struct db_table *table)
{
	return table->count;
}


void * db_node_set_info(struct db_node * node, void * info){
	void * old = NULL;
	
	if(!node){
		return (NULL);
	}

	old = node->info;
	node->info = info;

	return (old);
}

void * db_node_get_info(struct db_node * node){
	if(!node){
		return (NULL);
	}

	return (node->info);
}
