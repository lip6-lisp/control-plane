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

#ifndef	_DB_TABLE_H
#define	_DB_TABLE_H

#include "db_prefix.h"

/* bgp_table.h */
struct db_table
{
	struct db_node *top;
	//function used to free data of node when delete node
	void (*remove_fct)(void *);
	//number of node
	unsigned long count;
};

struct db_node
{
	struct prefix p;

	struct db_table *table;
	struct db_node *parent;
	struct db_node *link[2];
#define l_left   link[0]
#define l_right  link[1]
	void *info;
	void * flags;
	unsigned int lock;/*you can delete a node when its lock == 0*/
	/*y5er*/
	struct prefix peer;
	/*y5er*/
};

/**
 * Create a table
 *
 * remove_fct:	function to apply on an entry data when removed
 */
struct db_table * db_table_init(void (*remove_fct)(void*));

/**
 * Destroy table (clean memory)
 */
void db_table_finish(struct db_table * table);

/**
 * Nodes number (number of nodes in table)
 */
unsigned long db_table_count(struct db_table * table);

/**
 * Get the lock on node
 */
struct db_node * db_lock_node(struct db_node * node);

/**
 * Release the lock on node
 */
void db_unlock_node(struct db_node * node);

struct db_node * db_table_top(struct db_table * table);
struct db_node *db_route_next(struct db_node *);
struct db_node *db_route_next_until(struct db_node *, struct db_node *);

/**
 * Add a new node in table with prefix p
 *
 * PRECONDITION: nodes in table have the same family as prefix
 */
struct db_node * db_node_get(struct db_table * table, struct prefix * prefix);

/**
 * Remove node (and remove its data)
 */
void db_node_delete(struct db_node * node);

/**
 * Set node data
 *
 * Return previous data
 */
void * db_node_set_info(struct db_node * node , void * data);

/**
 * Get node data
 */
void * db_node_get_info(struct db_node * node);

/**
 * Get the node in table that best match prefix
 *
 * PRECONDITION: nodes in table have the same family as prefix
 *
 */
struct db_node * db_node_match(struct db_table * table, struct prefix * prefix);
struct db_node * db_node_match_prefix(struct db_table * table, struct prefix * prefix);

/**
 * Get the node in table with the exact match address in IPv4
 *
 * PRECONDITION: nodes in table have the family AF_INET
 */
struct db_node * db_node_match_ipv4(struct db_table * table, struct in_addr * address);

#ifdef HAVE_IPV6
/**
 * Get the node in table with the exact match address in IPv6
 * 
 * PRECONDITION: nodes in table have the family AF_INET6
 */
struct db_node *db_node_match_ipv6(struct db_table * table, struct in6_addr * address);
#endif /* HAVE_IPV6 */

/**
 * Get the node in table with the exact match prefix
 *
 * PRECONDITION: nodes in table have the same family as prefix
 */
struct db_node *db_node_match_exact(struct db_table * table, struct prefix * prefix);

#endif	/* _DB_TABLE_H */
