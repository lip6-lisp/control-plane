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

#ifndef _DB_PREFIX_H
#define _DB_PREFIX_H

#include <netinet/in.h>

/* Maskbit. */
extern u_char maskbit[];

/* IPv4 and IPv6 unified prefix structure. */
struct prefix {
	u_char family;
	u_char prefixlen;
	union
	{
		u_char prefix;
		struct in_addr prefix4;
#ifdef HAVE_IPV6
		struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
	} u __attribute__ ((aligned (8)));
};

/* IPv4 prefix structure. */
struct prefix_ipv4 {
	u_char family;
	u_char prefixlen;
	struct in_addr prefix __attribute__ ((aligned (8)));
};

/* IPv6 prefix structure. */
#ifdef HAVE_IPV6
struct prefix_ipv6 {
	u_char family;
	u_char prefixlen;
	struct in6_addr prefix __attribute__ ((aligned (8)));
};
#endif /* HAVE_IPV6 */


/* When string format is invalid return 0. */
int str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p);

/* If given string is valid return pin6 else return NULL */
#ifdef HAVE_IPV6
int str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p);
#endif

/* Generic function for conversion string to struct prefix. */
int str2prefix (const char *str, struct prefix *p);

/* Apply mask to IPv4 prefix. */
void apply_mask_ipv4 (struct prefix_ipv4 *p);

#ifdef HAVE_IPV6
void apply_mask_ipv6 (struct prefix_ipv6 *p);

void str2in6_addr (const char *str, struct in6_addr *addr);
#endif /* HAVE_IPV6 */

void apply_mask (struct prefix *p);

struct prefix *new_prefix(u_char preflen, struct in_addr *prefix);

void *prefix2str(struct prefix *p);

int prefix_match (const struct prefix *n, const struct prefix *p);

#endif /* _DB_PREFIX_H */
