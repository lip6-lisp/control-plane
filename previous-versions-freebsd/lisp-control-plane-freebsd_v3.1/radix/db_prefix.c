
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

u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

/* When string format is invalid return 0. */
	int
str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p)
{
	int ret;
	int plen;
	char *pnt;
	char *cp;

	/* Find slash inside string. */
	pnt = strchr (str, '/');

	/* String doesn't contail slash. */
	if (pnt == NULL)
	{
		/* Convert string to prefix. */
		ret = inet_aton (str, &p->prefix);
		if (ret == 0)
			return 0;

		/* If address doesn't contain slash we assume it host address. */
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;

		return ret;
	}
	else
	{
		cp = calloc(1, (pnt - str) + 1);
		strncpy (cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_aton (cp, &p->prefix);

		free(cp);

		/* Get prefix length. */
		plen = (u_char) atoi (++pnt);
		if (plen > IPV4_MAX_PREFIXLEN)
			return 0;

		p->family = AF_INET;
		p->prefixlen = plen;
	}

	return ret;
}

/* If given string is valid return pin6 else return NULL */
#ifdef HAVE_IPV6
	int
str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p)
{
	char *pnt;
	char *cp;
	int ret;

	pnt = strchr (str, '/');

	/* If string doesn't contain `/' treat it as host route. */
	if (pnt == NULL)
	{
		ret = inet_pton (AF_INET6, str, &p->prefix);
		if (ret != 1)
			return 0;
		p->prefixlen = IPV6_MAX_BITLEN;
	}
	else
	{
		int plen;

		cp = calloc(1,  (pnt - str) + 1);
		strncpy (cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ret = inet_pton (AF_INET6, cp, &p->prefix);
		free (cp);
		if (ret != 1)
			return 0;
		plen = (u_char) atoi (++pnt);
		if (plen > 128)
			return 0;
		p->prefixlen = plen;
	}
	p->family = AF_INET6;

	return ret;
}
#endif


/* Generic function for conversion string to struct prefix. */
	int
str2prefix (const char *str, struct prefix *p)
{
	int ret;

	/* First we try to convert string to struct prefix_ipv4. */
	ret = str2prefix_ipv4 (str, (struct prefix_ipv4 *) p);
	if (ret)
		return ret;

#ifdef HAVE_IPV6
	/* Next we try to convert string to struct prefix_ipv6. */
	ret = str2prefix_ipv6 (str, (struct prefix_ipv6 *) p);
	if (ret)
		return ret;
#endif /* HAVE_IPV6 */

	return 0;
}



/* Apply mask to IPv4 prefix. */
	void
apply_mask_ipv4 (struct prefix_ipv4 *p)
{
	u_char *pnt;
	int index;
	int offset;

	index = p->prefixlen / 8;

	if (index < 4)
	{
		pnt = (u_char *) &p->prefix;
		offset = p->prefixlen % 8;

		pnt[index] &= maskbit[offset];
		index++;

		while (index < 4)
			pnt[index++] = 0;
	}
}


#ifdef HAVE_IPV6
	void
apply_mask_ipv6 (struct prefix_ipv6 *p)
{
	u_char *pnt;
	int index;
	int offset;

	index = p->prefixlen / 8;

	if (index < 16)
	{
		pnt = (u_char *) &p->prefix;
		offset = p->prefixlen % 8;

		pnt[index] &= maskbit[offset];
		index++;

		while (index < 16)
			pnt[index++] = 0;
	}
}

	void
str2in6_addr (const char *str, struct in6_addr *addr)
{
	int i;
	unsigned int x;

	/* %x must point to unsinged int */
	for (i = 0; i < 16; i++)
	{
		sscanf (str + (i * 2), "%02x", &x);
		addr->s6_addr[i] = x & 0xff;
	}
}
#endif /* HAVE_IPV6 */

	void
apply_mask (struct prefix *p)
{
	switch (p->family)
	{
		case AF_INET:
			apply_mask_ipv4 ((struct prefix_ipv4 *)p);
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			apply_mask_ipv6 ((struct prefix_ipv6 *)p);
			break;
#endif /* HAVE_IPV6 */
		default:
			break;
	}
	return;
}

	struct prefix *
new_prefix(u_char preflen, struct in_addr * prefix){
	struct prefix * p;
	p = (struct prefix *)calloc(1, sizeof(struct prefix));
	p->family = AF_INET;
	p->prefixlen = preflen; 
	memcpy(&p->u.prefix4, prefix, sizeof(struct in_addr));

	return (p);
}

	void *
prefix2str(struct prefix * p){
	char buf[512];
	char * rt;
	u_char rt_len;
	
	bzero(buf, 512);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, 512);
	rt_len = (p->family == AF_INET)?INET_ADDRSTRLEN:INET6_ADDRSTRLEN;
	rt_len += 5;
	rt = calloc(rt_len,sizeof(char));
	sprintf(rt, "%s/%d",buf,p->prefixlen);
	rt[rt_len] = '\0';
	return rt;
}
