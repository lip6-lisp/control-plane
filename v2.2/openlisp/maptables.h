/*- /usr/src/sys/net/lisp/maptables.h
 *
 * Copyright (c) 2010 - 2011 The OpenLISP Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  Contributors: 
 *               Luigi Iannone <ggx@openlisp.org>
 *
 * $Id: maptables.h 177 2011-09-22 14:33:51Z ggx $
 *
 */

/*
 *  Copyright (c) 1980, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _MAP_TABLES_H_
#define _MAP_TABLES_H_

#ifdef _KERNEL
#include "opt_lisp.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#endif /*_KERNEL*/

#include <net/radix.h>
#include <netinet/in.h>


#define IPv4_EIDs_TABLE 0
#define IPv6_EIDs_TABLE 1
#define MAX_TABLES 2

/* MAPTABLES returns the pointer to the radix_node_head of the 
 * maptables for AF_INET and AF_INET6, NULL otherwise.
 */
#define MAPTABLES(m,t)						\
        if (t == AF_INET) {					\
	       m = map_tables[IPv4_EIDs_TABLE];			\
	} else if (t == AF_INET6) {                             \
	       m = map_tables[IPv6_EIDs_TABLE];			\
	       } else { m = NULL; }


/* Useful constant */
#define MAX_RLOC_PRI  255   /* Max allowed priority. A value of 
			     * 255 means that that RLOC MUST not 
			     * be used.
			     */

struct rloc_mtx {           /* GgX - Metrics associated to the RLOC
			     * Usefull for messages mapping sockets 
			     */

        uint8_t priority;    /* GgX - Each RLOC has a priority. 
			      */
        uint8_t weight;      /* GgX - Each locator has a weight. Used for 
			      * for load balancing pusposes when two or
			      * more locators have the same priority.
			      * The sum of the weight fields of all rlocs 
			      * having the same priority must always be 100
			      * or 0. the latter means all to 0.
			      */
        uint16_t flags;      /* GgX it is 16 bit to achieve 32 alignment
			      * and contains useful flags	
			      */

        uint32_t mtu;        /* GgX - MTU for the specific RLOC.
			      * This entry is meaningful only for local
			      * mapping (i.e., part of the database)
			      * for wich the flag 'i' is set (local interface).
			      * The field is initialized only at creation
			      * by copying the value of the corresponding
			      * interface. If the MTU of the interface 
			      * changes afterwards, the field is not updated.
			      * 
			      * By now mtu given through mapping sockets 
			      * is ignored.
			      */

        struct nonce_type tx_nonce; /* Nonce to be used when sending a
				    * LISP encapsulated packet to the RLOC.
				    */

        struct nonce_type rx_nonce; /* Nonce to be used when receiving a
				     * LISP encapsulated packet to the RLOC.
				     */

};

/* RLOC metrics Flags Definition */
#define RLOCF_UP        0x01    /* RLOC Status bit . */ 
#define RLOCF_LIF       0x02    /* RLOC is a local interface.
				 * This is only valid for local mappings.
				 */
#define RLOCF_TXNONCE     0x04    /* RLOC Tx Nonce present. */ 
#define RLOCF_RXNONCE     0x08    /* RLOC Rx Nonce present. */ 

struct rloc_metrics {

	u_long	 rlocmtx_locks;/* Kernel must leave these values alone */

        struct rloc_mtx rlocmtx; /* GgX -  Metrics     */

	u_long	rloc_hit; /* Number of times this RLOC has been selected */

};


/*
 * An  entry consists of a source address (or subnet) (EIDs)
 * and a reference to a LISP entry. The LISP entry is a set of RLOCs.
 */

/* GgX - An RLOC is either an IPv6 or an IPv4 full ip address.
 * This is why a sockaddr_storage is used.
 * 
 */
struct locator {
        struct sockaddr_storage * rloc_addr;
        struct rloc_metrics rloc_metrix;
};



/* GgX - Since there can be several locators associated to the same EID 
 * the locator data structure includes a pointer in order to create lists
 */ 

struct locator_chain{
        struct locator rloc;
        struct locator_chain * next;	     
};


struct mapentry {
	struct	radix_node map_nodes[2];    /* tree glue, and other values */
	/* GgX - From original code:
	 * XXX struct mapentry must begin with a struct radix_node 
	 * (or two!) because the code does some casts of 
	 * a 'struct radix_node *' to a 'struct mapentry *'
	 */
#define	map_key(r)	(*((struct sockaddr **)(&(r)->map_nodes->rn_key)))
#define	map_mask(r)	(*((struct sockaddr **)(&(r)->map_nodes->rn_mask)))
#define	map_rlocsnum(r)	((r)->rlocs_cnt)
#define	map_rlocs(r)	((r)->rlocs)

        struct locator_chain * rlocs;  /* Set of locators */
        int    rlocs_cnt;              /* Number of rlocs */
        lsbits_type rlocs_statusbits;  /* Needed for compatibility with 
					* ITR not supporting versioning
					*/
        uint16_t vnum;                 /* Version Number of the mapping
					*/ 
        uint16_t pad;                  /* Just to keep 32 bits alignment.
					*/
	u_long	 map_flags;		/* local/remote? */
	long	 map_refcnt;		/* # held references */
        time_t   map_lastused;          /* When the mapping has been used
					 * last time
					 */

#ifdef _KERNEL
 /* XXX ugly, user apps use this definition but don't have a mtx def */
	struct	mtx map_mtx;		/* mutex for map entry */
#endif
};


/* GgX - A mapping for a specific EID consists of a mapentry
 * and the EID itself.
 */
struct eidmap {
        struct mapentry *mapping;
        struct sockaddr_storage eid;
};


#define	MAPF_DB	        0x001	/* Mapping is part of the Database */
#define	MAPF_VERSIONING	0x002	/* Mapping uses Versioning */
#define	MAPF_LOCBITS	0x004	/* Mapping uses LocStatus bits */
#define MAPF_STATIC	0x008	/* manually added */
#define	MAPF_UP		0x010	/* Mapping usable */
#define	MAPF_ALL	0x020	/* Operation concerns both DB and Cache */
#define MAPF_EXPIRED    0x040   /* Not used for more than XPGTO time */
#define MAPF_NEGATIVE   0x080   /* Negative Mapping (no RLOCs forward 
				 * natively)
				 */
#define MAPF_DONE	0x100	/* message confirmed */


/*
 * Mapping statistics (Mixed IPv4 IPv6).
 */
struct	mapstats {
        uint64_t    miss;    /* failed lookups */
        uint64_t    hit;     /* successfull lookups */
};

struct	mappingstats {

        struct mapstats db;    /* Database Stats */

        struct mapstats cache; /* Cache Stats */
};

/*
 * Structures for routing messages.
 */
struct map_msghdr {
	uint8_t	 map_msglen;	/* to skip over non-understood messages */
	uint8_t	 map_version;   /* future binary compatibility */
	uint16_t map_type;	/* message type */

	uint32_t map_flags;	/* flags, incl. kern & message, e.g. DONE */
	uint16_t map_addrs;	/* bitmask identifying sockaddrs in msg */
        uint16_t map_versioning;/* Mapping Version Number */

        int     map_rloc_count;/* Number of rlocs appended to the msg */
	pid_t	map_pid;	/* identify sender */
	int	map_seq;	/* for sender to identify action */
	int	map_errno;	/* why failed */

};

#define MAPM_VERSION	1	/* Up the ante and ignore older versions */

/*
 * Message types.
 */
#define MAPM_ADD	   0x01	 /* Add Map */
#define MAPM_DELETE	   0x02	 /* Delete Map */
#define MAPM_CHANGE	   0x03	 /* Change Mapping (not yet implemented) */
#define MAPM_GET 	   0x04	 /* Get matching mapping */
#define MAPM_MISS          0x05  /* Lookup Failed  (general case) */
#define MAPM_MISS_EID      0x06  /* Lookup Failed  and EID returned */
#define MAPM_MISS_HEADER   0x07  /* Lookup Failed  and IP header returned */
#define MAPM_MISS_PACKET   0x08  /* Lookup Failed  and Packet returned */
#define MAPM_LSBITS        0x09  /* Locator Status Bits Changed */
#define MAPM_LOCALSTALE    0x0A  /* Local Map Version is stale */
#define MAPM_REMOTESTALE   0x0B  /* Remote Map Version is stale */
#define MAPM_NONCEMISMATCH 0x0C  /* Rceived a mismatching nonce */


/* Sysctl missmsg state definition
 */
#define LISP_MISSMSG_EID           1
#define LISP_MISSMSG_HEADER        2
#define LISP_MISSMSG_PACKET        3

/* Sysctl ETR state definition
 */
#define LISP_ETR_STANDARD          1
#define LISP_ETR_NOTIFY            2
#define LISP_ETR_SECURE            3

/*
 * Bitmask values for map_addrs.
 */
#define MAPA_EID	0x01	 /* EID sockaddr present */
#define MAPA_EIDMASK	0x02	 /* netmask sockaddr present */
#define MAPA_RLOC	0x04	 /* Locator present */

/*
 * Index offsets for sockaddr array for alternate internal encoding.
 */
#define MAPX_EID	0	 /* EID sockaddr present */
#define MAPX_EIDMASK	1	 /* EIDmask sockaddr present */
#define MAPX_RLOC	2	 /* RLOC sockaddr present */
#define MAPX_MAX	3	 /* size of array to allocate */

struct map_addrinfo {
	int	 mapi_addrs;
	struct	sockaddr_storage *mapi_info[MAPX_MAX];
        /* GgX - RLOC is a chain, thus  needs a different treatment. 
         * When using mapi_info[MAPX_RLOC] we have to cast
         * the pointer to a locator_chain struct
	 */
        uint32_t mapi_rloc_count; /* Number of rlocs */   
	int	 mapi_flags;
        uint16_t mapi_versioning; /* Map Versioning Number */

        uint16_t pad;             /* Not used. It just keeps the whole 
				   * structure 32 bits aligned! 
				   */
};
 
/*
 * This macro returns the size of a struct sockaddr when passed
 * through a routing socket. Basically we round up ss_len to
 * a multiple of sizeof(long), with a minimum of sizeof(long).
 * The check for a NULL pointer is just a convenience, probably never used.
 * The case ss_len == 0 should only apply to empty structures.
 * Since we never use port, flow label or other, there are at least 
 * 16 bit that are wasted. But alignment helps in speeding up
 * memory transfers.
 */
#define SS_SIZE(ss)							\
    (  (!(ss) || ((struct sockaddr_storage *)(ss))->ss_len == 0) ?	\
       sizeof(long)		:					\
	1 + ( (((struct sockaddr_storage *)(ss))->ss_len - 1) | (sizeof(long) - 1) ) )

/* GgX - Gives back the size of the chunk of memory necessary to
 * store an rloc. The size is give from the size of the sockaddr itself
 * plus the locator chain overhead.
 */
#define RLOC_SIZE(ss)							\
    (  (!(ss) || ((struct sockaddr_storage *)(ss))->ss_len == 0) ?	\
       (sizeof(struct locator_chain) + sizeof(long))		:	\
	sizeof(struct locator_chain) + 1 + ( (((struct sockaddr_storage *)(ss))->ss_len - 1) | (sizeof(long) - 1) ) )



#ifdef _KERNEL

#define	MAP_LOCK_INIT(_map) \
	mtx_init(&(_map)->map_mtx, "mapentry", NULL, MTX_DEF | MTX_DUPOK)


#define	MAP_LOCK(_map)		mtx_lock(&(_map)->map_mtx)

#define	MAP_UNLOCK(_map)	mtx_unlock(&(_map)->map_mtx)

#define	MAP_LOCK_DESTROY(_map)	mtx_destroy(&(_map)->map_mtx)

#define	MAP_LOCK_ASSERT(_map)	mtx_assert(&(_map)->map_mtx, MA_OWNED)


#define	MAP_ADDREF(_map) do {					\
	MAP_LOCK_ASSERT(_map);					\
	KASSERT((_map)->map_refcnt >= 0,			\
		("negative refcnt %ld", (_map)->map_refcnt));	\
	(_map)->map_refcnt++;					\
	} while (0)

#define	MAP_REMREF(_map) do {					\
	MAP_LOCK_ASSERT(_map);					\
	KASSERT((_map)->map_refcnt > 0,				\
		("bogus refcnt %ld", (_map)->map_refcnt));	\
	(_map)->map_refcnt--;					\
        } while (0)

#define	MAPFREE_LOCKED(_map) do {				\
		if ((_map)->map_refcnt <= 1)			\
			mapfree(_map);				\
		else {						\
			MAP_REMREF(_map);			\
			MAP_UNLOCK(_map);			\
		}						\
		/* guard against invalid refs */		\
		_map = 0;					\
	} while (0)
	
#define	MAPFREE(_map) do {					\
		MAP_LOCK(_map);					\
		MAPFREE_LOCKED(_map);				\
	} while (0)


#define FREE_EIDMAP(_eidmap)				\
        MAP_REMREF(_eidmap->mapping);			\
	free(_eidmap, M_TEMP);


extern struct radix_node_head *map_tables[MAX_TABLES];

void	 map_notifymsg(int, struct map_addrinfo *, struct mapentry *,
		       struct mbuf **, int, int *);

int	 map_setentry(struct mapentry *, struct sockaddr_storage *);
struct locator * map_findrloc(struct mapentry *, struct sockaddr_storage *);

int      map_select_srcrloc(struct mapentry * , struct locator *, 
			    struct locator **);

int      map_select_dstrloc(struct mapentry *, struct locator ** );
int      map_check_lsbits(struct mapentry * , lsbits_type * );
int      map_notify_smr(struct sockaddr_storage * eid);

/*
 * Note the following locking behavior:
 *
 *    dblookup(), cachelooup(), maprequest() return map->mapping unlocked
 */
void     dblookup(struct eidmap *);
void     cachelookup(struct eidmap *);
void     locked_dblookup(struct eidmap *);
void     locked_cachelookup(struct eidmap *);
int	 maprequest(int, struct map_addrinfo *, struct mapentry **);
void	 mapfree(struct mapentry *);

#endif /* _KERNEL */
 

#endif /* _MAP_TABLES_H_ */

