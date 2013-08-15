/*- /usr/src/sys/net/lisp/lisp.h
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
 * $Id: lisp.h 177 2011-09-22 14:33:51Z ggx $
 *
 */

#ifndef _LISP_H_
#define _LISP_H_

#include <netinet/in.h>

/* Switches for debugging
 */
#define LISP_DEBUG 1
#define LISP_BASIC_DEBUG 1

extern int lispmissmsg;
extern int lispetr;

extern int lispdebug;
#define DEBUGLISP(x) \
        if (lispdebug) {log(LOG_DEBUG,x);}


/* General Settings
 */

#define LISPMAXSTRLEN        32


/* Well-Known Port Numbers
 */
#define LISPDATA       4341  /* LISP Reserved port for Data encap/decap. 
			      */
#define LISPSIG        4342  /* LISP Reserved port for signaling. 
			      * Message like Map-Request and Map-Reply 
			      * use this port number.
			      */
#define MAXKEYLEN        10  /* Max size of the array containing the 
			      * field to hash for src port selection.
			      * This is the number of uint32_t.
			      * The max length is in the case of extended 
			      * hash (includes src and dst port number) for 
			      * an IPv6 packet:
			      * 8 uint32_t for the addresses
			      * 1 uint32_t for the protocol number
			      * 1 uint32_t for src & dst ports number
			      *
			      */


/* LISP Stats
 * This structure is used:
 * /sys/netinet/lisp/ip_lisp.c        IPv4 Statistics
 * /sys/netinet6/lisp6/ip6_lisp6.c    IPv6 Statistics
 */
struct	lispbasicstat {
				/* input statistics: */
	uint32_t ipackets;	  /* total input packets */
	uint32_t ioafpackets;	  /* total input packet with a different 
				   * AF family in the outer header packet 
				   */
	uint32_t ihdrops; 	  /* packet shorter than header */
        uint32_t ibadencap;	  /* no local mapping present */
	uint32_t ibadlen;	  /* data length larger than packet */
        uint32_t ibadsrcvnum;     /* bad source version number */
        uint32_t ibaddstvnum;     /* bad dst version number */

				/* output statistics: */
	uint32_t  opackets;		/* total output packets */
        uint32_t  ooafpackets;	        /* total input packet with a different 
					 * AF family in the inner packet 
					 */
        uint32_t  omissdrops;           /* Drops due to cache-miss. */
        uint32_t  onorlocdrops;         /* Drops due to No suitable RLOC. */
        uint32_t  osizedrops;           /* Drops due to MTU check. */
        uint32_t  onobufdrops;          /* Drops due to no buffer space. */
        uint32_t  odrops;               /* packet droped on output */
};

/*
 * LISP Specific error condiition
 * This MUST not be used outside the kernel LISP specific code.
 */

#ifdef _KERNEL
#define ELISP_HDREINVAL     1
#define ELISP_SRCVNUMINVAL  2
#define ELISP_DSTVNUMINVAL   3
#endif /* _KERNEL */

/*
 * LISP Packets data types and data structures.
 */

/* LISP Header in draft-ietf-lisp-08.txt
 *
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  L / |N|L|E|V|I|flags|                  Nonce/Map-Version            | 
 *  I   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  S \ |                 Instance ID/Locator Reach Bits                |
 *  P   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/* 
 * Locator Status bits - Data type and Macros.
 */ 

typedef uint32_t  lsbits_type;   /* unsigned 32 bit for block 
				   * manipulation. 
				   */

/* These two MUST be the same */
#define MAXLBIT    32    /* Max Number of Locator Status Bits */
#define MAXRLOCS   32    /* Max Number of RLOCs allowed in mapping */

/* Locator Status bit insertion by shift operation 
 */
#if BYTE_ORDER == LITTLE_ENDIAN

#define LSBITSHIFT(s) (1 << s)

#endif

#if BYTE_ORDER == BIG_ENDIAN

#define LSBITSHIFT(s) (1 << s)

#endif

/*
 * Versioning Bits
 */

struct vnum_subhdr {
  
        uint32_t pad:8,         /* padding */
                 src_vnum:12,   /* Source Version Number in 
				 * Network Byte Order
			         */
                 dst_vnum:12;   /* Destination Version Number in 
				 * Network Byte Order
				 */
};

#define MAXVNUM    4095
#define WRAPVNUM   2047
#define NULLVNUM   0

#define MASKVNUM(z)    (0x00000FFF & z)
 
/* The following returns 1 if x is newer the y.
 * Note that NULL version number check is not done here and should be
 * done by the user of the macro.
 */
#define NEWERVNUM(x,y) 			                \
  ( ( (MASKVNUM(x) < WRAPVNUM) &&                       \
      (MASKVNUM(x) < MASKVNUM(y)) &&                    \
      (MASKVNUM(y) < MASKVNUM((x + WRAPVNUM)))) ? 1 :   \
      ( ( (MASKVNUM(x) > WRAPVNUM) &&                   \
	  ((MASKVNUM(x) < MASKVNUM(y)) ||               \
	   (MASKVNUM(y) < MASKVNUM((x + WRAPVNUM))) ) ? 1 : 0 )) )	


struct instanceid_subhdr {
  
        uint32_t ID:24,         /* Instance ID */
                 shortlsb:8;    /* Short Loc-Stat-Bits 
			         */

};


/* Nonce 24-bit to be kept in Network byte order 
 */
struct nonce_type { /* Nonce data type */

      uint32_t pad:8,         /* padding */
                nvalue:24;      /* nonce value */

};      
#define NONCEMASK 0x00FFFFFF
#define MAXNONCE  16777216

struct lispflags { /* LISP Header flags */
      
#if BYTE_ORDER == LITTLE_ENDIAN
        uint32_t   rflag:3,            /* Reserved bits */
                    I:1,                /* Instance ID Bit */
                    V:1,                /* Versioning bit  */
                    E:1,                /* Echo-Nonce bit */
                    L:1,                /* Locator bit */ 
                    N:1,                /* Nonce bit */
                    pad:24;             /* padding */
#endif

#if BYTE_ORDER == BIG_ENDIAN
        uint32_t    N:1,                /* Nonce bit       */
                    L:1,                /* Locator bit     */ 
                    E:1,                /* Echo-Nonce bit  */
                    V:1,                /* Versioning bit  */
                    I:1,                /* Instance ID Bit */
                    rflag:3,            /* Reserved bits   */
                    pad:24;             /* padding         */
#endif

};
  
struct lispshimhdr {                     /* LISP Specific shim header
					  *
					  * Flags V and N are mutually 
					  * exclusive.
					  * The max number of Loc Status
					  * Bits is fixed to 32 (MAXLBIT).
					  */		
        union flags_nonce {
    
	        struct lispflags flags;      /* LISP Flags */

	        struct nonce_type hdrnonce;  /* Nonce */  

	        struct vnum_subhdr vnum;     /* String with Version Numbers
					      */
              
	} fnv;

  /* Useful shortcuts
   */
#define Nbit  fnv.flags.N
#define Lbit  fnv.flags.L
#define Ebit  fnv.flags.E
#define Vbit  fnv.flags.V
#define Ibit  fnv.flags.I
#define Nonce fnv.hdrnonce.nvalue
#define Svnum fnv.vnum.src_vnum
#define Dvnum fnv.vnum.dst_vnum


        union locstat_instance {

                lsbits_type locbits;     /* String of Locator Status bits  
					 */

	        struct instanceid_subhdr ilsb;  /* Instance ID and short 
						 * Loc-Stat-Bits
						 */
	} ils;

  /* Useful shortcuts
   */
#define LSbits ils.locbits
#define SLSbits ils.ilsb.locbits
#define iID ils.ilsb.ID

  /*#define Svnum lsv.vnum.src_vnum
    #define Dvnum lsv.vnum.dst_vnum*/

};


/* 
 * RLOC Address - 
 * We union in_addr and in6_addr for RLOCs addresses, so that routines 
 * manipulating RLOCs are unique, by using some macros that select 
 * the correct type based on the address family
 */
union rloc_addr {                       /* RLOC address type union of 
					 * in_addr and in6_addr. This allows 
					 * flexible call to some maptable 
					 * routines.
					 */
  struct in_addr  ipaddr;               /* Address IPv4 */
  struct in6_addr ip6addr;              /* Address IPv6 */

};  


     
/* 
 * Usefull Macros
 */

/* Returns the size of the IP header depending on the address 
 * Family
 */
#define SIZEOF_IPHDR(_af)				  		 \
  ((_af == AF_INET) ? (sizeof(struct ip)) :                      \
   ((_af == AF_INET6)?(sizeof(struct ip6_hdr)):	0))
 

/* 
 * Functions Prototype 
 */
#ifdef _KERNEL

struct eidmap;
struct locator;
/* Data structure and function needed for other sysctl handlers.
 */
struct keytab {
	char	*cptr;
	int	seq;
};

int            sysctl_matchkeyword(char *, struct keytab *);

void           m_copylisphdr(struct mbuf **, struct lispshimhdr *);

struct mbuf *  m_lisphdrprepend(struct mbuf *, struct eidmap *, 
				struct eidmap *, struct locator *, 
				struct locator *);

uint16_t       get_lisp_srcport(struct mbuf **);

int            check_lisphdr( struct lispshimhdr *, struct eidmap,
			      struct eidmap, struct locator *, 
			      struct locator *, int *);

#endif /* _KERNEL */

#endif  /* _LISP_H_ */
