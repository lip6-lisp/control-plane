#ifndef __HAVE_UDP_H
#define __HAVE_UDP_H

#define LISP_AFI_IP	1
#define LISP_AFI_IPV6	2

#define BUFLEN 512
#define PKBUFLEN 65527
#define	LISP_TYPE_RESERVED	0x0
#define LISP_TYPE_MAP_REQUEST	0x1
#define LISP_TYPE_MAP_REPLY	0x2
#define LISP_TYPE_MAP_REGISTER	0x3
#define LISP_TYPE_MAP_NOTIFY	0x4
#define	LISP_TYPE_MAP_REFERRAL	0x6
#define LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE	0x8
#define LISP_TYPE_INFO_MSG	0x7

#define LCAF_AFI	16387
#define LCAF_NATT	7
#define LCAF_TE		10
/*
 *      CO --
 *
 *      Calculate Offset
 *
 *      Try not to make dumb mistakes with
 *      pointer arithmetic
 *
 */



/* <AFI, Address> tuple IPv4 */
struct afi_address {
	uint16_t	afi;
	struct in_addr	address;
} __attribute__ ((__packed__));

/* <AFI, Address> tuple IPv6 */
struct afi_address6 {
	uint16_t	afi;
	struct in6_addr	address;
} __attribute__ ((__packed__));

/* <AFI, Address> tuple IPv4 and IPv6*/
union afi_address_generic {
	struct afi_address ip;
	struct afi_address6 ip6;
};

/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Type=6 |                Reserved               | Record Count  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Nonce . . .                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         . . . Nonce                           |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   |                          Record  TTL                          |
|   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R   | Referral Count| EID mask-len  | ACT |A|I|     Reserved        |
e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
c   |SigCnt |   Map Version Number  |            EID-AFI            |
o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
r   |                          EID-prefix ...                       |
d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
| L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| o |        Unused Flags         |R|         Loc/LCAF-AFI          |
| c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  \|                             Locator ...                       |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           AFI = 16387         |     Rsvd1     |     Flags     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type = 2    | IID mask-len  |             4 + n             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Instance ID                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              AFI = x          |         Address  ...          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct map_referral_lcaf_afi {
uint16_t	afi;
uint8_t		rsvd1;
uint8_t		flags;
uint8_t		type;
uint8_t		iid_masklen;
uint16_t	length;
uint32_t	iid;
};

struct map_referral_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		rsvd:4;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		rsvd:4;
#endif
	uint16_t	reserved;
	uint8_t		record_count;
	uint64_t	nonce;
}  __attribute__ ((__packed__));

struct map_referral_record {
	uint32_t	ttl;
	uint8_t		referral_count;
	uint8_t		eid_mask_len;
#ifdef LITTLE_ENDIAN
	uint8_t		reserved:3;
	uint8_t		i:1;
	uint8_t		a:1;
	uint8_t		act:3;
#else
	uint8_t		act:3;
	uint8_t		a:1;
	uint8_t		i:1;
	uint8_t		reserved:3;
#endif
	uint8_t		reserved1;
#ifdef LITTLE_ENDIAN
	uint16_t	version:12;
	uint16_t	sig_cnt:4;
#else
	uint16_t	sigcnt:4;
	uint16_t	version:12;
#endif
	struct map_referral_lcaf_afi lcaf;
	uint16_t	eid_prefix_afi;
	struct in_addr	eid_prefix;
} __attribute__ ((__packed__));

struct map_referral_record6 {
	uint32_t	ttl;
	uint8_t		referral_count;
	uint8_t		eid_mask_len;
#ifdef LITTLE_ENDIAN
	uint8_t		reserved:3;
	uint8_t		i:1;
	uint8_t		a:1;
	uint8_t		act:3;
#else
	uint8_t		act:3;
	uint8_t		a:1;
	uint8_t		i:1;
	uint8_t		reserved:3;
#endif
	uint8_t		reserved1;
#ifdef LITTLE_ENDIAN
	uint16_t	version:12;
	uint16_t	sig_cnt:4;
#else
	uint16_t	sigcnt:4;
	uint16_t	version:12;
#endif
	struct map_referral_lcaf_afi lcaf;
	uint16_t	eid_prefix_afi;
	struct in6_addr	eid_prefix;
} __attribute__ ((__packed__));

union map_referral_record_generic {
	struct map_referral_record	record;
	struct map_referral_record6	record6;
};

struct map_referral_locator {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags;
#ifdef LITTLE_ENDIAN
	uint8_t		R:1;
	uint8_t		unused_flags1:7;
#else
	uint8_t		unused_flags1:7;
	uint8_t		R:1;
#endif
	uint16_t	rloc_afi;
	struct in_addr	rloc;
} __attribute__ ((__packed__));

struct map_referral_locator6 {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags;
#ifdef LITTLE_ENDIAN
	uint8_t		R:1;
	uint8_t		unused_flags1:7;
#else
	uint8_t		unused_flags1:7;
	uint8_t		R:1;
#endif
	uint16_t	rloc_afi;
	struct in6_addr  rloc;
} __attribute__ ((__packed__));

union map_referral_locator_generic {
	struct map_referral_locator rloc;
	struct map_referral_locator6 rloc6;
};



/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Type=2 |P|E|S|          Reserved               | Record Count  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Nonce . . .                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         . . . Nonce                           |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   |                          Record  TTL                          |
|   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
r   |                          EID-prefix                           |
d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
| L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| o |        Unused Flags     |L|p|R|           Loc-AFI             |
| c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  \|                             Locator                           |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct map_reply_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		rsvd:1;
	uint8_t		security_bit:1;
	uint8_t		echo_nonce_capable:1;
	uint8_t		rloc_probe:1;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		rloc_probe:1;
	uint8_t		echo_nonce_capable:1;
	uint8_t		security_bit:1;
	uint8_t		rsvd:1;
#endif
	uint16_t	reserved;
	uint8_t		record_count;
	uint64_t	nonce;
}  __attribute__ ((__packed__));

struct map_reply_record {
	uint32_t	ttl;
	uint8_t		locator_count;
	uint8_t		eid_mask_len;
#ifdef LITTLE_ENDIAN
	uint8_t		reserved:4;
	uint8_t		a:1;
	uint8_t		act:3;
#else
	uint8_t		act:3;
	uint8_t		a:1;
	uint8_t		reserved:4;
#endif
	uint8_t		reserved1;
#ifdef LITTLE_ENDIAN
	uint16_t	version:12;
	uint16_t	rsvd:4;
#else
	uint16_t	rsvd:4;
	uint16_t	version:12;
#endif
	uint16_t	eid_prefix_afi;
	struct in_addr	eid_prefix;
} __attribute__ ((__packed__));

struct map_reply_record6 {
	uint32_t	ttl;
	uint8_t		locator_count;
	uint8_t		eid_mask_len;
#ifdef LITTLE_ENDIAN
	uint8_t		reserved:4;
	uint8_t		a:1;
	uint8_t		act:3;
#else
	uint8_t		act:3;
	uint8_t		a:1;
	uint8_t		reserved:4;
#endif
	uint8_t		reserved1;
#ifdef LITTLE_ENDIAN
	uint16_t	version:12;
	uint16_t	rsvd:4;
#else
	uint16_t	rsvd:4;
	uint16_t	version:12;
#endif
	uint16_t	eid_prefix_afi;
	struct in6_addr	eid_prefix;
} __attribute__ ((__packed__));

union map_reply_record_generic {
	struct map_reply_record		record;
	struct map_reply_record6	record6;
};

struct map_reply_locator {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags;
#ifdef LITTLE_ENDIAN
	uint8_t		R:1;
	uint8_t		p:1;
	uint8_t		L:1;
	uint8_t		unused_flags1:5;
#else
	uint8_t		unused_flags1:5;
	uint8_t		L:1;
	uint8_t		p:1;
	uint8_t		R:1;
#endif
	uint16_t	rloc_afi;
	struct in_addr	rloc;
} __attribute__ ((__packed__));

struct map_reply_locator6 {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags;
#ifdef LITTLE_ENDIAN
	uint8_t		R:1;
	uint8_t		p:1;
	uint8_t		L:1;
	uint8_t		unused_flags1:5;
#else
	uint8_t		unused_flags1:5;
	uint8_t		L:1;
	uint8_t		p:1;
	uint8_t		R:1;
#endif
	uint16_t	rloc_afi;
	struct in6_addr  rloc;
} __attribute__ ((__packed__));

union map_reply_locator_generic {
	struct map_reply_locator rloc;
	struct map_reply_locator6 rloc6;
};

struct lcaf_hdr{
	uint16_t 	afi;
	uint8_t		reserved;
	uint8_t		flags;
	uint8_t		type;
	uint8_t		reserved2;
	uint16_t	payload_len;
};

struct rloc_te{
	uint16_t	afi;
#ifdef LITTLE_ENDIAN
	uint16_t	reserved:13;
	uint8_t		L:1;
	uint8_t		P:1;
	uint8_t		S:1;
#else
	uint8_t		L:3;
	uint8_t		P:1;
	uint8_t		S:1;
	uint8_t		reserved:13;
#endif
	struct in_addr	hop_addr;
};

struct rloc6_te{
	uint16_t	afi;
#ifdef LITTLE_ENDIAN
	uint16_t	reserved:13;
	uint8_t		L:1;
	uint8_t		P:1;
	uint8_t		S:1;
#else
	uint8_t		L:3;
	uint8_t		P:1;
	uint8_t		S:1;
	uint8_t		reserved:13;
#endif
	struct in6_addr	hop_addr;
};
union rloc_te_generic {
	struct rloc_te rloc;
	struct rloc6_te rloc6;
};

struct map_reply_locator_te {
	uint8_t		priority;
	uint8_t		weight;
	uint8_t		m_priority;
	uint8_t		m_weight;
	uint8_t		unused_flags;
#ifdef LITTLE_ENDIAN
	uint8_t		R:1;
	uint8_t		p:1;
	uint8_t		L:1;
	uint8_t		unused_flags1:5;
#else
	uint8_t		unused_flags1:5;
	uint8_t		L:1;
	uint8_t		p:1;
	uint8_t		R:1;
#endif
	struct lcaf_hdr lcaf;
} __attribute__ ((__packed__));

/* Map-Referral handling code */
void * udp_map_referral_init(void *data);

int udp_map_referral_add_record(void *data, uint32_t iid, struct prefix *p,
							uint32_t ttl, uint8_t lcount, uint32_t version,
							uint8_t A, uint8_t act, uint8_t i, uint8_t sigcnt);

int udp_map_referral_add_locator(void *data, struct map_entry *e);

int udp_map_referral_error(void *data);

int udp_map_referral_terminate(void *data);

/* ! Map-Referral handling code */



/* Map-Reply handling code */
void *udp_map_reply_init(void *data);

int udp_map_reply_add_record(void *data, struct prefix *p,
						uint32_t ttl, uint8_t lcount,
						uint32_t version, uint8_t A, uint8_t act);

int udp_map_reply_add_locator(void *data, struct map_entry *e);

int udp_map_reply_terminate(void *data);

/* ! Map-Reply handling code */

/* Map-Request handling code */
struct map_request{
	char *eid;
	uint64_t nonce;
};

int udp_request_terminate(void *data);

int udp_request_get_eid(void *data, struct prefix *p);

uint64_t udp_request_get_nonce(void *data);

int udp_request_is_ddt(void *data);

int udp_request_get_itr(void *data, union sockunion *itr, int afi);

int udp_request_get_port(void *data, uint16_t *port);

void *udp_request_add(void *data, uint8_t security, uint8_t ddt,\
		uint8_t A, uint8_t M, uint8_t P, uint8_t S,\
		uint8_t p, uint8_t s, uint64_t nonce,\
		const union sockunion *src, \
		const union sockunion *dst, \
		const struct prefix *eid );

uint32_t _forward_to_etr(void *data, struct db_node *rn);
int _send_negative_map_reply(void *data, struct communication_fct *fct, \
		struct db_node *rn, struct prefix *pf, uint32_t ttl, uint8_t A, uint8_t act,	uint8_t version );
/* ! Map-Request handling code */

/* Communication handling code */
void *udp_start_communication(void *context);

void *udp_stop_communication(void *context);

/* Map Serveur specifique fonctions */
void *_ms_recal_hashing(const void *packet, int pk_len, void *key, void *rt, int no_nonce);
int ms_process_info_req(struct pk_req_entry *pke);

int addrcmp(union sockunion *src, union sockunion *dst);

uint8_t *build_encap_pkt(uint8_t *pkt, size_t pkt_len, void *lisp_oh,
			 size_t lisp_oh_len, const union sockunion *src,
			 const union sockunion *dst, size_t *buf_len);

size_t _get_reply_record_size(const union map_reply_record_generic *rec);

/* RTR specifique fonctions */
int rtr_process_map_register(struct pk_req_entry *pke);
int rtr_process_map_notify(struct pk_req_entry *pke);

/*
 * Map-Request draft-ietf-lisp-22 structures definition
 * Map encapsulated control message draft-fuller-lisp-ddt-00
 *
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
LH  |Type=8 |S|D|R|N|                 Reserved                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  / |                       IPv4 or IPv6 Header                     |
IH  |                  (uses RLOC or EID addresses)                 |
  \ |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  / |       Source Port = xxxx      |       Dest Port = yyyy        |
UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \ |           UDP Length          |        UDP Checksum           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
LCM |Type=1 |A|M|P|S|p|s|   Reserved      |   IRC   | Record Count  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Nonce . . .                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         . . . Nonce                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Source-EID-AFI        |   Source EID Address  ...     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \ |                       EID-prefix  ...                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Map-Reply Record  ...                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct lisp_control_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		N:1;
	uint8_t		R:1;
	uint8_t		ddt_originated:1;
	uint8_t		security_bit:1;
	uint8_t		type:4;
#else
	uint8_t		type:4;
	uint8_t		security_bit:1;
	uint8_t		ddt_originated:1;
	uint8_t		R:1;
	uint8_t		N:1;
#endif
	uint8_t		reserved[3];
} __attribute__ ((__packed__));


struct map_request_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		smr_bit:1;
	uint8_t		rloc_probe:1;
	uint8_t		map_data_present:1;
	uint8_t		auth_bit:1;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		auth_bit:1;
	uint8_t		map_data_present:1;
	uint8_t		rloc_probe:1;
	uint8_t		smr_bit:1;
#endif
#ifdef LITTLE_ENDIAN
	uint8_t         reserved1:6;
	uint8_t         smr_invoke_bit:1;
	uint8_t         pitr_bit:1;
#else
	uint8_t		pitr_bit:1;
	uint8_t		smr_invoke_bit:1;
	uint8_t		reserved1:6;
#endif
#ifdef LITTLE_ENDIAN
	uint8_t		irc:5;
	uint8_t		reserved2:3;
#else
	uint8_t		reserved2:3;
	uint8_t		irc:5;
#endif
	uint8_t		record_count;
	uint64_t	nonce;
}  __attribute__ ((__packed__));



/* Map-Request record tuple IPv4 */
struct map_request_record {
	uint8_t		reserved;
	uint8_t		eid_mask_len;
	uint16_t	eid_prefix_afi;
	struct in_addr	eid_prefix;
} __attribute__ ((__packed__));


/* Map-Request record tuple IPv6 */
struct map_request_record6 {
	uint8_t		reserved;
	uint8_t		eid_mask_len;
	uint16_t	eid_prefix_afi;
	struct in6_addr	eid_prefix;
} __attribute__ ((__packed__));

/* Map-Request record tuple IPv4 and IPv6 */
union map_request_record_generic {
	struct map_request_record	record;
	struct map_request_record6	record6;
};
/*
	0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           AFI = 16387         |     Rsvd1     |     Flags     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type = 2    | IID mask-len  |             4 + n             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Instance ID                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              AFI = x          |         Address  ...          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct map_request_record_lcaf {
	uint8_t		reserved;
	uint8_t		eid_mask_len;
	uint16_t	afi;
	uint8_t		rsvd1;
	uint8_t		flags;
	uint8_t		type;
	uint8_t		iid_masklen;
	uint16_t	length;
	uint32_t	iid;
	uint16_t	eid_prefix_afi;
	struct in_addr	eid_prefix;
} __attribute__ ((__packed__));

struct map_request_record6_lcaf {
	uint8_t		reserved;
	uint8_t		eid_mask_len;
	uint16_t	afi;
	uint8_t		rsvd1;
	uint8_t		flags;
	uint8_t		type;
	uint8_t		iid_masklen;
	uint16_t	length;
	uint32_t	iid;
	uint16_t	eid_prefix_afi;
	struct in6_addr	eid_prefix;
} __attribute__ ((__packed__));

union map_request_record_generic_lcaf {
	struct map_request_record_lcaf	record;
	struct map_request_record6_lcaf	record6;
};
/* =========================================================== */

/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Type=3 |P|  |I|       Reserved               |M| Record Count  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Nonce . . .                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         . . . Nonce                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Key ID             |  Authentication Data Length   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                     Authentication Data                       ~
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   |                          Record  TTL                          |
|   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
r   |                          EID-prefix                           |
d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
| L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| o |        Unused Flags     |L|p|R|           Loc-AFI             |
| c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  \|                             Locator                           |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct map_register_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		R:1; /* TODO: no longer RFC compliante */
	uint8_t		I:1;
	uint8_t		rsvd:1;
	uint8_t		proxy_map_reply:1;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		proxy_map_reply:1;
	uint8_t		rsvd:1;
	uint8_t		I:1;
	uint8_t		R:1; /* TODO: no longer RFC compliante */
#endif
        uint8_t     reserved1;
#ifdef LITTLE_ENDIAN
	uint8_t     want_map_notify:1;
        uint8_t     reserved2:7;
#else
        uint8_t     reserved2:7;
	uint8_t     want_map_notify:1;
#endif
	uint8_t		record_count;
	uint64_t        nonce;
	uint16_t	key_id;
	uint16_t	auth_data_length;
	uint8_t		auth_data[0];
}  __attribute__ ((__packed__));

#define map_register_record_generic 	map_reply_record_generic
#define map_register_locator 		map_reply_locator
#define map_register_locator6 		map_reply_locator6
#define map_register_locator_generic 	map_reply_locator_generic

/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Type=4 |I|            Reserved                 | Record Count  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Nonce . . .                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         . . . Nonce                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Key ID             |  Authentication Data Length   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                     Authentication Data                       ~
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   |                          Record  TTL                          |
|   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
r   |                          EID-prefix                           |
d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
| L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| o |        Unused Flags     |L|p|R|           Loc-AFI             |
| c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  \|                             Locator                           |
+-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct map_notify_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		rsvd:3;
	uint8_t		I:1;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		I:1;
	uint8_t		rsvd:3;
#endif
	uint8_t		reserved[2];
	uint8_t		record_count;
	uint64_t        nonce;
	uint16_t	key_id;
	uint16_t	auth_data_length;
	uint8_t		auth_data[0];
}  __attribute__ ((__packed__));

#define map_notify_record_generic 	map_reply_record_generic
#define map_notify_locator 		map_reply_locator
#define map_notify_locator6 		map_reply_locator6
#define map_notify_locator_generic 	map_reply_locator_generic

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Type=7 |R|               Reserved                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Nonce . . .                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      . . . Nonce                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Key ID             |  Authentication Data Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                     Authentication Data                       ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              TTL                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          EID-prefix                           |
+->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  |           AFI = 16387         |    Rsvd1      |     Flags     |
|  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  |    Type = 7     |     Rsvd2   |             4 + n             |
|  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
N  |        MS UDP Port Number     |      ETR UDP Port Number      |
A  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
T  |              AFI = x          | Global ETR RLOC Address  ...  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
L  |              AFI = x          |       MS RLOC Address  ...    |
C  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
A  |              AFI = x          | Private ETR RLOC Address ...  |
F  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  |              AFI = x          |      RTR RLOC Address 1 ...   |
|  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  |              AFI = x          |       RTR RLOC Address n ...  |
+->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct  info_msg_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		rsvd:3;
	uint8_t		R:1;
	uint8_t		lisp_type:4;
#else
	uint8_t		lisp_type:4;
	uint8_t		R:1;
	uint8_t		rsvd:3;
#endif
	uint8_t		reserved[3];
	uint64_t	nonce;
	uint16_t	key_id;
	uint16_t	auth_data_length;
	uint8_t		auth_data[0];
}  __attribute__ ((__packed__));

#define info_msg_ttl_t uint32_t
#define info_msg_eid map_request_record_generic

/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |N|L|E|V|I|flags|            Nonce/Map-Version                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Instance ID/Locator-Status-Bits               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct lisp_data_hdr {
#ifdef LITTLE_ENDIAN
	uint8_t		flags:3;
	uint8_t		I:1;
	uint8_t		V:1;
	uint8_t		E:1;
	uint8_t		L:1;
	uint8_t		N:1;
#else
	uint8_t		N:1;
	uint8_t		L:1;
	uint8_t		E:1;
	uint8_t		V:1;
	uint8_t		I:1;
	uint8_t		flags:3;
#endif
	uint8_t		nonce[3];
	uint8_t		instance_id[3];
	uint8_t		lsbs;
}  __attribute__ ((__packed__));

#define DATA_MAP_NOTIFY_INSTANCE_ID 0xFFFFFF

#endif
