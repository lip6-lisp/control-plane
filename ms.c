#include "lib.h"
#include "db.h"
#include "udp.h"

/* Send Info-Reply */
	int
ms_send_info_rep(struct pk_req_entry *pke, struct site_info *site)
{
	char *buf, *ptr;
	struct info_msg_hdr *imh;
	struct lcaf_hdr *lcaf;
	uint16_t auth_len = HMAC_SHA1_DIGEST_LENGTH;
	size_t buf_len;
	int i;
	struct list_entry_t *entry;
	union sockunion *addr, dest;
	size_t slen;
	int sock;

	buf = calloc(PKBUFLEN, sizeof(char));
	if (!buf) {
		cp_log(LLOG, "memory allocation error: %s", strerror(errno));
		return -1;
	}
	ptr = buf;
	memcpy(buf, pke->buf, pke->buf_len);
	/* set type and bit set for Info-Reply */
	imh = (struct info_msg_hdr*)ptr;
	imh->R = 1;
	ptr += pke->buf_len - sizeof(uint16_t); /* remove AFI = 0 field */
	/* Fill NAT LCAF */
	lcaf = (struct lcaf_hdr*)ptr;
	lcaf->afi = htons(LCAF_AFI);
	lcaf->type = LCAF_NATT;
	ptr += sizeof(*lcaf);

	*(uint16_t *)ptr = htons(LISP_CP_PORT);
	ptr += sizeof(uint16_t);
	*(uint16_t *)ptr = htons(sk_get_port(&pke->si));
	ptr += sizeof(uint16_t);
	entry = &rtr_db->head;
	for (i = 0; i < (3 + rtr_db->count); i++) {
		switch (i) {
		case 0:
			addr = &pke->si;
			break;
		case 1:
			addr = &pke->di;
			break;
		case 2:
			addr = NULL;
			break;
		default:
			entry = entry->next;
			addr = &((struct rtr_entry*)(entry->data))->rloc;
			break;
		}

		if (!addr) {
			*(uint16_t *)ptr = 0;
			ptr += sizeof(uint16_t);
			continue;
		}

		switch (addr->sa.sa_family) {
		case AF_INET:
			*(uint16_t *)ptr = htons(LISP_AFI_IP);
			ptr += sizeof(uint16_t);
			memcpy(ptr, &addr->sin.sin_addr,
			       sizeof(addr->sin.sin_addr));
			ptr += sizeof(addr->sin.sin_addr);
			break;
		case AF_INET6:
			*(uint16_t *)ptr = htons(LISP_AFI_IPV6);
			ptr += sizeof(uint16_t);
			memcpy(ptr, &addr->sin6.sin6_addr,
			       sizeof(addr->sin6.sin6_addr));
			ptr += sizeof(addr->sin6.sin6_addr);
			break;
		default:
			cp_log(LDEBUG, "unsupported address family\n");
			free(buf);
			return -1;
		}
	}
	lcaf->payload_len = htons(ptr - (char *)lcaf - sizeof(*lcaf));
	buf_len = ptr - buf;

	/* compute authentication data */
	imh->key_id = htons(1); //HMAC-SHA-1-96
	imh->auth_data_length = htons(auth_len);
	_ms_recal_hashing(buf, buf_len, site->key, imh->auth_data, 0);

	memcpy(&dest, &pke->si, sizeof(dest));
	sk_set_port(&dest, sk_get_port(&pke->si));

	cp_log(LDEBUG, "Send Info-Reply to %s:%d\n",
		sk_get_ip(&dest, ip), sk_get_port(&dest));

	/* select socket for ds */
	switch (dest.sa.sa_family) {
	case AF_INET:
		sock = skfd;
		slen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		sock = skfd6;
		slen = sizeof(struct sockaddr_in6);
		break;
	default:
		cp_log(LDEBUG, "unsupported address family\n");
		free(buf);
		return -1;
	}

	if (sendto(sock, buf, buf_len, 0, &dest.sa, slen) == -1) {
		cp_log(LLOG, "sendto error: %s\n", strerror(errno));
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}

/* Process Info-Resquest message */
	int
ms_process_info_req(struct pk_req_entry *pke)
{
	char *ptr = pke->buf;
	struct info_msg_hdr *lcm = (struct info_msg_hdr*) ptr;
	size_t auth_len = ntohs(lcm->auth_data_length);
	char *auth_data;
	union info_msg_eid *rec;
	struct prefix eid;
	struct db_table *db;
	struct db_node *node;
	struct list_entry_t *s_entry;
	struct site_info *site;
	char *s_hmac;
	int ret;

	cp_log(LDEBUG, "LCM: <type=%u, R=%u, M=%u, nonce=0x%lx, key id=%u, auth data length=%u\n", \
				lcm->lisp_type,
				lcm->R, \
				ntohll(lcm->nonce), \
				ntohs(lcm->key_id), \
				ntohs(lcm->auth_data_length));

	cp_log(LDEBUG, "Info-Request: Authenticate ETR....\n");

	ptr += sizeof(*lcm);
	auth_data = ptr;
	ptr += auth_len + sizeof(info_msg_ttl_t);
	rec = (union info_msg_eid*)ptr;

	/* get EID-prefix */
	bzero(&eid, sizeof(struct prefix));
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		eid.family = AF_INET;
		eid.u.prefix4 = rec->record.eid_prefix;
		break;
	case LISP_AFI_IPV6:
		eid.family = AF_INET6;
		eid.u.prefix6 = rec->record6.eid_prefix;
		break;
	default:
		cp_log(LDEBUG, "unsuported family\n");
		return -1;
	}
	eid.prefixlen = rec->record.eid_mask_len;

	/* search for EID-prefix, must: belong to one active site */
	db = ms_get_db_table(ms_db, &eid);
	node = db_node_match_prefix(db, &eid);
	if (!node) {
		cp_log(LDEBUG, "EID %s not found\n", prefix2str(&eid));
		return -1;
	}

	while (node != db->top && !ms_node_is_type(node, _EID))
		node = node->parent;

	if (node == db->top) {
		cp_log(LDEBUG, "EID %s not in registed range\n", prefix2str(&eid));
		return -1;
	}
	s_entry = ((struct mapping_flags *)node->flags)->rsvd;

	/* authenticate ETR */
	cp_log(LDEBUG, "Info-Request: Authenticate processing........\n");

	site = (struct site_info *)s_entry->data;
	s_hmac = malloc(auth_len);
	if (!s_hmac) {
		cp_log(LLOG, "memory allocation error: %s", strerror(errno));
		return -1;
	}

	_ms_recal_hashing(pke->buf, pke->buf_len, site->key, s_hmac, 0);
	ret = strncmp(auth_data, s_hmac, auth_len);
	free(s_hmac);
	if (ret != 0) {
		cp_log(LDEBUG, "Info-Request: Authentication not success....., ignore package\n");
		return -1;
	}

	cp_log(LDEBUG, "Info-Request: Authenticate - OK\n");
	cp_log(LDEBUG, "Info-Request: Send info request\n");

	ms_send_info_rep(pke, site);

	return 0;
}
