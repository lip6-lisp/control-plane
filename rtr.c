#include "lib.h"
#include "db.h"
#include "udp.h"

	int
search_rloc_cmp(void *rloc, void *entry)
{
	struct map_entry *me = (struct map_entry *)entry;

	if (!me || !rloc)
		return -1;

	return addrcmp(rloc, &me->rloc);
}

	int
rtr_forward_map_register(struct pk_req_entry *pke)
{
	/* include ECM header in pke buffer */
	pke->buf_len += (uint8_t *)pke->buf - (uint8_t *)pke->lh;
	pke->buf = pke->lh;

	/* set ECM header bits */
	pke->lh->R = 0;
	pke->lh->N = 1;

	cp_log(LDEBUG, "Forward ECMed Map-Register to %s:%d\n",
		sk_get_ip(&pke->ih_di, ip), sk_get_port(&pke->ih_di));

	/* select socket for ds */
	if (pke->ih_di.sa.sa_family != AF_INET) {
		cp_log(LDEBUG, "unsupported address family\n");
		return -1;
	}

	if (sendto(skfd, pke->lh, pke->buf_len, 0,
		   &pke->ih_di.sa, sizeof(struct sockaddr_in)) == -1) {
		cp_log(LLOG, "sendto error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

	int
rtr_process_map_register(struct pk_req_entry *pke)
{
	struct map_register_hdr *lcm = (struct map_register_hdr *)pke->buf;
	union map_register_record_generic *rec;
	uint8_t *xtr_id;
	struct db_table *db;
	struct db_node *mapping;
	struct prefix eid;
	struct mapping_flags flags;
	union map_register_locator_generic *loc;
	uint8_t lcount;
	size_t len;
	int local_rloc_pass = 0;
	struct list_entry_t *le, *le_tmp;
	struct map_entry *me;

	if (lcm->record_count > 1) {
		cp_log(LDEBUG, "ECMed Map_Register should have only one mapping record\n");
		return -1;
	}

	if (!lcm->I) {
		cp_log(LDEBUG, "ECMed Map_Register record should have an xTR-ID\n");
		return -1;
	}

	xtr_id = (uint8_t *)pke->buf + pke->buf_len - (16 + 8); /* 129bits xTR-ID + 64bits site-ID */

	rec = (union map_register_record_generic *)CO(lcm,
				sizeof(*lcm) + ntohs(lcm->auth_data_length));

	/* get EID-prefix */
	memset(&eid, 0, sizeof(eid));
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
		cp_log(LDEBUG, "unsuported address family\n");
		return -1;
	}
	eid.prefixlen = rec->record.eid_mask_len;

	/* find node if it already exists */
	db = ms_get_db_table(ms_db, &eid);
	mapping = db_node_match_prefix(db, &eid);
	if (mapping) {
		while (mapping != db->top && !ms_node_is_type(mapping, _MAPP))
			mapping = mapping->parent;
	}

	if (!mapping || mapping == db->top) {
		/* create new mapping */
		memset(&flags, 0, sizeof(flags));
		flags.act = rec->record.act;
		flags.A = rec->record.a;
		flags.version = rec->record.version;
		flags.ttl = ntohl(rec->record.ttl);
		flags.referral = 0;
		flags.proxy = lcm->proxy_map_reply;
		flags.range = _MAPP;
		mapping = generic_mapping_new(&eid);
		if (!mapping) {
			cp_log(LLOG, "failed to create new mapping\n");
			return -1;
		}
		cp_log(LDEBUG, "Creat new mapping for EID prefix %s\n",
		       prefix2str(&eid));
		generic_mapping_set_flags(mapping, &flags);
	}

	lcount = rec->record.locator_count;
	len = _get_reply_record_size(rec);
	loc = (union map_register_locator_generic *)CO(rec, 0);
	while (len? lcount-- : lcount) {
		union sockunion rloc;
		uint8_t R;

		loc = (union map_register_locator_generic *)CO(loc, len);
		len = sizeof(struct map_register_locator);

		if (ntohs(loc->rloc.rloc_afi) != LISP_AFI_IP) {
			cp_log(LDEBUG, "Unsupporte AFI for an ETR behind a NAT\n");
			return -1;
		}

		/* Reachable locator that is no this RTR's RLOC, skip */
		if (memcmp(&pke->di.sin.sin_addr, &loc->rloc.rloc,
			   sizeof(struct in_addr)) != 0 && loc->rloc.R)
			continue;

		/* do two pass for the RTR's RLOC : first for the implicit
		 * ETR's natted RLOC then for the RTR's local RLOC */
		if (loc->rloc.R && local_rloc_pass == 0) {
			memcpy(&rloc.sin.sin_addr, &pke->ih_si.sin.sin_addr,
			       sizeof(struct in_addr));
			local_rloc_pass ++;
			len = 0;
			R = 0;
		} else {
			memcpy(&rloc.sin.sin_addr, &loc->rloc.rloc,
			       sizeof(struct in_addr));
			R = loc->rloc.R;
		}
		rloc.sin.sin_family = AF_INET;

		/* search for an already existing entry for this rloc */
		le = list_search(mapping->info, &rloc, search_rloc_cmp);
		if (le) {
			me = le->data;
			if (memcmp(me->xtr_id, xtr_id, sizeof(me->xtr_id)) == 0) {
				me->nonce = ntohll(lcm->nonce);
				me->unverified = 1;
				/* do not update priority and weight with
				 * implicit ETR's natted RLOC */
				if (len == 0)
					continue;

				me->priority = loc->rloc.priority;
				me->weight = loc->rloc.weight;
				me->m_priority = loc->rloc.m_priority;
				me->m_weight = loc->rloc.m_weight;
				cp_log(LDEBUG, "Update RLOC: %s, priority=%u, weight=%u, m_priority=%u, m_weight=%u\n",
				       sk_get_ip(&me->rloc, ip), me->priority,
				       me->weight, me->m_priority, me->m_weight);
			}
			continue;
		}

		/* Do not create an entry for unreachable RLOCs not issuing this
		 * Map-reguister */
		if (memcmp(&pke->ih_si.sin.sin_addr, &rloc.sin.sin_addr,
			   sizeof(struct in_addr)) != 0 && !loc->rloc.R)
			continue;

		me = calloc(1, sizeof(*me));
		if (!me) {
			cp_log(LLOG, "memory allocation failed: %s\n",
			       strerror(errno));
			return -1;
		}
		memcpy(&me->rloc, &rloc, sizeof(rloc));
		me->priority = loc->rloc.priority;
		me->weight = loc->rloc.weight;
		me->m_priority = loc->rloc.m_priority;
		me->m_weight = loc->rloc.m_weight;
		me->r = R;
		me->L = loc->rloc.L;
		me->p = loc->rloc.p;
		me->unverified = 1;

		me->natted = 1;
		memcpy(&me->nat_rloc, &pke->si, sizeof(me->nat_rloc));
		memcpy(&me->rtr_rloc, &pke->di, sizeof(me->rtr_rloc));
		me->nonce = ntohll(lcm->nonce);
		if (xtr_id)
			memcpy(me->xtr_id, xtr_id, sizeof(me->xtr_id));

		list_insert(mapping->info, me, NULL);

		cp_log(LDEBUG, "Add new RLOC: %s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d\n",
		       sk_get_ip(&me->rloc, ip), me->priority, me->weight,
		       me->m_priority, me->m_weight, me->r, me->L, me->p);
	}

	/* purge not updated rlocs associated with this xTR (xTR-ID) */
	le = ((struct list_t *)mapping->info)->head.next;
	while(le != &((struct list_t *)mapping->info)->tail) {
		me = le->data;
		le_tmp = le;
		le = le->next;
		if (memcmp(me->xtr_id, xtr_id, sizeof(me->xtr_id)) == 0 &&
		    !me->unverified) {
			cp_log(LDEBUG, "Remove deprecated RLOC: %s\n",
			       sk_get_ip(&me->rloc, ip));
			list_remove(mapping->info, le_tmp, NULL);
			free(me);
		}
	}

	return rtr_forward_map_register(pke);
}

	int
rtr_send_data_map_notify(struct pk_req_entry *pke, union sockunion *dest)
{
	struct lisp_data_hdr ldh;
	unsigned int instance_id = DATA_MAP_NOTIFY_INSTANCE_ID;
	uint8_t *buf;
	size_t buf_len;
	char ip2[INET6_ADDRSTRLEN];

	/* prepare lisp data header*/
	memset(&ldh , 0, sizeof(ldh));
	ldh.I = 1;
	memcpy(ldh.instance_id, &instance_id, sizeof(ldh.instance_id));

	/* encapsulate map-notify in the lisp_data_header */
	buf = build_encap_pkt(pke->buf, pke->buf_len, &ldh, sizeof(ldh),
			      &pke->ih_si, &pke->ih_di, &buf_len);
	if (!buf)
		return -1;

	cp_log(LDEBUG, "Forward ECMed Map-Notify to %s:%d via %s:%d\n",
	       sk_get_ip(&pke->ih_di, ip), sk_get_port(&pke->ih_di),
	       sk_get_ip(dest, ip2), sk_get_port(dest));

	/* select socket */
	if (dest->sa.sa_family != AF_INET) {
		cp_log(LDEBUG, "unsupported address family\n");
		free(buf);
		return -1;
	}

	if (sendto(skfd, buf, buf_len, 0, &dest->sa,
		   sizeof(struct sockaddr_in)) == -1) {
		cp_log(LLOG, "sendto error: %s\n", strerror(errno));
		free(buf);
		return -1;
	}

	free(buf);

	return 0;
}

	int
rtr_process_map_notify(struct pk_req_entry *pke)
{
	struct map_notify_hdr *lcm = (struct map_notify_hdr *)pke->buf;
	union map_notify_record_generic *rec;
	uint8_t *xtr_id;
	struct db_table *db;
	struct db_node *mapping;
	struct prefix eid;
	union map_notify_locator_generic *loc;
	union sockunion *dest = NULL;
	uint8_t lcount;
	size_t len;
	int local_rloc_pass = 0;
	struct map_entry *me;
	struct list_entry_t *le, *le_tmp;

	if (lcm->record_count > 1) {
		cp_log(LDEBUG, "ECMed Map_Notify should have only one mapping record\n");
		return -1;
	}

	if (!lcm->I) {
		cp_log(LDEBUG, "ECMed Map_Notify record should have an xTR-ID\n");
		return -1;
	}

	xtr_id = (uint8_t *)pke->buf + pke->buf_len - (16 + 8); /* 128bits xTR-ID + 64bits site-ID */

	rec = (union map_notify_record_generic *)CO(lcm,
				sizeof(*lcm) + ntohs(lcm->auth_data_length));

	/* get EID-prefix */
	memset(&eid, 0, sizeof(eid));
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
		cp_log(LDEBUG, "unsuported address family\n");
		return -1;
	}
	eid.prefixlen = rec->record.eid_mask_len;

	/* find node */
	db = ms_get_db_table(ms_db, &eid);
	mapping = db_node_match_prefix(db, &eid);
	if (mapping) {
		while (mapping != db->top && !ms_node_is_type(mapping, _MAPP))
			mapping = mapping->parent;
	}

	if(!mapping || mapping == db->top) {
		cp_log(LDEBUG, "no mapping found for EID prefix %s\n",
		       prefix2str(&eid));
		return -1;
	}

	lcount = rec->record.locator_count;
	len = _get_reply_record_size(rec);
	loc = (union map_notify_locator_generic *)CO(rec, 0);
	while (len? lcount-- : lcount) {
		struct list_entry_t *le;
		union sockunion rloc;

		loc = (union map_notify_locator_generic *)CO(loc, len);
		len = sizeof(struct map_register_locator);

		if (ntohs(loc->rloc.rloc_afi) != LISP_AFI_IP) {
			cp_log(LDEBUG, "Unsupporte AFI for an ETR behind a NAT\n");
			return -1;
		}

		/* Reachable locator that is no this RTR's RLOC, skip */
		if (memcmp(&pke->di.sin.sin_addr, &loc->rloc.rloc,
			   sizeof(struct in_addr)) != 0 && loc->rloc.R)
			continue;

		/* do two pass for the RTR's RLOC : first for the implicit
		 * ETR's natted RLOC then for the RTR's local RLOC */
		if (loc->rloc.R && local_rloc_pass == 0) {
			memcpy(&rloc.sin.sin_addr, &pke->ih_di.sin.sin_addr,
			       sizeof(struct in_addr));
			local_rloc_pass ++;
			len = 0;
		} else {
			memcpy(&rloc.sin.sin_addr, &loc->rloc.rloc,
			       sizeof(struct in_addr));
		}
		rloc.sin.sin_family = AF_INET;

		le = list_search(mapping->info, &rloc, search_rloc_cmp);
		if (!le)
			continue;

		me = le->data;
		if (memcmp(me->xtr_id, xtr_id, sizeof(me->xtr_id)) != 0 ||
		    me->nonce != ntohll(lcm->nonce))
			continue;

		me->unverified = 0;

		/* global translated RLOC */
		if (len == 0)
			dest = &me->nat_rloc;
	}

	/* purge unverified rlocs of this xTR (xTR-ID) */
	le = ((struct list_t *)mapping->info)->head.next;
	while(le != &((struct list_t *)mapping->info)->tail) {
		me = le->data;
		le_tmp = le;
		le = le->next;
		if (memcmp(me->xtr_id, xtr_id, sizeof(me->xtr_id)) == 0 &&
		    me->unverified) {
			cp_log(LDEBUG, "Remove unverified RLOC: %s",
			       sk_get_ip(&me->rloc, ip));
			list_remove(mapping->info, le_tmp, NULL);
			free(me);
		}
	}

	if (!dest) {
		cp_log(LDEBUG, "could not found destination nat rloc\n");
		return -1;
	}

	return rtr_send_data_map_notify(pke, dest);
}
