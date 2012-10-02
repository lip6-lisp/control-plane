/*-/usr/src/sbin/mapd/lig.h
 *
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
 * $Id: send_map_request.c 185 2011-09-24 11:22:53Z ggx $
 *
 */

/*
 *	send_map_request.c
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *      Functions related to sending a map-request
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Tue Apr 14 14:48:13 2009
 *
 *	IPv6 support added by Lorand Jakab <lj@icanhas.net>
 *	Mon Aug 23 15:26:51 2010 +0200
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     o Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the University nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 *	 $Header: /mnt/disk1/dmm/src/lig/RCS/send_map_request.c,v 1.1 2010/11/14 20:48:35 dmm Exp $ 
 *
 */

#include	"map_register_reply.h"

//
//Check if a IP address is right
//

unsigned int usable_addr(addr)
     struct sockaddr	*addr;
{
    char buf[NI_MAXHOST];
    int e;

    if ((e = getnameinfo(addr,SA_LEN(addr->sa_family),
						buf,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) != 0)
	{
		fprintf(stderr,"getnameinfo: %s\n",gai_strerror(e));
		exit(-1);
    }
	return(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&
		strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN));
}

/*
 *	get_saddr for source ip in inner header in EMR
 *
 */

int get_saddr(afi,saddr)
     int		afi;
     struct     sockaddr    *saddr;
{
    struct	ifaddrs		*ifaddr, *ifptr;
    if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 0;
    }

	ifptr = ifaddr;
    for (ifptr = ifaddr; ifptr != NULL; ifptr = ifptr->ifa_next) {
		if (ifptr->ifa_addr == NULL)
			continue;
		if (ifptr->ifa_addr->sa_family != afi )
			continue;
		if (usable_addr(ifptr->ifa_addr)) {
		    memcpy((void *) saddr,ifptr->ifa_addr,SA_LEN(afi));
		    freeifaddrs(ifaddr);
			return 0;
		}
    }

	freeifaddrs(ifaddr);
    return -1;
}

/*
 *	send_map_request --
 *
 *	Sends a IP/UDP encapsulated map-request for eid to map_server
 *
 *
 *	Here's the packet we need to build:
 *
 *                      IP header (ip.src = <us>, ip.dst = <map-resolver>) 
 *                      UDP header (udp.srcport = <kernel>, udp.dstport = 4342) 
 *       lcp         -> lisp_control_pkt
 *       packet,iph  -> IP header (ip.src = <this host>, ip.dst = eid) 
 *       udph        -> UDP (udp.srcport = ANY, udp.dstport = 4342) 
 *       map_request -> struct map-request 
 *
 *	We'll open a UDP socket on dest port 4342, and 
 *	give it a "packet" that that looks like:
 *
*          lcp -> lisp_control_pkt
 *  packet,iph -> IP header (SRC = this host,  DEST = eid)
 *	  udph -> UDP (DEST PORT = 4342)
 * map_request -> struct map-request
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 16 14:46:51 2009
 *
 *	$Header: /mnt/disk1/dmm/src/lig/RCS/send_map_request.c,v 1.1 2010/11/14 20:48:35 dmm Exp $
 *
 */

int send_map_request(s,nonce0,nonce1,before,eid_addr,map_resolver_addr,my_addr, emr_inner_src_port, smr_bit)
     int		s;
     unsigned int	nonce0;
     unsigned int	nonce1;
     struct timeval     *before;
     struct sockaddr	*eid_addr;
     struct sockaddr	*map_resolver_addr;
     struct sockaddr	*my_addr; 
	 int  emr_inner_src_port;
	 int smr_bit;
{

    unsigned int		ip_len		   = 0;
    unsigned int		udp_len		   = 0;
    unsigned int		packet_len	   = 0;
    int				nbytes		   = 0;
    int				e		   = 0;
    char buf1[NI_MAXHOST];
    char buf2[NI_MAXHOST];

    uchar			packet[MAX_IP_PACKET];	
    struct lisp_control_pkt	*lcp;
    struct ip			*iph;
    struct ip6_hdr		*ip6h;
    struct udphdr		*udph;
    struct map_request_pkt	*map_request;
    struct map_request_eid	*map_request_eid;
	unsigned int udp_checksum_disabled	= 0;
	unsigned int debug			= 0;
    /*
     * The source address in the inner IP header
     * 
     * Its address family depends on the destination EID, regardless of the
     * Map-Resolver. If the host has no usable IPv6 address, the "::" address
     * will be used.
     *
     */

    struct sockaddr_storage	inner_src;

    if (get_saddr(eid_addr->sa_family,&inner_src)) {
	struct addrinfo	    hints;
	struct addrinfo	    *res;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = eid_addr->sa_family;
	hints.ai_socktype  = 0;
	hints.ai_flags     = AI_NUMERICHOST;
	hints.ai_protocol  = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr      = NULL;
	hints.ai_next      = NULL;

	/* Update IPv6 with the v4 mapped address instead of :: */

	if ((e = getaddrinfo(
			(eid_addr->sa_family == AF_INET) ? "0.0.0.0" : "::",
			NULL, &hints, &res)) != 0) {
	    fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
	    exit(BAD);
	}

	memcpy(&inner_src, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    }
    if (debug > 2) {
	getnameinfo((struct sockaddr *)&inner_src,
		SA_LEN(((struct sockaddr *)&inner_src)->sa_family),
		buf1,NI_MAXHOST,NULL,0,NI_NUMERICHOST);
	getnameinfo(eid_addr,SA_LEN(eid_addr->sa_family),buf2,NI_MAXHOST,NULL,0,NI_NUMERICHOST);
	fprintf(stderr, "send_map_request (inner header): <%s:%d,%s:%d>\n",
		buf1,
		emr_inner_src_port,
		buf2,
		LISP_CONTROL_PORT);
    }

    /*
     *	make sure packet is clean
     */

    memset(packet, 0, MAX_IP_PACKET);

    /*
     *	Build the packet.
     *
     *	The packet has the following form:
     *
     *	 outer-ip-header		built by the kernel
     *	 udp-header (4342)		built by the kernel
     *	 lisp lisp control packet 	struct  lisp_control_pkt *lcp
     *	 inner-ip-header		struct ip      *iphdr
     *	 udp-header (4342)		struct udphdr  *udphdr
     *   lisp-header (map-request)	struct map_request_pkt *map_request
     */

    /*
     *	CO is a macro that makes sure the pointer 
     *  arithmetic is done correctly. Basically...
     *
     *   #define	CO(addr,len) (((char *) addr + len))
     *
     */

    lcp			= (struct lisp_control_pkt *) packet;

    if (eid_addr->sa_family == AF_INET) {
	iph		= (struct ip *)               CO(lcp,  sizeof(struct lisp_control_pkt));
	ip6h		= NULL;
	udph		= (struct udphdr *)           CO(iph,  sizeof(struct ip));
    } else {
	iph		= NULL;
	ip6h		= (struct ip6_hdr *)          CO(lcp,  sizeof(struct lisp_control_pkt));
	udph		= (struct udphdr *)           CO(ip6h, sizeof(struct ip6_hdr));
    }

    map_request         = (struct map_request_pkt *)  CO(udph, sizeof(struct udphdr));

    if (my_addr->sa_family == AF_INET)
        map_request_eid  = (struct map_request_eid *)  CO(map_request, sizeof(struct map_request_pkt) + sizeof(struct in_addr));
    else
        map_request_eid  = (struct map_request_eid *)  CO(map_request, sizeof(struct map_request_pkt) + sizeof(struct in6_addr));
    /*
     *  compute lengths of interest
     */

    udp_len	= sizeof(struct udphdr) + sizeof(struct map_request_pkt)
                                        + sizeof(struct map_request_eid);

    if (my_addr->sa_family == AF_INET)
        udp_len = udp_len               + sizeof(struct in_addr);
    else
        udp_len = udp_len               + sizeof(struct in6_addr);
    
    if (eid_addr->sa_family == AF_INET) {
        udp_len = udp_len               + sizeof(struct in_addr);
	ip_len	= udp_len		+ sizeof(struct ip);
    } else {
        udp_len = udp_len               + sizeof(struct in6_addr);
	ip_len	= udp_len		+ sizeof(struct ip6_hdr);
    }

    packet_len  = ip_len                + sizeof(struct lisp_control_pkt);

    /*
     *	Tell the Map Resolver its an LISP Encapsulated control packet 
     */

    lcp->type = LISP_ENCAP_CONTROL_TYPE; 

    /*
     *	Build inner IP header
     *
     *  packet,iph -> IP header (SRC = this host,  DEST = EID)
     *
     */

    if (eid_addr->sa_family == AF_INET) {
	iph->ip_hl         = 5;
	iph->ip_v          = 4;
	iph->ip_tos        = 0;
	iph->ip_len        = htons(ip_len);	/* ip + udp headers, + map_request */
	iph->ip_id         = htons(54321);	/* the value doesn't matter here */
	iph->ip_off        = 0;
	iph->ip_ttl        = 255;
	iph->ip_p          = IPPROTO_UDP;
	iph->ip_sum        = 0;		/* compute checksum later */
	iph->ip_src.s_addr = ((struct sockaddr_in *)&inner_src)->sin_addr.s_addr;
	iph->ip_dst.s_addr = ((struct sockaddr_in *)eid_addr)->sin_addr.s_addr;
    } else {
	ip6h->ip6_vfc	   = 0x6E;
	ip6h->ip6_plen     = htons(udp_len);	/* udp header + map_request */
	ip6h->ip6_nxt      = IPPROTO_UDP;
	ip6h->ip6_hlim     = 64;
	ip6h->ip6_src      = ((struct sockaddr_in6 *)&inner_src)->sin6_addr;
	ip6h->ip6_dst      = ((struct sockaddr_in6 *)eid_addr)->sin6_addr;
    }

    /*
     *	Build UDP inner header
     *
     *   DEST Port is 4342 (LISP Control)
     */


#ifdef BSD
    udph->uh_sport = htons(emr_inner_src_port);
    udph->uh_dport = htons(LISP_CONTROL_PORT);
    udph->uh_ulen  = htons(udp_len);
    udph->uh_sum   = 0;
#else
    udph->source = htons(emr_inner_src_port);
    udph->dest   = htons(LISP_CONTROL_PORT);
    udph->len    = htons(udp_len);
    udph->check  = 0;
#endif

    /* 
     *	Build the Map-Request
     *
     *	Map-Request Message Format 
     *    
     *          0                   1                   2                   3
     *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |Type=1 |A|M|P|S|       Reserved      |   IRC   | Record Count  |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                         Nonce . . .                           |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                         . . . Nonce                           |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |         Source-EID-AFI        |   Source EID Address  ...     |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                              ...                              |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
     * Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   \ |                       EID-prefix  ...                         |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                   Map-Reply Record  ...                       |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                     Mapping Protocol Data                     |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */ 

    /*
     * We set Source-EID-AFI to 0 and skip the Source EID Address field
     */

    map_request->smr_bit                     = smr_bit;
    map_request->rloc_probe                  = 0;
    map_request->map_data_present            = 0;
    map_request->auth_bit                    = 0;
    map_request->lisp_type                   = LISP_MAP_REQUEST;
    map_request->irc                         = 0;
    map_request->record_count                = 1;
    map_request->lisp_nonce0                 = htonl(nonce0); 
    map_request->lisp_nonce1                 = htonl(nonce1); 
    map_request->source_eid_afi              = 0;

    if (my_addr->sa_family == AF_INET) {
        map_request->itr_afi                 = htons(LISP_AFI_IP);
        memcpy(&(map_request->originating_itr_rloc),
                &(((struct sockaddr_in *)my_addr)->sin_addr), sizeof(struct in_addr));
    } else {
        map_request->itr_afi                 = htons(LISP_AFI_IPV6);
        memcpy(&(map_request->originating_itr_rloc),
                &(((struct sockaddr_in6 *)my_addr)->sin6_addr), sizeof(struct in6_addr));
    }

    if (eid_addr->sa_family == AF_INET) {
        map_request_eid->eid_mask_len	     = LISP_IP_MASK_LEN;
        map_request_eid->eid_prefix_afi      = htons(LISP_AFI_IP);
        memcpy(&map_request_eid->eid_prefix,
                &(((struct sockaddr_in *)eid_addr)->sin_addr), sizeof(struct in_addr));
        iph->ip_sum			     = ip_checksum(packet,ip_len);
    } else {
        map_request_eid->eid_mask_len	     = LISP_IPV6_MASK_LEN;
        map_request_eid->eid_prefix_afi      = htons(LISP_AFI_IPV6);
        memcpy(&map_request_eid->eid_prefix,
                &(((struct sockaddr_in6 *)eid_addr)->sin6_addr), sizeof(struct in6_addr));
    }

    if (udp_checksum_disabled)
	udpsum(udph) = 0;
    else {
	if (eid_addr->sa_family == AF_INET)
	    udpsum(udph) = udp_checksum(udph,udp_len,iph->ip_src.s_addr,iph->ip_dst.s_addr);
	else
	    udpsum(udph) = udp6_checksum(ip6h,udph,udp_len);
    }

    /*
     *	Set up to talk to the map-resolver
     *
     *	Kernel puts on:
     *
     *	 IP  (SRC = my_addr, DEST = map_resolver)
     *   UDP (DEST PORT = 4342)
     *
     *	The UDP packet we build (packet) looks like:
     *
     *	 IP  (SRC = my_addr, DEST = eid)
     *	 UDP (DEST PORT = 4342)
     *	 map-request_pkt
     *
     */

    if (gettimeofday(before,NULL) == -1) {
	perror("gettimeofday");
	return(BAD);
    }

	if ((nbytes = sendto(s,
			 (const void *) packet,
			 packet_len,
			 0,
			 map_resolver_addr,
			 SA_LEN(map_resolver_addr->sa_family))) < 0) {
	perror("sendto");
	exit(BAD);
    }

    if (nbytes != packet_len) {
	fprintf(stderr,
		"send_map_request: nbytes (%d) != packet_len(%d)\n",
		nbytes, packet_len);
	exit(BAD);
    }

    return(GOOD);
}


