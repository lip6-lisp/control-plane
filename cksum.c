/* 
 *	cksum.c --
 * 
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Compute the IP checksum for lig
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 09:44:57 2009
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
 *	$Header: /mnt/disk1/dmm/src/lig/RCS/cksum.c,v 1.2 2010/11/14 20:50:24 dmm Exp $
 *
 */

#include	"map_register_reply.h"

ushort ip_checksum (buf, nwords)
    unsigned short *buf;
    int            nwords; 
{
    unsigned long sum;

    for (sum = 0; nwords > 0; nwords--)
	sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}



/*    
 *
 *	Calculate the UDP checksum (calculated with the whole packet).
 *
 *	Parameters:
 *
 *	buff	-	pointer to the UDP header
 *	len	-	the UDP packet length.
 *	src	-	the IP source address (in network format).
 *	dest	-	the IP destination address (in network format).
 *
 *	Returns:        The result of the checksum
 *
 */

uint16_t udp_checksum (buff,len,src,dest)
	const void	*buff;
	unsigned int	len;
	in_addr_t	src;
	in_addr_t	dest;
{

    const	uint16_t *buf	= buff;
    uint16_t	*ip_src		= (void *)&src;
    uint16_t	*ip_dst		= (void *)&dest;
    unsigned int length		= len;
    uint32_t	sum		= 0;

    while (len > 1) {
	sum += *buf++;
	if (sum & 0x80000000)
	    sum = (sum & 0xFFFF) + (sum >> 16);
	len -= 2;
    }
 
    /* Add the padding if the packet length is odd */

    if (len & 1)
	sum += *((uint8_t *)buf);
 
    /* Add the pseudo-header */

    sum += *(ip_src++);
    sum += *ip_src;
 
    sum += *(ip_dst++);
    sum += *ip_dst;
 
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
 
    /* Add the carries */

    while (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16);
 
    /* Return the one's complement of sum */

    return ((uint16_t)(~sum));
}

uint16_t udp6_checksum (ip6,up,len)
        const struct ip6_hdr *ip6;
        const struct udphdr *up;
        unsigned int len;
{
    size_t i;
    register const u_int16_t *sp;
    uint32_t sum;
    union {
        struct {
            struct in6_addr ph_src;
            struct in6_addr ph_dst;
            u_int32_t       ph_len;
            u_int8_t        ph_zero[3];
            u_int8_t        ph_nxt;
        } ph;
        u_int16_t pa[20];
    } phu;

    /* pseudo-header */
    memset(&phu, 0, sizeof(phu));
    phu.ph.ph_src = ip6->ip6_src;
    phu.ph.ph_dst = ip6->ip6_dst;
    phu.ph.ph_len = htonl(len);
    phu.ph.ph_nxt = IPPROTO_UDP;

    sum = 0;
    for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
        sum += phu.pa[i];

    sp = (const u_int16_t *)up;

    for (i = 0; i < (len & ~1); i += 2)
        sum += *sp++;

    if (len & 1)
        sum += htons((*(const u_int8_t *)sp) << 8);

    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;

    return (sum);
}
