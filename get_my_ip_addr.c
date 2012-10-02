/*
 *	get_my_ip_addr.c
 *
 *	Copyright (c) 2010, David Meyer <dmm@1-4-5.net>
 *	All rights reserved.
 *
 *	Basically, loop through the interfaces
 *	and take the first non-loopback interface.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Mon Jul  6 09:45:50 2009
 *
 *	IPv6 support added by Lorand Jakab <lj@icanhas.net>
 *	Mon Aug 23 15:26:51 2010 +0200
 *
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
 *	$Header: /mnt/disk1/dmm/src/lig/RCS/get_my_ip_addr.c,v 1.1 2010/11/14 20:43:58 dmm Exp $
 *
 */


#include	"lig.h"
#include	"lig-external.h"


/*
 *	usable_addr
 *
 *	Basically, don't use the a looback or EID as 
 *	a source address
 *
 */

unsigned int usable_addr(addr)
     struct sockaddr	*addr;
{
    char buf[NI_MAXHOST];
    int e;

    if ((e = getnameinfo(addr,SA_LEN(addr->sa_family),
		    buf,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) != 0) {
	fprintf(stderr,"getnameinfo: %s\n",gai_strerror(e));
	exit(BAD);
    }

    if (disallow_eid)			/* don't allow an EID as the source in the innner IP header */
	return(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&
		strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN) &&
		strncmp(V4EID,buf,V4EID_PREFIX_LEN) &&
		strncmp(V6EID,buf,V6EID_PREFIX_LEN));
    else
	return(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&
		strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN));
}

/*
 *	get_my_ip_addr
 *
 *	Get a usable address for the source in the inner header in 
 *	the EMR we're about to send.
 *
 *	Probably not POSIX
 *
 */

int get_my_ip_addr(afi,my_addr)
     int		    afi;
     struct     sockaddr    *my_addr;
{

    struct	ifaddrs		*ifaddr;
    struct	ifaddrs		*ifa;

    if (getifaddrs(&ifaddr) == -1) {
	perror("getifaddrs");
	exit(BAD);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr == NULL)
	    continue;
	if (ifa->ifa_addr->sa_family != afi )
	    continue;
	if (usable_addr(ifa->ifa_addr)) {
	    memcpy((void *) my_addr,ifa->ifa_addr,SA_LEN(afi));
	    freeifaddrs(ifaddr);
	    return 0;
	}
    }

    freeifaddrs(ifaddr);
    return -1;
}


