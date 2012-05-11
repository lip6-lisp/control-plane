/* 
 *	map_register_reply.c --
 * 
 *	map_register_reply -- OpenLISP control-plane 
 *
 *	Copyright (c) 2012 LIP6 <http://www.lisp.ipv6.lip6.fr>
 *	Base on <Lig code> copyright by David Meyer <dmm@1-4-5.net>
 *	All rights reserved.
 *
 *	LIP6
 *	http://www.lisp.ipv6.lip6.fr
 *
 *Redistribution and use in source and binary forms, with or without
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
 */


#include	"map_register_reply.h"
#include    <pthread.h>


/*
 *	globals
 */
void * mapreply(void *);
void * send_map_register(void *threadarg);
void make_nonce(unsigned int *, unsigned int *);
void hexout(unsigned char *, int );

int main(int argc, char *argv[])
{
    
    struct map_db params;
	//getparameters_reg(&params, 0);

	int		s,s6;	
	struct	map_register_data map_register_data;
	struct	map_reply_data map_reply_data;
	struct	map_reply_data map_reply_data6;

	struct sockaddr_storage my_addr, my_addr6;
	pthread_t thread[3];
  	
  	struct addrinfo	    hints;
    struct addrinfo	    *res;
    struct protoent	    *proto;
  
	make_nonce(&map_register_data.nonce0, &map_register_data.nonce1);

    int i	= 0;		/* generic counter */
    int rc ,rc1, rc2; //Used for returning the handle for thread creation
        
    emr_inner_src_port	= 0;		
    char  emr_inner_src_port_str[NI_MAXSERV];

    int e		= 0;
    
    //Prepare sockets 
    if ((proto = getprotobyname("UDP")) == NULL) {
		perror ("getprotobyname");
		exit(BAD);
    }

    if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
		perror("SOCK_DGRAM (s)");
		exit(1);
    }

    if ((s6 = socket(AF_INET6,SOCK_DGRAM,proto->p_proto)) < 0) {
		perror("SOCK_DGRAM (s)");
		exit(1);
    }

	
	//Get source ip address, save in my_addr
   		
	//Port 4342 for LISP map register  and map reply	
	emr_inner_src_port = LISP_CONTROL_PORT;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	sprintf(emr_inner_src_port_str, "%d", emr_inner_src_port);

	if ((e = getaddrinfo(NULL, emr_inner_src_port_str, &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}
	//Bind the socket to 4342 and the internet interface 
	if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		exit(BAD);
	}

	map_register_data.register_socket=s;
	map_reply_data.sk=s;
	map_reply_data6.sk=s;
	freeaddrinfo(res);
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET6;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	if ((e = getaddrinfo(NULL, emr_inner_src_port_str, &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}
	//Bind the socket to 4342 and the internet interface 
	if (bind(s6, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		exit(BAD);
	}

	map_register_data.register_socket6=s6;
	map_reply_data.sk6=s6;
	map_reply_data6.sk6=s6;

	freeaddrinfo(res);

	//Creating two thread, one to send register message and one to reply with request mapping
	map_reply_data.l_sk=s;
	map_reply_data6.l_sk=s6;

	//Map reply thread
	rc1=pthread_create( &(thread[1]), NULL, mapreply,(void *)&map_reply_data );
	if (rc1){
	   printf("ERROR; return code from pthread_create() is %d\n", rc);
	  exit(-1);
	} 
	
	rc2=pthread_create( &(thread[2]), NULL, mapreply,(void *)&map_reply_data6 );
	if (rc2){
	   printf("ERROR; return code from pthread_create() is %d\n", rc);
	  exit(-1);
	}
    //Map register thread

	while(1){    

		rc=pthread_create( &(thread[0]), NULL, send_map_register, (void *)&map_register_data );
		if (rc){
			printf("ERROR; return code from pthread_create() is %d\n", rc);
	        exit(-1);
		}
		pthread_join(thread[0], NULL);
		
		sleep (45); //send map-register every X seconds
	}
    
       
	pthread_join(thread[1], NULL);
	pthread_join(thread[2], NULL);
    printf ("Main: Waited on thread %d.\n", i);
  
	
	pthread_exit(NULL);
	exit(GOOD);
}


//Debug functions
//Print map request message fied by fied

void print_map_request(packet, length)
    struct map_request_pkt *packet;
	int length;
{
    printf("\nMap-Request Packet\n");
    printf("==========================\n");
	hexout((unsigned char *)packet,length);
	struct in_addr *tmp;
	struct in6_addr *tmp6;
    struct map_request_pkt *map_request = packet;
	if (((struct lisp_control_pkt *) packet)->type == LISP_ENCAP_CONTROL_TYPE)//Map encapsulated package
	{
		/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |                       IPv4 or IPv6 Header                     |
		OH |                      (uses RLOC addresses)                    |
		 \ |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |       Source Port = xxxx      |       Dest Port = 4342        |
		UDP+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 \ |           UDP Length          |        UDP Checksum           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		LH |Type=8 |S|                  Reserved                           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |                       IPv4 or IPv6 Header                     |
		IH |                  (uses RLOC or EID addresses)                 |
		 \ |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |       Source Port = xxxx      |       Dest Port = yyyy        |
		UDP+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 \ |           UDP Length          |        UDP Checksum           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		LCM|                      LISP Control Message                     |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		*/
		struct ip			*iph;
		struct ip6_hdr		*iph6;
		struct udphdr		*udph;

		char ip_s[INET6_ADDRSTRLEN];
		char ip_d[INET6_ADDRSTRLEN];
		int port_s;
		int port_d;

		//print source and destionation of Inner Header
		iph = (struct ip *)  CO(map_request,  sizeof(struct lisp_control_pkt));

		int ipversion = iph->ip_v;
		if (ipversion == 4) {
			iph = (struct ip *)  CO(map_request,  sizeof(struct lisp_control_pkt));
			inet_ntop(AF_INET, &(iph->ip_src), ip_s, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(iph->ip_dst), ip_d, INET_ADDRSTRLEN);
		}
		else{
			iph6 = (struct ip6_hdr *)  CO(map_request,  sizeof(struct lisp_control_pkt));
			inet_ntop(AF_INET6, &(iph6->ip6_src), ip_s, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(iph6->ip6_dst), ip_d, INET6_ADDRSTRLEN);
		}
		
		udph		= (struct udphdr *) CO(map_request, sizeof(struct lisp_control_pkt) + ((ipversion == 4)? sizeof(struct ip): sizeof(struct ip6_hdr)) );
		
		port_s = ntohs(udph->uh_sport);
		port_d = ntohs(udph->uh_dport);
		
		map_request = (struct map_request_pkt *)  CO(udph, sizeof(struct udphdr));
		
		printf("**** Encapsulated Control Message****\n");
	    printf("SourceIP \t\t= %s\n",ip_s);
	    printf("DestIP \t\t= %s\n",ip_d);
	    printf("SourcePort \t\t= %d\n",port_s);
	    printf("DestPort \t\t= %d\n",port_d);
		printf("\n");

	}
    printf("lisp_type\t\t= %d\n",map_request->lisp_type);
	printf("auth_bit\t\t= 0x%x\n", map_request->auth_bit);
    printf("map_data_present\t= %d\n",map_request->map_data_present);
    printf("rloc_probet\t\t= %d\n", map_request->rloc_probe);
	printf("smr_bit\t\t\t= %d\n", map_request->smr_bit);
	printf("pitr_bit\t\t\t= %d\n", map_request->pitr_bit);
	printf("smr_invoked\t\t\t= %d\n", map_request->smr_invoked);

    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n",
	   ntohl(map_request->lisp_nonce0), 
	   ntohl(map_request->lisp_nonce1)); 
    printf("irc record_count\t\t= %d\n",map_request->irc);
	printf("record_count\t\t= %d\n",map_request->record_count);
    printf("source_eid_afi\t\t= %d\n",
	   ntohs(map_request->source_eid_afi));
	
	int i;
	void *ptr = CO(map_request, sizeof(struct map_request_pkt) - 2  );
	char ip6[INET6_ADDRSTRLEN]; 

	//Print EID AFI
	if (ntohs(map_request->source_eid_afi) == LISP_AFI_IP ) {
		tmp = (struct in_addr *)&map_request->itr_afi;
		ptr = CO(ptr, sizeof(struct in_addr));
		printf("itr afi - Source EID address\t= %s\n", inet_ntoa(*tmp));
	}
	else if (ntohs(map_request->source_eid_afi) == LISP_AFI_IPV6) {
		tmp6 = (struct in6_addr *)&map_request->itr_afi;
		inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
		printf("itr afi - Source EID address\t= %s\n", ip6);
		ptr = CO(ptr, sizeof(struct in6_addr));
	}
	
	//Print all ITR AFI,must there is at lease 1 ITR AFI
	for (i = 0; i<=map_request->irc; i++ ) {
	
		if (ntohs(*((ushort*)ptr)) == LISP_AFI_IP ) {
			tmp = (struct in_addr *) CO(ptr,2);
			printf("ITR %d: AFI = %d  ITR RLOC = %s\n",i,ntohs(*((ushort*)ptr)), inet_ntoa(*tmp));
			ptr = CO(ptr, sizeof(struct in_addr)+2);
		}
		else if (ntohs(*((ushort*)ptr)) == LISP_AFI_IPV6 ) {
			tmp6 = (struct in6_addr *)CO(ptr,2);
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("ITR %d: AFI = %d  ITR RLOC = %s\n",i,ntohs(*((ushort*)ptr)), ip6);
			ptr = CO(ptr, sizeof(struct in6_addr)+2);
		}
	}

	//Print all EID prefix
	struct	map_request_eid *map_request_eid;
	
	for (i = 0; i<  map_request->record_count; i++ ) {

		map_request_eid = (struct map_request_eid *) ptr;
	    printf("eid_mask_len\t\t= %d\n",map_request_eid->eid_mask_len);
		ptr = CO(ptr,2);
		if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)map_request_eid->eid_prefix;
			printf("EID %d: AFI = %d  EID prefix = %s\n",i,ntohs(map_request_eid->eid_prefix_afi), inet_ntoa(*tmp));
			ptr = CO(ptr, sizeof(struct in_addr)+2);
		}
		else if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IPV6 ) {
			tmp6 = (struct in6_addr *)map_request_eid->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("EID %d: AFI = %d   EID prefix = %s\n",i,ntohs(map_request_eid->eid_prefix_afi), ip6);
			ptr = CO(ptr, sizeof(struct in6_addr)+2);
		}
	}
	printf("==========================\n");

}








//Print map reply fied by fied

void print_map_reply(map_reply, length)
    struct map_reply_pkt *map_reply;
	int length;
{
    printf("\nMap-Reply Packet\n");
    printf("==========================\n");
	hexout((unsigned char *)map_reply,length);


    printf("lisp_type\t\t= %d\n",map_reply->lisp_type);
	printf("rloc_probe\t\t= %d\n", map_reply->rloc_probe);
    printf("echo_nonce_capable\t= %d\n",map_reply->echo_nonce_capable);
    printf("security_bit\t\t= %d\n", map_reply->security_bit);
	printf("record_count\t\t\t= %d\n", map_reply->record_count);
    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n", ntohl(map_reply->lisp_nonce0),  ntohl(map_reply->lisp_nonce1)); 

    struct in_addr *tmp;
	struct in6_addr *tmp6;
	int i,j;
	void *ptr = CO(map_reply, sizeof(struct map_reply_pkt)  );
	char ip6[INET6_ADDRSTRLEN]; 
	struct map_reply_eidtype * map_reply_eidtype;
	struct map_reply_loctype * map_reply_loctype;

	//print all record
	for (i = 0; i < map_reply->record_count ; i++ ) {
		map_reply_eidtype = (struct map_reply_eidtype *) ptr;
		printf("#Recodr%d\n",i);
	    printf("-------------\n");
		printf("record_ttl\t\t\t= %d\n", ntohl(map_reply_eidtype->record_ttl));
		printf("loc_count\t\t\t= %d\n", map_reply_eidtype->loc_count);
		printf("eid_mask_len\t\t\t= %d\n", map_reply_eidtype->eid_mask_len);
		printf("action\t\t\t= %d\n", map_reply_eidtype->action);
		printf("auth_bit\t\t\t= 0x%x\n", map_reply_eidtype->auth_bit);
	    printf("lisp_map_version\t\t= 0x%04x-0x%08x\n", map_reply_eidtype->lisp_map_version1,map_reply_eidtype->lisp_map_version2);
		printf("eid_afi\t\t\t= %d\n", ntohs(map_reply_eidtype->eid_afi));
		ptr = CO(ptr, sizeof(struct map_reply_eidtype));
		if (ntohs(map_reply_eidtype->eid_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)&map_reply_eidtype->eid_prefix;
			ptr = CO(ptr, sizeof(struct in_addr));
			printf("eid_prefix\t= %s\n", inet_ntoa(*tmp));
		}
		else if (ntohs(map_reply_eidtype->eid_afi) == LISP_AFI_IPV6) {
			tmp6 = (struct in6_addr *)&map_reply_eidtype->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("eid_prefix\t= %s\n", ip6);
			ptr = CO(ptr, sizeof(struct in6_addr));
		}
		//print rlocs
		for (j = 0; j < map_reply_eidtype->loc_count ; j ++ ) {
			map_reply_loctype = (struct map_reply_loctype *) ptr;
			printf("RLOC %d:\t\t\t", j);
			printf("priority %d\t", map_reply_loctype->priority);
			printf("weight %d\t", map_reply_loctype->weight);
			printf("mpriority %d\t", map_reply_loctype->mpriority);
			printf("mweight %d\t", map_reply_loctype->mweight);
			printf("rloc_local %d\t", map_reply_loctype->rloc_local);
			printf("rloc_prob %d\t", map_reply_loctype->rloc_prob);
			printf("reach_bit %d\t", map_reply_loctype->reach_bit);
			printf("loc_afi %d\t", ntohs(map_reply_loctype->loc_afi));
			ptr = CO(ptr,sizeof(struct map_reply_loctype));
			if (ntohs(map_reply_loctype->loc_afi) == LISP_AFI_IP ) {
				tmp = (struct in_addr *)&map_reply_loctype->locator;
				ptr = CO(ptr, sizeof(struct in_addr));
				printf("locator\t= %s\n", inet_ntoa(*tmp));
			}
			else if (ntohs(map_reply_loctype->loc_afi) == LISP_AFI_IPV6) {
				tmp6 = (struct in6_addr *)&map_reply_loctype->locator;
				inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
				printf("locator\t= %s\n", ip6);
				ptr = CO(ptr, sizeof(struct in6_addr));
			}

		}
	    printf("-------------\n");
	}
	
	printf("==========================\n");
}






//Print map register fied by fied

void print_map_register(map_register_ptr,length)
    void *map_register_ptr;
	int length;
{
	struct map_register_pkt * map_register;
	map_register = (struct map_register_pkt *)map_register_ptr;

	printf("\nMap-Register Packet\n");
    printf("==========================\n");
	hexout(map_register_ptr,length);

    printf("lisp_type\t\t= %d\n",map_register->lisp_type);
	printf("rloc_probe\t\t= %d\n", map_register->rloc_probe);
    printf("want_map_notify\t= %d\n",map_register->want_map_notify);
    printf("record_count\t\t= %d\n", map_register->record_count);
    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n", ntohl(map_register->lisp_nonce0),  ntohl(map_register->lisp_nonce1)); 
	printf("key_id\t\t\t= %d\n", ntohs(map_register->key_id));
	printf("key_len\t\t\t= %d\n", ntohs(map_register->key_len));
	printf("auth_data\t\t\t=");
	hexout(map_register->auth_data,ntohs(map_register->key_len));

    struct in_addr *tmp;
	struct in6_addr *tmp6;
	int i,j;
	void *ptr = CO(map_register, sizeof(struct map_register_pkt)  );
	char ip6[INET6_ADDRSTRLEN]; 
	struct lisp_map_register_eidtype * map_register_eidtype;
	struct lisp_map_register_loctype * map_register_loctype;

	//print all record
	for (i = 0; i < map_register->record_count ; i++ ) {
		map_register_eidtype = (struct lisp_map_register_eidtype *) ptr;
		printf("#Recodr%d\n",i);
	    printf("-------------\n");
		printf("record_ttl\t\t\t= %d\n", ntohl(map_register_eidtype->record_ttl));
		printf("loc_count\t\t\t= %d\n", map_register_eidtype->loc_count);
		printf("eid_mask_len\t\t\t= %d\n", map_register_eidtype->eid_mask_len);
		printf("action\t\t\t= %d\n", map_register_eidtype->action);
		printf("auth_bit\t\t\t= 0x%x\n", map_register_eidtype->auth_bit);
	    printf("lisp_map_version\t\t= 0x%04x-0x%08x\n", map_register_eidtype->lisp_map_version1,map_register_eidtype->lisp_map_version2);
		printf("eid_afi\t\t\t= %d\n", ntohs(map_register_eidtype->eid_afi));
		ptr = CO(ptr, sizeof(struct lisp_map_register_eidtype));
		if (ntohs(map_register_eidtype->eid_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)&map_register_eidtype->eid_prefix;
			ptr = CO(ptr, sizeof(struct in_addr));
			printf("eid_prefix\t= %s\n", inet_ntoa(*tmp));
		}
		else if (ntohs(map_register_eidtype->eid_afi) == LISP_AFI_IPV6) {
			tmp6 = (struct in6_addr *)&map_register_eidtype->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("eid_prefix\t= %s\n", ip6);
			ptr = CO(ptr, sizeof(struct in6_addr));
		}
		//print rlocs
		for (j = 0; j < map_register_eidtype->loc_count ; j ++ ) {
			map_register_loctype = (struct lisp_map_register_loctype *) ptr;

			printf("RLOC %d:\t\t\t", j);
			//printf("addr priority %p\t", &map_register_loctype->priority);
			printf("priority %d\t", map_register_loctype->priority);

			printf("weight %d\t", map_register_loctype->weight);
			printf("mpriority %d\t", map_register_loctype->mpriority);
			printf("mweight %d\t", map_register_loctype->mweight);
			printf("rloc_local %d\t", map_register_loctype->rloc_local);
			printf("rloc_probe %d\t", map_register_loctype->rloc_probe);
			printf("reach_bit %d\t", map_register_loctype->reach_bit);
			printf("loc_afi %d\t", ntohs(map_register_loctype->loc_afi));
			ptr = CO(ptr,sizeof(struct lisp_map_register_loctype));
			if (ntohs(map_register_loctype->loc_afi) == LISP_AFI_IP ) {
				tmp = (struct in_addr *)&map_register_loctype->locator;
				ptr = CO(ptr, sizeof(struct in_addr));
				printf("locator\t= %s\n", inet_ntoa(*tmp));
			}
			else if (ntohs(map_register_loctype->loc_afi) == LISP_AFI_IPV6) {
				tmp6 = (struct in6_addr *)&map_register_loctype->locator;
				inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
				printf("locator\t= %s\n", ip6);
				ptr = CO(ptr, sizeof(struct in6_addr));
			}

		}
	    printf("-------------\n");
	}
	
	printf("==========================\n");
}


//Dump as hexa
void hexout(unsigned char *data, int datalen) {

	printf("0x");
	while (datalen-- > 0)
		printf("%02x",(unsigned char)*data++);
	printf("\n");
}


//Create nonce by ramdom 

void make_nonce(nonce0,nonce1)
     unsigned int	*nonce0;
     unsigned int	*nonce1;
{
    *nonce0 = random()^random();
    *nonce1 = random()^time(NULL);
}
