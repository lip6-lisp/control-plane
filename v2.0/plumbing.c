
#include "lib.h"
#include "pthread.h"

extern struct communication_fct cli_fct;
extern struct communication_fct udp_fct;
	
	void
plumb()
{
	/* ADD CLI front-end to the server */
	pthread_t cli_th;
	pthread_create(&cli_th, NULL, cli_fct.start_communication, NULL);

	/* ADD UDP draft-ietf-lisp-23 front-end to the server */
	pthread_t udp_th;
	pthread_create(&udp_th, NULL, udp_fct.start_communication, NULL);

	//pthread_t udp_th6;
	//pthread_create(&udp_th6, NULL, udp_fct.start_communication, "IPV6");
	
	//pthread_join(cli_th, NULL);
	pthread_join(udp_th, NULL);
	//pthread_join(udp_th6, NULL);
}
