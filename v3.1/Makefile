SRC      = 
INC	 = 
OBJ	 = $(SRC:%.c=%.o)
EXE      = opencp

#
#
#	misc junk
#
RCS      = RCS
MISC     = Makefile README 

#
#	compile/load options
#

CC	 = gcc
CFLAGS   = -O2 -L/usr/local/lib/ -lexpat -L. -DHAVE_IPV6 -Wall -lpthread
LDLIBS   = 
LDFLAGS  = 
#
#
LISP_H = /usr/src/sys/net/lisp/lisp.h
${EXE}: 
	@if test -f $(LISP_H); then \
	${CC}    radix/*_*.c server.c  db.c udp.c hmac/*.c cli.c list/list.c thr_pool/*.c parser.c plumbing.c -D OPENLISP plugin_openlisp.c -o ${EXE} -g  -O2  -I/usr/local/include  -L/usr/local/lib -lexpat -L. -DHAVE_IPV6 -Wall -lpthread ; \
	else\
	${CC}  radix/*_*.c server.c  db.c udp.c hmac/*.c cli.c list/list.c thr_pool/*.c parser.c plumbing.c plugin_openlisp.c  -o ${EXE} -g  -O2  -I/usr/local/include  -L/usr/local/lib -lexpat -L. -DHAVE_IPV6 -Wall -lpthread  ;\
	fi;

with_openlisp: 
	${CC}    radix/*_*.c server.c  db.c udp.c hmac/*.c cli.c list/list.c thr_pool/*.c parser.c plumbing.c -D ${OPENLISP} plugin_openlisp.c -o ${EXE} -g  -O2  -I/usr/local/include  -L/usr/local/lib -lexpat -L. -DHAVE_IPV6 -Wall -lpthread 

install:
	/bin/cp ${EXE} /sbin/
	/bin/chmod a+x /sbin/${EXE}
	/bin/cp opencp_service /etc/rc.d/
	/bin/chmod a+x /etc/rc.d/opencp_service
	/bin/cp opencp.conf opencp_xtr.xml opencp_ms.xml opencp_mr.xml opencp_node.xml opencp_rtr.xml /etc/ 

clean:
	/bin/rm -f ${OBJ} ${EXE} ${MANOUT} core a.out Make.log Make.err *~
