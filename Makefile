SRC      != ls *.c */*.c
INC	 = 
OBJ	 = ${SRC:.c=.o}
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

CFLAGS   = -g -O2 -DHAVE_IPV6 -Wall -I/usr/local/include
LDLIBS   = 
LDFLAGS  = -L/usr/local/lib/ -lpthread -lexpat
#
#
LISP_H = /usr/src/sys/net/lisp/lisp.h

.if exists( $(LISP_H))
  CFLAGS += -DOPENLISP
.endif

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $>

safe-install: $(EXE)
	/usr/bin/install -m a+x $(EXE) /sbin/
	/usr/bin/install -m a+x opencp_service /etc/rc.d/opencp

install: safe-install
	/usr/bin/install -b opencp.conf opencp_xtr.xml opencp_ms.xml opencp_mr.xml opencp_ddtnode.xml opencp_rtr.xml /etc/

clean:
	/bin/rm -f ${OBJ} ${EXE} ${MANOUT} *.core a.out Make.log Make.err *~

.SUFFIXES: .c .o

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
