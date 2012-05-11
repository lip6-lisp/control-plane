# 
#	get_parameters_reg.c --
# 
#	get_parameters_reg -- OpenLISP control-plane 
#
#	Copyright (c) 2012 LIP6 <http://www.lisp.ipv6.lip6.fr>
#	Base on <Lig code> copyright by David Meyer <dmm@1-4-5.net>
#	All rights reserved.
#
#	LIP6
#	http://www.lisp.ipv6.lip6.fr
#	Thu Apr  12 00:00:00
#
#Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     o Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     o Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     o Neither the name of the University nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#
#

SRC      = map_register_reply.c hmac_sha.c sha.c  send_map_register.c send_map_reply.c get_parameters_reg.c 
INC	 = map_register_reply.h  sha.h
OBJ	 = $(SRC:%.c=%.o)
EXE      = lisp_register_reply
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
CFLAGS   = -Wall -Wno-implicit-function-declaration
LDLIBS   = 
LDFLAGS  = 
#
#
${EXE}: ${OBJ} ${INC} Makefile
	$(CC) -o $@ ${OBJ} $(LDLIBS) $(LDFLAGS)-lm -pthread

${MAN}: ${MANSRC}
	groff -t -e -mandoc -Tascii ${MANSRC} | col -bx > ${MANOUT}

install:
	/bin/cp ${EXE} /sbin/
	/bin/chmod a+x /sbin/${EXE}
	/bin/cp lisp /etc/rc.d/
	/bin/chmod a+x /etc/rc.d/lisp
	/bin/cp register_parameters.txt /etc/ 
clean:
	/bin/rm -f ${OBJ} ${EXE} ${MANOUT} core a.out Make.log Make.err *~
