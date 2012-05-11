#!/bin/sh
. /etc/rc.subr

name="lisp"
start_cmd="${name}_start"
stop_cmd=":"

lisp_start()
{
	/sbin/lisp_register_reply &
}

load_rc_config $name
run_rc_command "$1"
