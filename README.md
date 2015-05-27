
# Overview
The OpenLISP control plane (opencp) repository https://github.com/lip6-lisp/control-plane hosts an open source control plane for LISP (the Location/Idenfitier Separation Protocol), a protocol designed at the IETF.
It is designed to work on both linux and BSD platforms.

# For more info
http://www.lisp.ipv6.lip6.fr


# How to install ?


Require: expat library (need expat.h expat_external.h in /usr/local/include/)
	Installation of the expat library using ports collection (on FreeBSD) or packaging tool (on Linux).
	
	On FreeBSD:
		#cd /usr/ports/textproc/expat2
		#make clean install
	
	On Linux:(example for Ubuntu)
		#apt-get install libexpat1-dev

1. Make sure that you have the gcc compiler. 
If you use other compiler, modify the Makefile to assign CC variable to your compiler.
(Note: default FreeBSD 10 use `clang` instead `gcc`)
	CC = gcc  --> CC = your_complier

2. From source code directory, run 'make'. This will create the binary file 'opencp'.

3. From source code directory, run 'make install' to install the service script to /etc/rc.d/. 
It also copies the main configuration file (opencp.conf) and five other specific configuration files: 
 'opencp_xtr.xml, opencp_ms.xml, opencp_mr.xml, opencp_node.xml, opencp_rtr.xml' to /etc/. Please edit 
the configuration files to customize it before continuing. By default: opencp_mr-sample-configure-of-ddt-root.xml file 
contains an example configuration for the DDT root node function; opencp_xtr-sample-configure-of-lisp-te.xml file contains an example  configuration of the RTR node function; opencp_xtr-sample-configure-multi-mapping-system.xml contains an example  
configuration for the xTR node function. 

	a.  The main configuration (opencp.conf) allows you to indicate what  
control-plane function to enable. It also points to the specific xml configuration files for each functions.

	b.  The xTR configuration file (opencp_xtr.xml) includes:
	+ <mapserver> section: list of MSs the xTR registers to. 
	Each MS needs an authentication key. 
	+ <mapresolve> section: list of MRs the xTR can send map-requests to.
	+ One or more <eid> sections: each section gives the information of one EID IP prefix to register.

	c. Map server configuration file (opencp_ms.xml) includes:
	+ <geid> section: IP prefixes the map-server allows ETR to register to. The IP ranges must not overlap.
	+ One or more <site> sections: each section includes the information for one site:
		+ site name.
		+ key for map-register messages. NB: the key is case sensitive and must not include spaces.
		+ EID IP prefixes the site can register.

	d. DDT node and MR configuration file (opencp_mr.xml) includes:
	+ <geid> section: the IP prefix(es) the node is delegated. The IP ranges must not overlap. 
	NB: if the node is a DDT root, then it is here configured as being delegated for 0.0.0.0/0 (IPv4) and 0::/0 (IPv6).
	+ One or more <eid> sections: each section contains the information for one delegated prefix. 
	Special <eid> sections with prefix equal 0.0.0.0/0 or 0::/0 are for DDT root nodes.

	e. RTR configuration file (pencp_rtr.xml) includes:
	+ <mapresolve> section: list of MRs the RTR can send map-requests.
	+ One or more <eid> sections: each section includes the information for EID-prefix pass over RTR.
	
4. To start the program the first time, use 'service opencp start' or '/etc/rc.d/opencp_service start' command or run it manually by ./opencp -f [<path_to_opencp.conf>]

5. To let the program autostart when rebooting, edit the /etc/rc.conf adding the following line:
	opencp_enable="YES"

6. When running manually, opencp shows the log information to terminal. When run as a daemon (auto start when rebooting or by service command), opencp logs to `/var/log/opencp.log`. In FreeBSD, to rotate the log file, edit the /etc/newsyslog.conf and add the following line (opencp.log will be archived each time it gets over 1000KB):
	/var/log/opencp.log                     600  7     1000 *     JC    /var/run/opencp.pid  30

# Contact

Use github tracking system in case you encounter a bug.
Pull requests are welcome and should also go through the github system.





Reference
---------
DC. Phung, S. Secci, D. Saucez, L. Iannone, "The OpenLISP Control Plane Architecture", IEEE Network Magazine, 2014. Url: http://www-phare.lip6.fr/~secci/papers/PhSeSaIa-NETMAG14.pdf

Please acknowledge the paper above when using the code.
