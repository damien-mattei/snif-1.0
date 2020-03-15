/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */


/* definition to use the packet capture library , see: pcap man page */
typedef void (*grinder_t)( struct pcap_pkthdr *, u_char *);  /* ptr to the packet processor */

typedef struct in_addr internetAddress;


/* Globals */

pcap_t *descr; /* packet descriptor */

grinder_t grinder;

/* various options */

int verb; /* verbose level
	   *  1:   verbose
	   *  0:   normal
	   * -1:   quiet
	   */


char *dev;  /* interface name */

int promisc = 1; /* promiscious mode */

int pkt_count = -1; /* number of captured packets
		     * see pcap man page for more info */

int show_eth_vend = 1; /* show ethernet vendor codes */

char * vendsrc; /* ethernet vendor code of source address */
char * venddst; /* ethernet vendor code of destination address */

int dump_link_layer = 1; /* dump network link layer info (ethernet address ,...) */

int show_ts = 1; /* show time stamp info */

int send_esc = 1; /* send escape sequence to terminal
		   * enable color and bold text
		   */

int send_nl = 0; /* send a new line beetween each dumped packet */

int text_port = 1; /* print the TCP/UDP port in text
		    * ex: 80 -> World Wide Web HTTP
		    */

int not_wkp = 0; /* by default do not print in txt
		  * ports that are not "Well Known Ports"
		  */

char * portsrc; /* source port name */

char * portdst; /* destination port name */


#ifndef HAVE_HCREATE_R

int nel = 12000; /* number of elements in hash table */

#endif


int sl = 80; /* separator line length */

#define SLBUFSIZE 250

char * sls ; /* separator line string */
 
char smotif = '_'; /* separator motif */

int sl0; /* back up value of sl */

int resolv_ip = 0; /* resolve or not IP address in hostname */

struct winsize ws; /* used by ioctl to find the terminal window size */


#ifndef HAVE_HCREATE_R

DNScache * ptrcache = NULL; /* pointer to first element
			     * of DNS cache
			     */

int maxszcache = 1024; /* number of records in cache */

#else

int maxszcache = 4096; /* number of records in cache */

time_t creatime; /* time when DNS cache was created */ 

struct hsearch_data htab_ports; /* hash table for ports */

struct hsearch_data htab_ethernet; /* hash table for ethernet */

struct hsearch_data htab_dnscache; /* hash table for DNS cache */

int nbrinc = 0; /* number of entry currently  in DNS cache */

#endif


#define DEADLINE 21600 /* time of DNS cache in second */



/*********** for get_device_info ******************************************/
enum { ADDRS_SIZE = 8 };	/* Plenty of initial broadcast addresses. */
struct in_addr bcast_arr[ADDRS_SIZE];
int numbaddrs;		/* The actual number. */
struct in_addr if_addr; /* our interface IP address */
/**************************************************************************/


