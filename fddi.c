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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <search.h> /* added for hash tables */


#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/if_ether.h> /* includes net/ethernet.h */

#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h> /* needed for ether_ntoa */
#endif

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "fddi.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */







/*
 * Function: DecodeFDDIPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode FDDI (Fiber Distributed Data Interface) Packet
 *
 * Arguments: 
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* length of the packet */
    u_int32_t cap_len;      /* capture length variable */
  
    u_int32_t dataoff = sizeof(FDDIHdr);

    FDDIHdr * fddi_hdr_ptr;

    pkt_len = pkthdr->len;
    cap_len = pkthdr->caplen;

    if (dump_link_layer) { 

      printf("FDDI ");

    }

    if(BUFSIZ < pkt_len)
    {
        pkt_len = cap_len;
    }

 
    if(pkthdr->caplen < dataoff)
    {
      printf("Captured data length < FDDI header length! (%d < %d bytes)\n", pkthdr->caplen, dataoff);
      return;
    }

    /* let's put this in as the fddi header structure */
    fddi_hdr_ptr = (FDDIHdr *) pkt;

    /* printing FDDI source & destination address */
   
    if (dump_link_layer) { 

      if (send_esc) {

	SETATTRIB( BRIGHT );

	printf( "%X:%X:%X:%X:%X:%X", fddi_hdr_ptr->saddr[0],
		fddi_hdr_ptr->saddr[1], fddi_hdr_ptr->saddr[2], fddi_hdr_ptr->saddr[3],
		fddi_hdr_ptr->saddr[4], fddi_hdr_ptr->saddr[5]);

	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR );
	printf(" > ");
	SETATTRIB( BRIGHT );

	printf( "%X:%X:%X:%X:%X:%X\n", fddi_hdr_ptr->daddr[0],
		fddi_hdr_ptr->daddr[1], fddi_hdr_ptr->daddr[2], fddi_hdr_ptr->daddr[3],
		fddi_hdr_ptr->daddr[4], fddi_hdr_ptr->daddr[5]);
    
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR);

      }
      else {

	printf( "%X:%X:%X:%X:%X:%X", fddi_hdr_ptr->saddr[0],
		fddi_hdr_ptr->saddr[1], fddi_hdr_ptr->saddr[2], fddi_hdr_ptr->saddr[3],
		fddi_hdr_ptr->saddr[4], fddi_hdr_ptr->saddr[5]);

	printf(" > ");

	printf( "%X:%X:%X:%X:%X:%X\n", fddi_hdr_ptr->daddr[0],
		fddi_hdr_ptr->daddr[1], fddi_hdr_ptr->daddr[2], fddi_hdr_ptr->daddr[3],
		fddi_hdr_ptr->daddr[4], fddi_hdr_ptr->daddr[5]);
    
      }

    }

    DecodeLLC(pkt + sizeof(FDDIHdr), cap_len - sizeof(FDDIHdr),pkthdr);
   
    return;
}
