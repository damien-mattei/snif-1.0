/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@orange.fr>

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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */


/* needed for TCP, you know TCP rely on IP */
#include "ip.h" 

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "tcp.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/*
 * Function: DecodeTCP(u_int8_t *, const u_int32_t,IPHdr *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to th IP header
 *
 * Returns: void function
 */
void DecodeTCP(u_int8_t * pkt, const u_int32_t len,IPHdr * iptr)
{

  TCPHdr * tcptr;

  u_int32_t hlen;            /* TCP header length */
  u_short csum;              /* checksum */

  struct pseudoheader       /* pseudo header for TCP checksum calculations */
  {
    u_int32_t sip, dip;   /* IP addr */
    u_int8_t  zero;       /* checksum placeholder */
    u_int8_t  protocol;   /* protocol number */
    u_int16_t tcplen;     /* tcp packet length */
  };
  
  struct pseudoheader ph;    /* pseudo header declaration */
  u_int32_t tcp_options_len;
  u_int16_t sp;       /* source port TCP */
  u_int16_t dp;       /* dest port TCP */
  u_int8_t *data;     /* packet payload pointer */
  u_int16_t dsize;        /* packet payload size */

  if (send_esc) {
    SETCOLOR(TCP_COLOR);
  }

  printf("TCP ");
  
  if(len < 20)
    {
      printf("TCP packet (len = %d) cannot contain "
	     "20 byte header\n", len);
       
      return;
    }

  /* lay TCP on top of the data cause there is enough of it! */
  tcptr = (TCPHdr *) pkt;

  /* multiply the payload offset value by 4 */
  hlen = TCP_OFFSET(tcptr) << 2;

  if (verb >0) {
    printf("TCP th_off is %d, passed len is %lu\n", 
	   TCP_OFFSET(tcptr), (unsigned long)len);
  }

    if(hlen < 20)
    {
        printf("TCP Data Offset (%d) < hlen (%d) \n",
	       TCP_OFFSET(tcptr), hlen);

        return;
    }

    if(hlen > len)
    {
      printf("TCP Data Offset(%d) < longer than payload(%d)!\n",
	     TCP_OFFSET(tcptr) << 2, len);
      
      return;
    }

      
    /* setup the pseudo header for checksum calculation */
    ph.sip = (u_int32_t)(iptr->ip_src.s_addr); /* unsigned long int */
    ph.dip = (u_int32_t)(iptr->ip_dst.s_addr);
    ph.zero = 0;
    ph.protocol = iptr->ip_proto;
    ph.tcplen = htons((u_short)len);

    /* if we're being "stateless" we probably don't care about the TCP 
     * checksum, but it's not bad to keep around for shits and giggles */
    /* calculate the checksum */
    csum = in_chksum_tcp((u_int16_t *)&ph, (u_int16_t *)(tcptr), len);
        
    if(csum)
      {
      
	printf("Bad TCP checksum (0x%x versus 0x%x)\n", csum,
	       ntohs(tcptr->th_sum));
      }
    else
      {
	if (verb >0) {
	  printf("TCP Checksum: OK\n");
	}
      }
    

    /* if options are present, decode them */
    tcp_options_len = hlen - 20;

    if(tcp_options_len > 0)
    {
        printf("%lu bytes of tcp options....\n", 
                    (unsigned long)(tcp_options_len));

    }
    
    /* translate source and destination port */
    sp = ntohs(tcptr->th_sport);
    dp = ntohs(tcptr->th_dport);

    PrintPorts(sp,dp,TCP_COLOR);
   

    /* set the data pointer and size */
    data = (u_int8_t *) (pkt + hlen);

    if(hlen < len)
    {
        dsize = (u_short)(len - hlen);
    }
    else
    {
        dsize = 0;
    }
}
