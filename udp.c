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


/* needed for UDP, you know UDP rely on IP */
#include "ip.h" 

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "udp.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */


/*
 * Function: DecodeUDP(u_int8_t *, const u_int32_t, IPHdr *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to the IP header
 *
 * Returns: void function
 */
void DecodeUDP(u_int8_t * pkt, const u_int32_t len,IPHdr * iptr)
{

  
    UDPHdr * udptr;

    u_short csum;
    u_int16_t uhlen;

    struct pseudoheader  /* pseudo header required for checksum calculations */
    {
        u_int32_t sip, dip;
        u_int8_t  zero;
        u_int8_t  protocol;
        u_int16_t udplen;
    };

    struct pseudoheader ph;
    
    u_int16_t sp;       /* source port UDP */
    u_int16_t dp;       /* dest port UDP */
    u_int8_t *data;     /* packet payload pointer */
    u_int16_t dsize;        /* packet payload size */

    if (send_esc) {
      SETCOLOR(UDP_COLOR);
    }

    printf("UDP ");
    
    if(len < sizeof(UDPHdr))
    {
      
            printf("Truncated UDP header (%d bytes)\n", len);

        return;
    }

    /* set the ptr to the start of the UDP header */
    udptr = (UDPHdr *) pkt;
   
    uhlen = ntohs(udptr->uh_len);
        
    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
       
      printf("Invalid UDP Packet, length field < 8");
      return;
    }

    /* make sure there are enough bytes as designated by length field */
    if(len < uhlen)
    {
      printf("Short UDP packet, length field > payload length\n");
      return;
    }

    
    /* look at the UDP checksum to make sure we've got a good packet */

    /*  Checksum is the 16-bit one's complement of the one's complement sum of a
     * pseudo header of information from the IP header, the UDP header, and the 
     * data,  padded  with zero octets  at the end (if  necessary)  to  make  a 
     * multiple of two octets. (rfc768)
     */

    ph.sip = (u_int32_t)(iptr->ip_src.s_addr);
    ph.dip = (u_int32_t)(iptr->ip_dst.s_addr);
    ph.zero = 0;
    ph.protocol = iptr->ip_proto;
    ph.udplen = udptr->uh_len; 
    
    if(udptr->uh_chk)
      {
	csum = in_chksum_udp((u_int16_t *)&ph, (u_int16_t *)(udptr), uhlen);
      }
    else
      {
	csum = 0;
      }

    if(csum)
      {
	printf( "Bad UDP Checksum\n");
      }
    else
      {
	printf("UDP Checksum: OK\n");
      }
    

    /* source and destination ports */
    sp = ntohs(udptr->uh_sport);
    dp = ntohs(udptr->uh_dport);

    PrintPorts(sp,dp,UDP_COLOR);
    
    data = (u_int8_t *) (pkt + UDP_HEADER_LEN);
    
    /* length was validated up above */
    dsize = uhlen - UDP_HEADER_LEN; 

    return;
}
