/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@gmail.com>

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

/* needed for ICMP, you know ICMP is encapsuled in IP */
#include "ip.h"


#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "icmp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */


/*
 * Function: DecodeICMP(u_int8_t *, const u_int32_t, IPHdr * )
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to th IP header
 *
 * Returns: void function
 */
void DecodeICMP(u_int8_t * pkt, const u_int32_t len, IPHdr * iptr)
{

    ICMPHdr * icmptr;

    u_int16_t csum;
    u_int32_t orig_p_caplen;

    u_int8_t *data;     /* packet payload pointer */
    u_int16_t dsize;        /* packet payload size */

    if (send_esc) {
      SETCOLOR(ICMP_COLOR);
    }

    printf("ICMP ");
    
    if(len < ICMP_HEADER_LEN)
    {
      printf("WARNING: Truncated ICMP header "
	     "(%d bytes)\n", len);
      return;
    }

    /* set the header ptr first */
    icmptr = (ICMPHdr *) pkt;

    if (send_esc) {
      SETATTRIB( BRIGHT );
      }
    
    /* print some info on ICMP type */
    switch (icmptr->type)
      {
      case ICMP_ECHOREPLY:
	printf("Echo Reply\n");
	break;
      case ICMP_DEST_UNREACH:
	printf("Destination Unreachable\n");
	break;
      case ICMP_SOURCE_QUENCH:
	printf("Source Quench\n");
	break;
      case ICMP_REDIRECT:
	printf("Redirect (change route)\n");
	break;
      case ICMP_ECHO:
	printf("Echo Request\n");
	break;
      case ICMP_ROUTER_ADVERTISE:
	printf("Router Advertisement\n");
	break;
      case ICMP_ROUTER_SOLICIT:
	printf("Router Solicitation\n");
	break;
      case ICMP_TIME_EXCEEDED:
	printf("Time Exceeded\n");
	break;
      case ICMP_PARAMETERPROB:
	printf("Parameter Problem\n");
	break;
      case ICMP_INFO_REQUEST:
	printf("Information Request\n");
	break;
      case ICMP_INFO_REPLY:
	printf("Information Reply\n");
	break;
      case ICMP_TIMESTAMP:
	printf("Timestamp Request\n");
      case ICMP_TIMESTAMPREPLY:
	printf("Timestamp Reply\n");
	break;
      case ICMP_ADDRESS:
	printf("Address Mask Request\n");
	break;
      case ICMP_ADDRESSREPLY:
	printf("Address Mask Reply\n");
	break;
      }
    
    if (send_esc) {
      NORMALMODE();
      SETCOLOR( ICMP_COLOR );
    }
    
    /* check for some length */
    switch (icmptr->type)
      {
      case ICMP_ECHOREPLY:
      case ICMP_DEST_UNREACH:
      case ICMP_SOURCE_QUENCH:
      case ICMP_REDIRECT:
      case ICMP_ECHO:
      case ICMP_ROUTER_ADVERTISE:
      case ICMP_ROUTER_SOLICIT:
      case ICMP_TIME_EXCEEDED:
      case ICMP_PARAMETERPROB:
      case ICMP_INFO_REQUEST:
      case ICMP_INFO_REPLY:
	if (len < 8)  
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;

      case ICMP_TIMESTAMP:
      case ICMP_TIMESTAMPREPLY:
	if (len < 20)
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;

      case ICMP_ADDRESS:
      case ICMP_ADDRESSREPLY:
	if (len < 12)
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;
      }

    /* we always do checksums */
    csum = in_chksum_icmp((u_int16_t *)icmptr, len);

    if(csum)
      {
	printf("Bad ICMP Checksum\n");
      }
    else
      {
	printf("ICMP Checksum: OK\n");
      }
    

    dsize = (u_short)(len - ICMP_HEADER_LEN);
    data = pkt + ICMP_HEADER_LEN;

    printf("ICMP type: %d   code: %d\n", 
                icmptr->type, icmptr->code);

    switch(icmptr->type)
    {
        case ICMP_ECHOREPLY:
	  
            /* setup the pkt id ans seq numbers */
            dsize -= sizeof(struct idseq);
            data += sizeof(struct idseq);
            break;

        case ICMP_ECHO:
	    
            /* setup the pkt id and seq numbers */
            dsize -= sizeof(struct idseq);   /* add the size of the 
					      * echo ext to the data
					      * ptr and subtract it 
					      * from the data size */
            data += sizeof(struct idseq);
            break;

        case ICMP_DEST_UNREACH:
            {
	        
                /* if unreach packet is smaller than expected! */
                if(len < 16)
                {
		  printf("Truncated ICMP-UNREACH "
			 "header (%d bytes)\n", len);
                  
                    /* if it is less than 8 we are in trouble */
                    if(len < 8)
                        break;
                }

                orig_p_caplen = len - 8;

	    }

            break;

        case ICMP_REDIRECT:
            {
                /* if unreach packet is smaller than expected! */
                if(dsize < 28)
                {
		  printf("Truncated ICMP-REDIRECT "
			 "header (%d bytes)\n", len);
                                          
		  /* if it is less than 8 we are in trouble */
		  if(dsize < 8)
                        break;
                }

                orig_p_caplen = dsize - 8;

            }

            break;
    }

    return;
}
