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

#include <stdlib.h> /* added for calloc */

#include <string.h> /* added for memcpy,strncpy */


#include "ip.h"
#include "snif.h" /* function names definitions */

#include "ethernet.h"
#include "pppoe.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */






/*
 * Function: DecodePPPoE(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode PPP over ethernet packets
 *
 * Arguments:
 *            pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoE(u_int8_t * pkt, const u_int32_t len)
{

    PPPoEHdr *pppoe_hdr_ptr=0;
   
    PPPoE_Tag *ppppoe_tag=0;
    PPPoE_Tag tag;  /* needed to avoid alignment problems */

    EtherHdr * eptr; /*  needed to point back to ethernet header to
		      *  know if it's a DISCOVERY or SESSION packet */

    int i;
    char * buf;


    if (dump_link_layer) { 

      printf("PPP over Ethernet packet\n");

    }

     /* do a little validation */
    if(len < PPPOE_HEADER_LEN)
    {
       
       printf("Captured data length < PPPOE header length! (%d bytes)\n", len);
               
        return;
    }

    /* lay the ethernet structure over the packet data */
    eptr = (EtherHdr *) pkt - ETHERNET_HEADER_LEN;

    pppoe_hdr_ptr = (PPPoEHdr *)pkt;

    /* grab out the network type */
    switch(ntohs(eptr->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
            printf( "Discovery packet\n");
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            printf( "Session packet\n");
            break;

        default:
            return;
    }

    if (verb > 0) {
      switch(pppoe_hdr_ptr->code)
	{
        case PPPoE_CODE_PADI:
	  /* The Host sends the PADI packet with the DESTINATION_ADDR set 
	   * to the broadcast address.  The CODE field is set to 0x09 and
	   * the SESSION_ID MUST be set to 0x0000.
	   *
	   * The PADI packet MUST contain exactly one TAG of TAG_TYPE 
	   * Service-Name, indicating the service the Host is requesting, 
	   * and any number of other TAG types.  An entire PADI packet 
	   * (including the PPPoE header) MUST NOT exceed 1484 octets so 
	   * as to leave sufficient room for a relay agent to add a 
	   * Relay-Session-Id TAG.
	   */ 
	  printf("Active Discovery Initiation (PADI)\n");
	  break;

        case PPPoE_CODE_PADO:
	  /* When the Access Concentrator receives a PADI that it can 
	   * serve, it replies by sending a PADO packet.  The 
	   * DESTINATION_ADDR is the unicast address of the Host that 
	   * sent the PADI.  The CODE field is set to 0x07 and the 
	   * SESSION_ID MUST be set to 0x0000.  
	   * 
	   * The PADO packet MUST contain one AC-Name TAG containing the 
	   * Access Concentrator's name, a Service-Name TAG identical to 
	   * the one in the PADI, and any number of other Service-Name 
	   * TAGs indicating other services that the Access Concentrator 
	   * offers.  If the Access Concentrator can not serve the PADI 
	   * it MUST NOT respond with a PADO.
	   */ 
	  printf("Active Discovery Offer (PADO)\n");
	  break;

        case PPPoE_CODE_PADR:
	  /* Since the PADI was broadcast, the Host may receive more than 
	   * one PADO.  The Host looks through the PADO packets it receives 
	   * and chooses one.  The choice can be based on the AC-Name or 
	   * the Services offered.  The Host then sends one PADR packet 
	   * to the Access Concentrator that it has chosen.  The 
	   * DESTINATION_ADDR field is set to the unicast Ethernet address 
	   * of the Access Concentrator that sent the PADO.  The CODE 
	   * field is set to 0x19 and the SESSION_ID MUST be set to 0x0000.
	   *
	   * The PADR packet MUST contain exactly one TAG of TAG_TYPE 
	   * Service-Name, indicating the service the Host is requesting, 
	   * and any number of other TAG types.
	   */ 
	  printf("Active Discovery Request (PADR)\n");
	  break;

        case PPPoE_CODE_PADS:
	  /* When the Access Concentrator receives a PADR packet, it 
	   * prepares to begin a PPP session.  It generates a unique 
	   * SESSION_ID for the PPPoE session and replies to the Host with 
	   * a PADS packet.  The DESTINATION_ADDR field is the unicast 
	   * Ethernet address of the Host that sent the PADR.  The CODE 
	   * field is set to 0x65 and the SESSION_ID MUST be set to the 
	   * unique value generated for this PPPoE session.
	   *
	   * The PADS packet contains exactly one TAG of TAG_TYPE 
	   * Service-Name, indicating the service under which Access 
	   * Concentrator has accepted the PPPoE session, and any number 
	   * of other TAG types.
	   *
	   * If the Access Concentrator does not like the Service-Name in 
	   * the PADR, then it MUST reply with a PADS containing a TAG of 
	   * TAG_TYPE Service-Name-Error (and any number of other TAG 
	   * types).  In this case the SESSION_ID MUST be set to 0x0000.
	   */ 
	  printf("Active Discovery Session-confirmation (PADS)\n");
	  break;

        case PPPoE_CODE_PADT:
	  /* This packet may be sent anytime after a session is established 
	   * to indicate that a PPPoE session has been terminated.  It may 
	   * be sent by either the Host or the Access Concentrator.  The 
	   * DESTINATION_ADDR field is a unicast Ethernet address, the 
	   * CODE field is set to 0xa7 and the SESSION_ID MUST be set to 
	   * indicate which session is to be terminated.  No TAGs are 
	   * required.  
	   *
	   * When a PADT is received, no further PPP traffic is allowed to 
	   * be sent using that session.  Even normal PPP termination 
	   * packets MUST NOT be sent after sending or receiving a PADT.  
	   * A PPP peer SHOULD use the PPP protocol itself to bring down a 
	   * PPPoE session, but the PADT MAY be used when PPP can not be 
	   * used.
	   */ 
	  printf("Active Discovery Terminate (PADT)\n");
	  break;

        case PPPoE_CODE_SESS: 
	  printf("Session Packet (SESS)\n");
	  break;

        default:
	  printf("(Unknown code)\n");
	  break;
	}
    }

    if (ntohs(eptr->ether_type) != ETHERNET_TYPE_PPPoE_DISC) /* it's a SESSion ! */
    {
        DecodePppPktEncapsulated( pkt + PPPOE_HEADER_LEN,len - PPPOE_HEADER_LEN);
        return;
    }
    /* else */
/*     { */
/*         printf("Returning early on PPPOE discovery packet\n"); */
/*         return; */
/*     } */


    ppppoe_tag = (PPPoE_Tag *)(pkt + sizeof(PPPoEHdr));

    while (ppppoe_tag < (PPPoE_Tag *)(pkt + len))
    {
      if (((char*)(ppppoe_tag)+(sizeof(PPPoE_Tag)-1)) > (char*)(pkt + len))
        {
	  printf( "Not enough data in packet for PPPOE Tag\n");
	  break;
        }

      
        /* no guarantee in PPPoE spec that ppppoe_tag is aligned at all... */
        memcpy(&tag, ppppoe_tag, sizeof(tag));

        printf("\tPPPoE tag:\ntype: %04x length: %04x ", 
	       ntohs(tag.type), ntohs(tag.length));

	if (verb > 0) {

        switch(ntohs(tag.type))
        {
            case PPPoE_TAG_END_OF_LIST:
                printf( "(End of list)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME:
                printf( "(Service name)\n\t");
                break;
            case PPPoE_TAG_AC_NAME:
                printf( "(AC Name)\n\t");
                break;
            case PPPoE_TAG_HOST_UNIQ:
                printf( "(Host Uniq)\n\t");
                break;
            case PPPoE_TAG_AC_COOKIE:
                printf( "(AC Cookie)\n\t");
                break;
            case PPPoE_TAG_VENDOR_SPECIFIC:
                printf( "(Vendor Specific)\n\t");
                break;
            case PPPoE_TAG_RELAY_SESSION_ID:
                printf( "(Relay Session ID)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                printf( "(Service Name Error)\n\t");
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                printf( "(AC System Error)\n\t");
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                printf( "(Generic Error)\n\t");
                break;
            default:
                printf( "(Unknown)\n\t");
                break;
        }


        if (ntohs(tag.length) > 0)
        {

            switch (ntohs(tag.type))
            {
                case PPPoE_TAG_SERVICE_NAME:
                case PPPoE_TAG_AC_NAME:
                case PPPoE_TAG_SERVICE_NAME_ERROR:
                case PPPoE_TAG_AC_SYSTEM_ERROR:
                case PPPoE_TAG_GENERIC_ERROR: /* ascii data */
                    buf = (char *) calloc(ntohs(tag.length) + 1, sizeof(char));
                    strncpy(buf, (char *)(ppppoe_tag+1), ntohs(tag.length));
                    printf( "data (UTF-8): %s\n", buf);
                    free(buf);
                    break;

                case PPPoE_TAG_HOST_UNIQ:
                case PPPoE_TAG_AC_COOKIE:
                case PPPoE_TAG_RELAY_SESSION_ID:
                    printf( "data (bin): ");
                    for (i = 0; i < ntohs(tag.length); i++)
                        printf(
                                "%02x", *(((unsigned char *)ppppoe_tag) + 
                                    sizeof(PPPoE_Tag) + i));
                    printf( "\n");
                    break;

                default:
                    printf( "unrecognized data\n");
                    break;
            }

        }

	}

        ppppoe_tag = (PPPoE_Tag *)((char *)(ppppoe_tag+1)+ntohs(tag.length));
    }

    return;
}
