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

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "vlan.h"

#include "ethernet.h"

#include "llc.h"

#include "ip.h"
#include "snif.h" /* function names definitions */

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

/* Decode Vlan traffic*/
void DecodeVlan(u_int8_t * pkt, const u_int32_t len,struct pcap_pkthdr * pkthdr) 
{

  VlanTagHdr * vlan_hdr_ptr;

  if (send_esc) {
    SETCOLOR(NETWORK_LAYER_COLOR);
   }


    if(len < sizeof(VlanTagHdr))
    {
        printf("Not enough data to process a Vlan header\n");

        printf("Dropping bad packet\n");
             
        return;
    }

    vlan_hdr_ptr = (VlanTagHdr *) pkt;

     if (dump_link_layer) { 
       SETATTRIB( BRIGHT );
       printf("Vlan traffic:\n");
       NORMALMODE();
       SETCOLOR(NETWORK_LAYER_COLOR);
       printf("   Priority: %d(0x%X)\n", 
                            VTH_PRIORITY(vlan_hdr_ptr), VTH_PRIORITY(vlan_hdr_ptr));
       printf("   CFI: %d\n", VTH_CFI(vlan_hdr_ptr));
       printf("   Vlan ID: %d(0x%04X)\n", 
                            VTH_VLAN(vlan_hdr_ptr), VTH_VLAN(vlan_hdr_ptr));
       printf("   Vlan Proto: 0x%04X\n", 
                            ntohs(vlan_hdr_ptr->vth_proto));
     }


    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(vlan_hdr_ptr->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
      /* sound strange : proto can't be compared with a length ! */
    {
        if(len < sizeof(VlanTagHdr) + sizeof(LLCHdr))


        {
           printf("Not enough data for Vlan + LLC header\n");
        
	   printf("Dropping bad packet\n");
	   
	   return;            
        }
        
	/* assuming we have an LLC header */
        DecodeLLC (pkt + sizeof(VlanTagHdr), len - sizeof(VlanTagHdr),pkthdr);

    }
    else
      {
        switch(ntohs(vlan_hdr_ptr->vth_proto))
	  {
	  case ETHERNET_TYPE_IP:
	    DecodeIP(pkt + sizeof(VlanTagHdr), 
		     len - sizeof(VlanTagHdr));
	    return;
	    
	  case ETHERNET_TYPE_ARP:
	    DecodeARP();
	    return;
	    
	  case ETHERNET_TYPE_REVARP:
	    DecodeReverseARP();   
	    return;
	    
	  case ETHERNET_TYPE_IPV6:
	    DecodeIPV6(pkt + sizeof(VlanTagHdr), 
		       len - sizeof(VlanTagHdr)
		       ,pkthdr);
	    return;

	  default:
	    printf( "Unknown network protocol: code %d\n",
		    ntohs(vlan_hdr_ptr->vth_proto));
	    return;
	  }
      }
}

